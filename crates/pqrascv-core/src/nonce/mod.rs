//! Replay-resistant nonce management.
//!
//! # Audit Findings Fixed
//!
//! **Finding #3 — Replay Vulnerability**: `timestamp=0` bypassed freshness
//! checks entirely. Captured attestations became permanently replayable.
//!
//! **Finding #6 — Weak Event Counter Semantics**: Counters were caller-controlled
//! and non-monotonic.
//!
//! # v2 Design
//!
//! 1. [`ClockEvidence`] replaces the raw `u64` timestamp. `NoRtc` is an
//!    explicit variant — there is no silent bypass via `timestamp=0`.
//!
//! 2. [`NonceLedger`] enforces single-use nonces. The verifier registers a
//!    nonce before sending the challenge and marks it consumed when the quote
//!    arrives. A nonce that is not in the ledger, or has already been consumed,
//!    is rejected immediately.
//!
//! 3. [`NonceHandle`] is an opaque token returned by the ledger. The verifier
//!    passes it to the verification pipeline; the pipeline consumes it exactly
//!    once.
//!
//! # Deployment Requirements — Read Before Deploying
//!
//! `InMemoryNonceLedger` is **single-process only**. It provides correct replay
//! protection within one process instance but fails silently in any of:
//!
//! - **Multi-node deployments**: a nonce registered on node A is unknown to
//!   node B. An attacker routes the replayed quote to a different node.
//! - **Process restarts**: the in-memory ledger is lost. Nonces issued before
//!   the restart are not tracked; a replayed quote will pass the nonce check.
//! - **Autoscaling / failover**: same as multi-node.
//!
//! For any of the above topologies, implement [`NonceLedger`] against a shared
//! persistent store — Redis, PostgreSQL, or equivalent. The trait requires only
//! two methods; the implementation is straightforward.
//!
//! The `pqrascv-nonce-backends` crate provides reference Redis and PostgreSQL
//! implementations of [`NonceLedger`] that satisfy the distributed and
//! crash-recovery portions of this contract.
//!
//! # TTL & Crash-Recovery Contract
//!
//! A conforming [`NonceLedger`] implementation MUST uphold the following,
//! which is exercised by the shared conformance suite in
//! `pqrascv-nonce-backends`:
//!
//! 1. **Single-use.** A nonce registered via [`NonceLedger::register`] (or
//!    [`register_with_ttl`](NonceLedger::register_with_ttl)) can be consumed at
//!    most once. A second [`consume`](NonceLedger::consume) of the same nonce
//!    MUST return [`PqRascvError::InvalidNonce`], even across concurrent handles
//!    sharing the same store (distributed single-use).
//!
//! 2. **TTL eviction.** When a nonce is registered with a non-zero `ttl_secs`,
//!    it expires once the supplied monotone clock advances strictly past
//!    `registered_at + ttl_secs`. Consuming an expired (but never-consumed)
//!    nonce MUST fail with [`PqRascvError::InvalidNonce`]; the same nonce value
//!    MAY then be re-registered as if fresh. TTL is keyed on the caller-supplied
//!    `now` ("now" seconds), which the caller derives from
//!    [`ClockEvidence`] / a trusted clock — the ledger never reads a clock
//!    itself, keeping the trait `no_std`-clean.
//!
//! 3. **Eviction bound.** An implementation MAY bound the consumed-nonce
//!    history (see [`DEFAULT_MAX_CONSUMED`]). Eviction MUST be FIFO and MUST NOT
//!    drop an entry that is still within its TTL window if a bounded entry is
//!    available to evict instead is NOT required — bounded eviction is a memory
//!    safeguard, and the security trade-off is documented per impl.
//!
//! 4. **Crash recovery.** A persistent-store implementation (Redis/Postgres)
//!    MUST preserve the consumed/registered state across a process restart of
//!    the ledger client: re-opening a ledger against the same store and
//!    attempting to consume an already-consumed nonce MUST still be rejected.
//!    [`InMemoryNonceLedger`] explicitly does NOT satisfy this (state is lost on
//!    restart); persistent backends do.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::error::PqRascvError;

// ── ClockEvidence ─────────────────────────────────────────────────────────

/// Explicit clock evidence in an attestation quote.
///
/// Replaces the raw `u64` timestamp from v1. There is no silent bypass:
/// a device without a real-time clock must use `NoRtc`, and the verifier
/// policy explicitly controls whether `NoRtc` quotes are accepted.
///
/// # Audit Finding #3 Fix
///
/// In v1, `timestamp: u64` allowed `timestamp=0` to bypass freshness checks.
/// This enum makes the absence of a clock an explicit, policy-controlled choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClockEvidence {
    /// Unix seconds from a trusted real-time clock.
    ///
    /// The verifier checks that `now - ts <= max_quote_age_secs`.
    TrustedRtc(u64),
    /// Device has no real-time clock.
    ///
    /// Freshness is enforced solely by the nonce mechanism.
    /// The verifier policy must explicitly set `allow_rtcless_devices = true`
    /// to accept these quotes.
    NoRtc,
}

impl ClockEvidence {
    /// Returns the trusted Unix-seconds value when present.
    ///
    /// Returns `Some(secs)` for [`ClockEvidence::TrustedRtc`] and `None` for
    /// [`ClockEvidence::NoRtc`]. Callers driving TTL on a [`NonceLedger`] supply
    /// the returned value as the `now` parameter; when `None`, the caller must
    /// fall back to a verifier-side trusted clock (the ledger never reads a
    /// clock itself, keeping the trait `no_std`-clean).
    #[must_use]
    pub fn now_secs(&self) -> Option<u64> {
        match self {
            Self::TrustedRtc(secs) => Some(*secs),
            Self::NoRtc => None,
        }
    }
}

// ── NonceHandle ───────────────────────────────────────────────────────────

/// An opaque handle to a registered, unconsumed nonce.
///
/// Returned by [`NonceLedger::register`]. Consume via [`NonceLedger::consume_handle`]
/// (preferred) or [`NonceLedger::consume`].
///
/// The handle cannot be cloned or copied, enforcing single-issue at the type
/// level. Prefer `consume_handle` over `consume` because moving the handle
/// into that method makes it impossible for the caller to accidentally use the
/// same handle twice.
#[derive(Debug)]
pub struct NonceHandle {
    pub(crate) nonce: [u8; 32],
}

impl NonceHandle {
    /// Returns the raw nonce bytes (for embedding in a [`Challenge`](crate::quote::Challenge)).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.nonce
    }
}

// ── NonceLedger trait ─────────────────────────────────────────────────────

/// Single-use nonce enforcement.
///
/// The verifier generates a nonce, registers it in the ledger, sends it to
/// the prover in a `Challenge`, then consumes it when the quote arrives.
/// Any attempt to reuse a nonce is rejected.
///
/// # Caller Obligation
///
/// The verifier (`verify_cbor`, `verify_with_challenge`, etc.) does **not**
/// automatically consume nonces. You must call `consume` or `consume_handle`
/// on the ledger **before or after** calling the verifier. Forgetting to
/// consume means the same nonce can be presented again and will pass the
/// verifier's nonce check.
///
/// Recommended pattern:
///
/// ```rust,ignore
/// let handle = ledger.register(random_nonce)?;
/// let challenge = Challenge::new(*handle.as_bytes());
/// // … send challenge, receive cbor …
/// ledger.consume_handle(handle)?;   // consume before or after verify_cbor
/// verifier.verify_cbor(&cbor, &vk, &random_nonce, now)?;
/// ```
///
/// # Implementations
///
/// - [`InMemoryNonceLedger`] — for tests and single-process verifiers.
/// - Production with multiple nodes: implement with Redis or a database.
///   The trait requires only `register` and `consume`.
pub trait NonceLedger {
    /// Registers a fresh nonce and returns a handle.
    ///
    /// The nonce must be cryptographically random (32 bytes from OS entropy).
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::InvalidNonce`] if the nonce is already registered
    /// (collision — astronomically unlikely with a proper RNG).
    fn register(&mut self, nonce: [u8; 32]) -> Result<NonceHandle, PqRascvError>;

    /// Registers a fresh nonce with a time-to-live, returning a handle.
    ///
    /// Identical to [`register`] except the nonce expires once the caller's
    /// monotone clock advances strictly past `now + ttl_secs`. A `ttl_secs` of
    /// `0` means "no TTL" — the nonce never expires on its own and behaves
    /// exactly like [`register`]. `now` is a caller-supplied Unix-seconds value
    /// (e.g. from [`ClockEvidence::now_secs`]); the ledger does not read a clock.
    ///
    /// The default implementation ignores TTL and delegates to [`register`], so
    /// existing implementations remain valid. TTL-aware implementations
    /// ([`InMemoryNonceLedger`] and the persistent backends) override this.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::InvalidNonce`] if the nonce is already registered
    /// and still live (not expired).
    ///
    /// [`register`]: NonceLedger::register
    fn register_with_ttl(
        &mut self,
        nonce: [u8; 32],
        now: u64,
        ttl_secs: u64,
    ) -> Result<NonceHandle, PqRascvError> {
        let _ = (now, ttl_secs);
        self.register(nonce)
    }

    /// Consumes a nonce by reference, marking it as used.
    ///
    /// Returns `Ok(())` if the nonce was registered and not yet consumed.
    /// Returns `Err(PqRascvError::InvalidNonce)` if the nonce is unknown or
    /// has already been consumed (replay attempt).
    ///
    /// Prefer [`consume_handle`] when you have ownership of the handle — it
    /// provides a compile-time guarantee that the handle cannot be used again.
    ///
    /// [`consume_handle`]: NonceLedger::consume_handle
    fn consume(&mut self, nonce: &[u8; 32]) -> Result<(), PqRascvError>;

    /// Consumes a nonce at a given point in time, honoring TTL expiry.
    ///
    /// Identical to [`consume`] except that an entry whose TTL has elapsed
    /// (i.e. `now` is strictly past `registered_at + ttl_secs`) is treated as
    /// already-evicted: it is removed and the call fails with
    /// [`PqRascvError::InvalidNonce`]. `now` is a caller-supplied Unix-seconds
    /// value; the ledger does not read a clock.
    ///
    /// The default implementation ignores `now` and delegates to [`consume`].
    /// TTL-aware implementations override this.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::InvalidNonce`] if the nonce is unknown, already
    /// consumed, or expired.
    ///
    /// [`consume`]: NonceLedger::consume
    fn consume_at(&mut self, nonce: &[u8; 32], now: u64) -> Result<(), PqRascvError> {
        let _ = now;
        self.consume(nonce)
    }

    /// Consumes a nonce by taking ownership of its handle.
    ///
    /// Equivalent to [`consume`] but moves the handle into this method,
    /// making it impossible for the caller to use the same handle twice.
    /// This is the preferred API when you hold a [`NonceHandle`] returned
    /// by [`register`].
    ///
    /// # Errors
    ///
    /// Same as [`consume`]: returns [`PqRascvError::InvalidNonce`] if the
    /// nonce was never registered or has already been consumed.
    ///
    /// [`consume`]: NonceLedger::consume
    /// [`register`]: NonceLedger::register
    fn consume_handle(&mut self, handle: NonceHandle) -> Result<(), PqRascvError> {
        let nonce = *handle.as_bytes();
        self.consume(&nonce)
    }
}

// ── InMemoryNonceLedger ───────────────────────────────────────────────────

/// Default cap on the consumed-nonce history.
///
/// At ~1 quote per second this covers ~18 hours of consumption history.
/// After 65,536 consumed nonces the oldest entry is evicted (FIFO). An evicted
/// nonce could theoretically be re-registered, but with 32-byte random nonces
/// the probability of a collision with a genuinely fresh registration is 2⁻²⁵⁶.
///
/// Adjust via [`InMemoryNonceLedger::new`] if your workload requires a longer
/// replay-detection window.
pub const DEFAULT_MAX_CONSUMED: usize = 65_536;

/// In-memory [`NonceLedger`] for tests and single-process verifiers.
///
/// # Limitations
///
/// - **Single-process only.** For distributed verifiers, implement
///   [`NonceLedger`] against a shared persistent store.
/// - **Not crash-safe.** All state is lost on process restart. Nonces issued
///   before a restart are no longer tracked; a replayed quote passes the check.
/// - **Bounded consumed history.** Once `max_consumed` entries accumulate the
///   oldest is evicted. See [`DEFAULT_MAX_CONSUMED`].
#[cfg(feature = "alloc")]
pub struct InMemoryNonceLedger {
    /// Registered-but-unconsumed nonces mapped to their expiry deadline.
    ///
    /// The value is `Some(deadline_secs)` when a TTL was supplied, or `None`
    /// for nonces registered without a TTL (never expire on their own).
    pending: BTreeMap<[u8; 32], Option<u64>>,
    consumed: BTreeSet<[u8; 32]>,
    /// Insertion-order index into `consumed` for FIFO eviction.
    consumed_order: VecDeque<[u8; 32]>,
    max_consumed: usize,
}

#[cfg(feature = "alloc")]
impl InMemoryNonceLedger {
    /// Creates a new ledger with the specified maximum consumed-nonce history.
    ///
    /// When the consumed set reaches `max_consumed`, the oldest entry is evicted
    /// before the new one is inserted. Passing `0` uses [`DEFAULT_MAX_CONSUMED`].
    #[must_use]
    pub fn new(max_consumed: usize) -> Self {
        Self {
            pending: BTreeMap::new(),
            consumed: BTreeSet::new(),
            consumed_order: VecDeque::new(),
            max_consumed: if max_consumed == 0 {
                DEFAULT_MAX_CONSUMED
            } else {
                max_consumed
            },
        }
    }
}

#[cfg(feature = "alloc")]
impl Default for InMemoryNonceLedger {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CONSUMED)
    }
}

#[cfg(feature = "alloc")]
impl InMemoryNonceLedger {
    /// Returns `true` if `deadline` indicates the nonce has expired at `now`.
    ///
    /// A nonce with no TTL (`None`) never expires. A TTL'd nonce expires once
    /// `now` is strictly greater than its deadline.
    fn is_expired(deadline: Option<u64>, now: u64) -> bool {
        matches!(deadline, Some(deadline) if now > deadline)
    }

    /// Inserts `nonce` into the consumed set, evicting FIFO when at capacity.
    fn mark_consumed(&mut self, nonce: [u8; 32]) {
        // Evict the oldest consumed nonce when the cap is reached.
        // This bounds memory growth; see DEFAULT_MAX_CONSUMED for the
        // security trade-off with very old evicted nonces.
        if self.consumed.len() >= self.max_consumed {
            if let Some(oldest) = self.consumed_order.pop_front() {
                self.consumed.remove(&oldest);
            }
        }
        self.consumed.insert(nonce);
        self.consumed_order.push_back(nonce);
    }

    /// Registers `nonce` with an optional expiry deadline.
    fn register_inner(
        &mut self,
        nonce: [u8; 32],
        deadline: Option<u64>,
        now: u64,
    ) -> Result<NonceHandle, PqRascvError> {
        // An expired pending entry is treated as absent: it can be re-registered.
        if let Some(&existing) = self.pending.get(&nonce) {
            if !Self::is_expired(existing, now) {
                return Err(PqRascvError::InvalidNonce);
            }
        }
        if self.consumed.contains(&nonce) {
            return Err(PqRascvError::InvalidNonce);
        }
        self.pending.insert(nonce, deadline);
        Ok(NonceHandle { nonce })
    }

    /// Consumes `nonce`, treating any TTL-expired entry as already evicted.
    fn consume_inner(&mut self, nonce: &[u8; 32], now: u64) -> Result<(), PqRascvError> {
        match self.pending.remove(nonce) {
            // Never registered, or already consumed (replay).
            None => Err(PqRascvError::InvalidNonce),
            // Expired before consumption — evicted, not consumed. The nonce is
            // now re-registerable per the TTL contract.
            Some(deadline) if Self::is_expired(deadline, now) => Err(PqRascvError::InvalidNonce),
            Some(_) => {
                self.mark_consumed(*nonce);
                Ok(())
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl NonceLedger for InMemoryNonceLedger {
    fn register(&mut self, nonce: [u8; 32]) -> Result<NonceHandle, PqRascvError> {
        // No TTL and now=0: a never-expiring entry, equivalent to v1 behavior.
        self.register_inner(nonce, None, 0)
    }

    fn register_with_ttl(
        &mut self,
        nonce: [u8; 32],
        now: u64,
        ttl_secs: u64,
    ) -> Result<NonceHandle, PqRascvError> {
        // ttl_secs == 0 means "no TTL"; otherwise the deadline saturates so a
        // huge TTL never wraps.
        let deadline = if ttl_secs == 0 {
            None
        } else {
            Some(now.saturating_add(ttl_secs))
        };
        self.register_inner(nonce, deadline, now)
    }

    fn consume(&mut self, nonce: &[u8; 32]) -> Result<(), PqRascvError> {
        // now=0 can never be "strictly past" a saturated deadline, so a
        // non-TTL-aware caller never trips expiry.
        self.consume_inner(nonce, 0)
    }

    fn consume_at(&mut self, nonce: &[u8; 32], now: u64) -> Result<(), PqRascvError> {
        self.consume_inner(nonce, now)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn register_and_consume_succeeds() {
        let mut ledger = InMemoryNonceLedger::default();
        let nonce = [0x42u8; 32];
        let handle = ledger.register(nonce).unwrap();
        assert_eq!(handle.as_bytes(), &nonce);
        ledger.consume(&nonce).unwrap();
    }

    #[test]
    fn replay_is_rejected() {
        let mut ledger = InMemoryNonceLedger::default();
        let nonce = [0x01u8; 32];
        ledger.register(nonce).unwrap();
        ledger.consume(&nonce).unwrap();
        // Second consume must fail.
        assert_eq!(ledger.consume(&nonce), Err(PqRascvError::InvalidNonce));
    }

    #[test]
    fn unknown_nonce_is_rejected() {
        let mut ledger = InMemoryNonceLedger::default();
        assert_eq!(
            ledger.consume(&[0xffu8; 32]),
            Err(PqRascvError::InvalidNonce)
        );
    }

    #[test]
    fn duplicate_register_is_rejected() {
        let mut ledger = InMemoryNonceLedger::default();
        let nonce = [0x77u8; 32];
        ledger.register(nonce).unwrap();
        assert!(ledger.register(nonce).is_err());
    }

    // ── consume_handle ────────────────────────────────────────────────────

    #[test]
    fn consume_handle_succeeds() {
        let mut ledger = InMemoryNonceLedger::default();
        let nonce = [0xAAu8; 32];
        let handle = ledger.register(nonce).unwrap();
        ledger.consume_handle(handle).unwrap();
        // Replay via consume must now fail.
        assert_eq!(ledger.consume(&nonce), Err(PqRascvError::InvalidNonce));
    }

    #[test]
    fn consume_handle_on_unknown_nonce_fails() {
        let mut ledger = InMemoryNonceLedger::default();
        // Construct a handle without registering (simulates a stale handle).
        let handle = NonceHandle {
            nonce: [0xBBu8; 32],
        };
        assert_eq!(
            ledger.consume_handle(handle),
            Err(PqRascvError::InvalidNonce)
        );
    }

    // ── bounded consumed set ──────────────────────────────────────────────

    #[test]
    fn consumed_set_evicts_when_cap_reached() {
        // Use a tiny cap (4) to make eviction observable.
        let mut ledger = InMemoryNonceLedger::new(4);

        // Fill the consumed set to the cap.
        for i in 0u8..4 {
            let nonce = [i; 32];
            ledger.register(nonce).unwrap();
            ledger.consume(&nonce).unwrap();
        }
        // The consumed set holds [0,0,…], [1,1,…], [2,2,…], [3,3,…].
        assert_eq!(ledger.consumed.len(), 4);

        // Consume a fifth nonce — the oldest ([0,0,…]) is evicted.
        let fifth = [4u8; 32];
        ledger.register(fifth).unwrap();
        ledger.consume(&fifth).unwrap();
        assert_eq!(ledger.consumed.len(), 4, "cap must be maintained");
        // The evicted nonce is no longer in the consumed set.
        assert!(
            !ledger.consumed.contains(&[0u8; 32]),
            "oldest nonce must be evicted"
        );
        // The newest entry is present.
        assert!(ledger.consumed.contains(&[4u8; 32]));
    }

    #[test]
    fn replay_detected_within_cap() {
        let mut ledger = InMemoryNonceLedger::new(8);
        let nonce = [0xCCu8; 32];
        ledger.register(nonce).unwrap();
        ledger.consume(&nonce).unwrap();
        // Replay attempt while nonce is still within the cap — must be rejected.
        assert_eq!(ledger.consume(&nonce), Err(PqRascvError::InvalidNonce));
    }

    // ── TTL semantics ─────────────────────────────────────────────────────

    #[test]
    fn ttl_nonce_consumable_before_expiry() {
        let mut ledger = InMemoryNonceLedger::default();
        let nonce = [0x10u8; 32];
        ledger.register_with_ttl(nonce, 1_000, 60).unwrap();
        // now=1_059 is within registered_at(1_000)+ttl(60)=1_060.
        ledger.consume_at(&nonce, 1_059).unwrap();
        // Replay still rejected.
        assert_eq!(ledger.consume_at(&nonce, 1_059), Err(PqRascvError::InvalidNonce));
    }

    #[test]
    fn ttl_nonce_rejected_after_expiry() {
        let mut ledger = InMemoryNonceLedger::default();
        let nonce = [0x11u8; 32];
        ledger.register_with_ttl(nonce, 1_000, 60).unwrap();
        // now=1_061 is strictly past the deadline 1_060: expired.
        assert_eq!(
            ledger.consume_at(&nonce, 1_061),
            Err(PqRascvError::InvalidNonce)
        );
    }

    #[test]
    fn ttl_boundary_is_inclusive_of_deadline() {
        let mut ledger = InMemoryNonceLedger::default();
        let nonce = [0x12u8; 32];
        ledger.register_with_ttl(nonce, 1_000, 60).unwrap();
        // now == deadline (1_060): NOT strictly past, still live.
        ledger.consume_at(&nonce, 1_060).unwrap();
    }

    #[test]
    fn expired_nonce_is_reregisterable() {
        let mut ledger = InMemoryNonceLedger::default();
        let nonce = [0x13u8; 32];
        ledger.register_with_ttl(nonce, 1_000, 60).unwrap();
        // Expired consume evicts the entry.
        assert_eq!(
            ledger.consume_at(&nonce, 2_000),
            Err(PqRascvError::InvalidNonce)
        );
        // Same value can be registered fresh after expiry-eviction.
        ledger.register_with_ttl(nonce, 2_000, 60).unwrap();
        ledger.consume_at(&nonce, 2_010).unwrap();
    }

    #[test]
    fn expired_pending_can_be_reregistered_without_consume() {
        let mut ledger = InMemoryNonceLedger::default();
        let nonce = [0x14u8; 32];
        ledger.register_with_ttl(nonce, 1_000, 10).unwrap();
        // Re-register the same value after its TTL elapsed: allowed, the stale
        // pending entry is overwritten.
        ledger.register_with_ttl(nonce, 5_000, 10).unwrap();
        ledger.consume_at(&nonce, 5_005).unwrap();
    }

    #[test]
    fn zero_ttl_means_no_expiry() {
        let mut ledger = InMemoryNonceLedger::default();
        let nonce = [0x15u8; 32];
        ledger.register_with_ttl(nonce, 1_000, 0).unwrap();
        // Far-future now must not expire a no-TTL nonce.
        ledger.consume_at(&nonce, u64::MAX).unwrap();
    }

    #[test]
    fn consumed_nonce_not_resurrected_by_ttl() {
        // A consumed nonce stays consumed regardless of TTL clock movement.
        let mut ledger = InMemoryNonceLedger::default();
        let nonce = [0x16u8; 32];
        ledger.register_with_ttl(nonce, 1_000, 60).unwrap();
        ledger.consume_at(&nonce, 1_010).unwrap();
        // Even far in the future, replay rejected (consumed set has no TTL).
        assert_eq!(
            ledger.consume_at(&nonce, u64::MAX),
            Err(PqRascvError::InvalidNonce)
        );
        // And re-registration is rejected because it is in the consumed set.
        assert!(ledger.register_with_ttl(nonce, u64::MAX, 60).is_err());
    }

    // ── multi-node gap documentation test ────────────────────────────────
    //
    // This test models the multi-node replay scenario:
    // - Node A issues and consumes a nonce.
    // - Node B has a separate ledger instance and never saw the nonce.
    // - The quote is replayed to Node B — it passes Node B's nonce check.
    //
    // This is the documented limitation of InMemoryNonceLedger. The test
    // asserts the gap exists and is not silently "fixed" by the type system.
    #[test]
    fn multi_node_replay_gap_exists_by_design() {
        let mut node_a = InMemoryNonceLedger::default();
        let mut node_b = InMemoryNonceLedger::default();

        let nonce = [0xDDu8; 32];

        // Node A issues and consumes the nonce.
        node_a.register(nonce).unwrap();
        node_a.consume(&nonce).unwrap();

        // Node B has never seen this nonce — registration succeeds because
        // its ledger is independent. This is the documented gap: a shared
        // persistent store is required for multi-node replay protection.
        assert!(
            node_b.register(nonce).is_ok(),
            "InMemoryNonceLedger cannot detect cross-node replay — use a shared store"
        );
    }
}
