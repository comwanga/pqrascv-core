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

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeSet;

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

// ── NonceHandle ───────────────────────────────────────────────────────────

/// An opaque handle to a registered, unconsumed nonce.
///
/// Returned by [`NonceLedger::register`]. Pass to the verification pipeline,
/// which calls [`NonceLedger::consume`] exactly once.
///
/// The handle cannot be cloned or copied, enforcing single-use at the type level.
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
/// # Implementations
///
/// - [`InMemoryNonceLedger`] — for tests and single-process verifiers.
/// - Production: implement with Redis or a database for distributed verifiers.
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

    /// Consumes a nonce, marking it as used.
    ///
    /// Returns `Ok(())` if the nonce was registered and not yet consumed.
    /// Returns `Err(PqRascvError::InvalidNonce)` if the nonce is unknown or
    /// has already been consumed (replay attempt).
    fn consume(&mut self, nonce: &[u8; 32]) -> Result<(), PqRascvError>;
}

// ── InMemoryNonceLedger ───────────────────────────────────────────────────

/// In-memory [`NonceLedger`] for tests and single-process verifiers.
///
/// Not suitable for distributed deployments — use a shared store (Redis,
/// `PostgreSQL`) in production.
#[cfg(feature = "alloc")]
#[derive(Default)]
pub struct InMemoryNonceLedger {
    /// Nonces that have been registered but not yet consumed.
    pending: BTreeSet<[u8; 32]>,
    /// Nonces that have been consumed (kept to detect replay attempts).
    consumed: BTreeSet<[u8; 32]>,
}

#[cfg(feature = "alloc")]
impl NonceLedger for InMemoryNonceLedger {
    fn register(&mut self, nonce: [u8; 32]) -> Result<NonceHandle, PqRascvError> {
        if self.pending.contains(&nonce) || self.consumed.contains(&nonce) {
            return Err(PqRascvError::InvalidNonce);
        }
        self.pending.insert(nonce);
        Ok(NonceHandle { nonce })
    }

    fn consume(&mut self, nonce: &[u8; 32]) -> Result<(), PqRascvError> {
        if !self.pending.remove(nonce) {
            // Either never registered, or already consumed (replay).
            return Err(PqRascvError::InvalidNonce);
        }
        self.consumed.insert(*nonce);
        Ok(())
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
}
