//! Broadcast layer: the [`Broadcaster`] trait, shared error/fee types, retry
//! helper, and an always-on [`MockBroadcaster`] for deterministic contract
//! tests.
//!
//! Real backends ([`crate::backends`]) are gated behind the `live-network`
//! feature and only touch the network when the relevant environment variables
//! are set. The broadcast *contract* (idempotency, bounded retry, fee
//! estimation) is fully exercised here against the mock with no network.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU32, Ordering};

use bitcoin::{Transaction, Txid};

/// A fee rate in satoshis per virtual byte.
///
/// rust-bitcoin's `FeeRate` is per-kwu and easy to misuse; we expose a small,
/// explicit sat/vB wrapper at the broadcast boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeeRate {
    sat_per_vb: u64,
}

impl FeeRate {
    /// Constructs a fee rate from satoshis per virtual byte.
    #[must_use]
    pub fn from_sat_per_vb(sat_per_vb: u64) -> Self {
        Self { sat_per_vb }
    }

    /// Returns the rate in satoshis per virtual byte.
    #[must_use]
    pub fn sat_per_vb(&self) -> u64 {
        self.sat_per_vb
    }
}

/// Errors a broadcaster can return.
#[derive(Debug)]
#[non_exhaustive]
pub enum BroadcastError {
    /// A transient error (network blip, node temporarily unavailable). Eligible
    /// for retry.
    Transient(String),
    /// The transaction was rejected by consensus/policy (e.g. bad signature,
    /// non-standard). **Not** retried — retrying cannot help.
    Rejected(String),
    /// Fee estimation is unavailable for the requested target.
    FeeEstimationUnavailable,
    /// Configuration/setup error (e.g. missing required env var for a live
    /// backend).
    Configuration(String),
}

impl BroadcastError {
    /// Whether this error is worth retrying.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient(_))
    }
}

impl core::fmt::Display for BroadcastError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transient(m) => write!(f, "transient broadcast error: {m}"),
            Self::Rejected(m) => write!(f, "transaction rejected: {m}"),
            Self::FeeEstimationUnavailable => f.write_str("fee estimation unavailable"),
            Self::Configuration(m) => write!(f, "broadcaster configuration error: {m}"),
        }
    }
}

impl std::error::Error for BroadcastError {}

/// Bounded retry policy for broadcast submission.
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    /// Maximum number of attempts (must be >= 1). `1` means no retries.
    pub max_attempts: u32,
    /// Base backoff in milliseconds between attempts (linear: attempt N waits
    /// `base_backoff_ms * N`). The mock does not sleep; live backends do.
    pub base_backoff_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_backoff_ms: 250,
        }
    }
}

impl RetryConfig {
    /// A policy with a single attempt (no retries).
    #[must_use]
    pub fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            base_backoff_ms: 0,
        }
    }
}

/// Runs `attempt` up to `cfg.max_attempts` times, retrying only on transient
/// errors. `sleep` is injected so tests stay instant and deterministic.
///
/// # Errors
///
/// Returns the last error if all attempts are exhausted, or immediately on a
/// non-transient error.
pub fn retry_broadcast<F, S>(
    cfg: RetryConfig,
    mut attempt: F,
    mut sleep: S,
) -> Result<Txid, BroadcastError>
where
    F: FnMut() -> Result<Txid, BroadcastError>,
    S: FnMut(u64),
{
    let max = cfg.max_attempts.max(1);
    let mut last_err: Option<BroadcastError> = None;
    for n in 1..=max {
        match attempt() {
            Ok(txid) => return Ok(txid),
            Err(e) if e.is_transient() => {
                last_err = Some(e);
                if n < max {
                    sleep(cfg.base_backoff_ms.saturating_mul(u64::from(n)));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or(BroadcastError::Transient("retry exhausted".into())))
}

/// A Bitcoin transaction broadcaster.
///
/// Implementations MUST be **idempotent**: re-broadcasting a transaction that
/// is already in the mempool or confirmed returns `Ok(txid)`, not an error.
pub trait Broadcaster {
    /// Submits a transaction, returning its txid on success (or if it was
    /// already known to the network).
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastError`] on rejection or unrecoverable transient
    /// failure (after the backend's own retry policy, if any).
    fn broadcast(&self, tx: &Transaction) -> Result<Txid, BroadcastError>;

    /// Estimates a fee rate to get confirmed within `target_blocks`.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastError::FeeEstimationUnavailable`] if no estimate is
    /// available for the target.
    fn estimate_fee(&self, target_blocks: u16) -> Result<FeeRate, BroadcastError>;
}

// ── MockBroadcaster ───────────────────────────────────────────────────────

/// In-memory broadcaster for deterministic contract tests.
///
/// Records every submitted txid, simulates idempotency (a duplicate submission
/// returns `Ok` with the same txid and is **not** double-counted as a new
/// broadcast), and can be primed to fail a configurable number of times with a
/// transient error before succeeding (to exercise retry logic).
#[derive(Debug, Default)]
pub struct MockBroadcaster {
    /// Txids that have been successfully accepted (the simulated mempool/chain).
    accepted: RefCell<Vec<Txid>>,
    /// Number of remaining transient failures to inject before accepting.
    fail_remaining: AtomicU32,
    /// Total number of broadcast *attempts* observed (including injected
    /// failures and idempotent re-submissions).
    attempts: AtomicU32,
    /// Fee rate to report from `estimate_fee`, or `None` to report unavailable.
    fee: Option<FeeRate>,
}

impl MockBroadcaster {
    /// A mock that accepts on the first try and reports a default fee.
    #[must_use]
    pub fn new() -> Self {
        Self {
            accepted: RefCell::new(Vec::new()),
            fail_remaining: AtomicU32::new(0),
            attempts: AtomicU32::new(0),
            fee: Some(FeeRate::from_sat_per_vb(1)),
        }
    }

    /// A mock that returns `n` transient failures before accepting.
    #[must_use]
    pub fn failing(n: u32) -> Self {
        let m = Self::new();
        m.fail_remaining.store(n, Ordering::SeqCst);
        m
    }

    /// Sets the fee rate this mock reports (`None` => unavailable).
    #[must_use]
    pub fn with_fee(mut self, fee: Option<FeeRate>) -> Self {
        self.fee = fee;
        self
    }

    /// Total broadcast attempts observed.
    #[must_use]
    pub fn attempt_count(&self) -> u32 {
        self.attempts.load(Ordering::SeqCst)
    }

    /// Number of distinct accepted transactions (the simulated mempool size).
    #[must_use]
    pub fn accepted_count(&self) -> usize {
        self.accepted.borrow().len()
    }

    /// Whether `txid` is in the simulated mempool/chain.
    #[must_use]
    pub fn contains(&self, txid: &Txid) -> bool {
        self.accepted.borrow().contains(txid)
    }
}

impl Broadcaster for MockBroadcaster {
    fn broadcast(&self, tx: &Transaction) -> Result<Txid, BroadcastError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let txid = tx.compute_txid();

        // Idempotency: already known => Ok, no state change, no double count.
        if self.accepted.borrow().contains(&txid) {
            return Ok(txid);
        }

        // Injected transient failure path (for retry tests).
        if self.fail_remaining.load(Ordering::SeqCst) > 0 {
            self.fail_remaining.fetch_sub(1, Ordering::SeqCst);
            return Err(BroadcastError::Transient(
                "mock injected transient failure".into(),
            ));
        }

        self.accepted.borrow_mut().push(txid);
        Ok(txid)
    }

    fn estimate_fee(&self, _target_blocks: u16) -> Result<FeeRate, BroadcastError> {
        self.fee.ok_or(BroadcastError::FeeEstimationUnavailable)
    }
}
