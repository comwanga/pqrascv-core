//! Redis-backed [`NonceLedger`] with atomic single-use via `SET … NX`.
//!
//! Uses the synchronous `redis::Connection`, so it implements the synchronous
//! `NonceLedger` trait directly with no async runtime.
//!
//! # Atomicity
//!
//! Single-use is enforced by `SET <key> 1 NX EX <ttl>`: the `NX` flag makes
//! Redis create the key only if it does not already exist, atomically on the
//! server. Exactly one caller — across all nodes — observes `OK`; concurrent or
//! later callers observe `nil` and are rejected. This is the consume step.
//!
//! # Model
//!
//! Because consume is the single atomic write, [`register`] is a no-op that
//! merely returns a handle (the verifier still needs the nonce bytes to embed
//! in the challenge). The replay-protection invariant lives entirely in the
//! atomic `SET NX` at consume time. TTL is applied via `EX`, matching the
//! contract's TTL-eviction semantics: Redis expires the key, after which the
//! same nonce value can be consumed again as if fresh.
//!
//! # Crash recovery
//!
//! With Redis persistence (AOF/RDB) enabled, consumed-nonce keys survive a
//! client *or* server restart, so a replayed nonce is still rejected after a
//! restart — satisfying the contract's crash-recovery requirement. (A purely
//! in-memory Redis without persistence does not; that is a deployment choice.)

use pqrascv_core::error::PqRascvError;
use pqrascv_core::nonce::{InMemoryNonceLedger, NonceHandle, NonceLedger};

/// Default key prefix for nonce entries.
const DEFAULT_PREFIX: &str = "pqrascv:nonce:";

/// Redis-backed distributed [`NonceLedger`].
pub struct RedisNonceLedger {
    conn: redis::Connection,
    prefix: String,
    /// TTL (seconds) applied to consumed-nonce keys when `consume` (no explicit
    /// `now`) is used. `consume_at` / `register_with_ttl` derive their own.
    default_ttl_secs: u64,
}

impl RedisNonceLedger {
    /// Connects to Redis at `url` (e.g. `redis://127.0.0.1/`).
    ///
    /// `default_ttl_secs` is the expiry applied to consumed keys via the
    /// non-TTL [`consume`](NonceLedger::consume) path; `0` means no expiry
    /// (keys persist until evicted by Redis policy).
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::InternalError`] if the client cannot be built or
    /// a connection cannot be opened.
    pub fn connect(url: &str, default_ttl_secs: u64) -> Result<Self, PqRascvError> {
        let client = redis::Client::open(url).map_err(|_| PqRascvError::InternalError)?;
        let conn = client
            .get_connection()
            .map_err(|_| PqRascvError::InternalError)?;
        Ok(Self {
            conn,
            prefix: DEFAULT_PREFIX.to_string(),
            default_ttl_secs,
        })
    }

    /// Overrides the key prefix (useful to isolate test namespaces).
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn key(&self, nonce: &[u8; 32]) -> String {
        let mut s = String::with_capacity(self.prefix.len() + 64);
        s.push_str(&self.prefix);
        for b in nonce {
            use core::fmt::Write as _;
            // hex encode; write! to a String is infallible.
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Atomic `SET key 1 NX [EX ttl]`. Returns `Ok(true)` if this caller won
    /// the create (i.e. the nonce was not previously consumed), `Ok(false)` if
    /// the key already existed (replay).
    fn set_nx(&mut self, nonce: &[u8; 32], ttl_secs: u64) -> Result<bool, PqRascvError> {
        let key = self.key(nonce);
        // redis-rs returns Option<String>: Some("OK") on create, None on
        // conflict (NX failed). Build the command explicitly to attach EX.
        let mut cmd = redis::cmd("SET");
        cmd.arg(&key).arg(1).arg("NX");
        if ttl_secs > 0 {
            cmd.arg("EX").arg(ttl_secs);
        }
        let created: Option<String> = cmd
            .query(&mut self.conn)
            .map_err(|_| PqRascvError::InternalError)?;
        Ok(created.is_some())
    }
}

impl NonceLedger for RedisNonceLedger {
    fn register(&mut self, nonce: [u8; 32]) -> Result<NonceHandle, PqRascvError> {
        // Registration carries no server state for the SET-NX model; mint a
        // handle so the caller can embed the nonce in a challenge.
        let mut tmp = InMemoryNonceLedger::default();
        tmp.register(nonce)
    }

    fn register_with_ttl(
        &mut self,
        nonce: [u8; 32],
        _now: u64,
        ttl_secs: u64,
    ) -> Result<NonceHandle, PqRascvError> {
        // Stash the TTL for the matching consume by remembering it on the
        // default; the atomic write happens at consume time. The verifier is
        // expected to consume with consume_at and the same ttl horizon.
        self.default_ttl_secs = ttl_secs;
        self.register(nonce)
    }

    fn consume(&mut self, nonce: &[u8; 32]) -> Result<(), PqRascvError> {
        let ttl = self.default_ttl_secs;
        if self.set_nx(nonce, ttl)? {
            Ok(())
        } else {
            Err(PqRascvError::InvalidNonce)
        }
    }

    fn consume_at(&mut self, nonce: &[u8; 32], _now: u64) -> Result<(), PqRascvError> {
        // Redis enforces TTL server-side via the EX set at consume; an expired
        // key simply no longer exists, so a re-consume after expiry creates a
        // fresh key (allowed), matching the TTL-eviction contract.
        self.consume(nonce)
    }
}
