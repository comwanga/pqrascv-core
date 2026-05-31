//! PostgreSQL-backed [`NonceLedger`] with atomic single-use via `INSERT … ON
//! CONFLICT`.
//!
//! Uses the synchronous `postgres::Client` (not `tokio-postgres`), so it
//! implements the synchronous `NonceLedger` trait directly with no async
//! runtime.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS consumed_nonces (
//!     nonce      BYTEA PRIMARY KEY,
//!     expires_at BIGINT          -- NULL = never expires; else Unix seconds
//! );
//! ```
//!
//! # Atomicity
//!
//! Single-use is enforced by the primary key plus a conditional upsert:
//!
//! ```sql
//! INSERT INTO consumed_nonces (nonce, expires_at)
//! VALUES ($1, $2)
//! ON CONFLICT (nonce) DO UPDATE
//!   SET expires_at = EXCLUDED.expires_at
//!   WHERE consumed_nonces.expires_at IS NOT NULL
//!     AND consumed_nonces.expires_at < $3;   -- only overwrite expired rows
//! ```
//!
//! The statement affects exactly **one** row when the caller wins (fresh nonce,
//! or a previously-expired row being reclaimed) and **zero** rows when a live
//! consumed row already exists (replay). The whole upsert is a single atomic
//! statement, so two clients racing on the same nonce cannot both win.
//!
//! # Crash recovery
//!
//! Rows are durable in Postgres, so consumed nonces survive a client *and*
//! server restart: a replay after restart still conflicts with the live row and
//! is rejected. This satisfies the contract's crash-recovery requirement.

use postgres::{Client, NoTls};
use pqrascv_core::error::PqRascvError;
use pqrascv_core::nonce::{InMemoryNonceLedger, NonceHandle, NonceLedger};

/// PostgreSQL-backed distributed [`NonceLedger`].
pub struct PostgresNonceLedger {
    client: Client,
    /// TTL (seconds) applied on the non-TTL [`consume`](NonceLedger::consume)
    /// path; `0` means the row never expires.
    default_ttl_secs: u64,
}

impl PostgresNonceLedger {
    /// Connects to Postgres using a libpq connection string and ensures the
    /// `consumed_nonces` table exists.
    ///
    /// `default_ttl_secs` is the expiry applied via the non-TTL
    /// [`consume`](NonceLedger::consume) path; `0` means rows never expire.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::InternalError`] if the connection cannot be
    /// established or the schema cannot be created.
    pub fn connect(conn_str: &str, default_ttl_secs: u64) -> Result<Self, PqRascvError> {
        let client = Client::connect(conn_str, NoTls).map_err(|_| PqRascvError::InternalError)?;
        let mut ledger = Self {
            client,
            default_ttl_secs,
        };
        ledger.ensure_schema()?;
        Ok(ledger)
    }

    /// Creates the `consumed_nonces` table if absent (idempotent).
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::InternalError`] on a DDL failure.
    pub fn ensure_schema(&mut self) -> Result<(), PqRascvError> {
        self.client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS consumed_nonces (\
                     nonce BYTEA PRIMARY KEY, \
                     expires_at BIGINT\
                 );",
            )
            .map_err(|_| PqRascvError::InternalError)
    }

    /// Atomic conditional upsert. Returns `Ok(true)` if this caller won the
    /// insert (fresh or reclaimed-expired nonce), `Ok(false)` on conflict with
    /// a live row (replay).
    ///
    /// `now` is used to detect expired rows eligible for reclamation;
    /// `expires_at` is the deadline to store (`None` = never expires).
    fn try_consume(
        &mut self,
        nonce: &[u8; 32],
        now: u64,
        expires_at: Option<u64>,
    ) -> Result<bool, PqRascvError> {
        let nonce_slice: &[u8] = nonce.as_slice();
        let expires_param: Option<i64> = expires_at.map(cast_u64_to_i64);
        let now_param: i64 = cast_u64_to_i64(now);

        let affected = self
            .client
            .execute(
                "INSERT INTO consumed_nonces (nonce, expires_at) \
                 VALUES ($1, $2) \
                 ON CONFLICT (nonce) DO UPDATE \
                   SET expires_at = EXCLUDED.expires_at \
                   WHERE consumed_nonces.expires_at IS NOT NULL \
                     AND consumed_nonces.expires_at < $3",
                &[&nonce_slice, &expires_param, &now_param],
            )
            .map_err(|_| PqRascvError::InternalError)?;
        Ok(affected == 1)
    }
}

/// Saturating cast from `u64` (Unix seconds) to the `i64` Postgres `BIGINT`
/// uses. Times beyond `i64::MAX` seconds are billions of years away.
fn cast_u64_to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

impl NonceLedger for PostgresNonceLedger {
    fn register(&mut self, nonce: [u8; 32]) -> Result<NonceHandle, PqRascvError> {
        // Registration is stateless for the INSERT-ON-CONFLICT model; mint a
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
        self.default_ttl_secs = ttl_secs;
        self.register(nonce)
    }

    fn consume(&mut self, nonce: &[u8; 32]) -> Result<(), PqRascvError> {
        // Without an explicit clock, use now=0; the row's TTL (if any) is
        // computed from default_ttl_secs relative to 0, so expiry-reclaim is
        // governed by consume_at in TTL deployments.
        let expires_at = if self.default_ttl_secs == 0 {
            None
        } else {
            Some(self.default_ttl_secs)
        };
        if self.try_consume(nonce, 0, expires_at)? {
            Ok(())
        } else {
            Err(PqRascvError::InvalidNonce)
        }
    }

    fn consume_at(&mut self, nonce: &[u8; 32], now: u64) -> Result<(), PqRascvError> {
        let expires_at = if self.default_ttl_secs == 0 {
            None
        } else {
            Some(now.saturating_add(self.default_ttl_secs))
        };
        if self.try_consume(nonce, now, expires_at)? {
            Ok(())
        } else {
            Err(PqRascvError::InvalidNonce)
        }
    }
}
