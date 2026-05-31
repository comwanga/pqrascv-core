//! Live-server conformance + distributed-replay tests for the real Redis and
//! PostgreSQL backends.
//!
//! These are gated behind BOTH the `integration-tests` feature AND the relevant
//! environment variable (`REDIS_URL` / `POSTGRES_URL`). With neither set, the
//! file compiles to nothing under the feature and is entirely absent without
//! it, so `cargo test` stays green with no services running.
//!
//! Run against live servers with, e.g.:
//!
//! ```sh
//! REDIS_URL=redis://127.0.0.1/ \
//! POSTGRES_URL=postgres://postgres@127.0.0.1/postgres \
//!   cargo test -p pqrascv-nonce-backends --features integration-tests
//! ```

#![cfg(feature = "integration-tests")]

use pqrascv_core::error::PqRascvError;
use pqrascv_core::nonce::NonceLedger;
use pqrascv_nonce_backends::conformance::{
    assert_distributed_single_use, assert_fresh_nonce_registers_and_consumes,
    assert_second_consume_rejected, assert_unknown_nonce_rejected,
};

// ── Redis ──────────────────────────────────────────────────────────────────

#[cfg(feature = "redis-backend")]
mod redis_live {
    use super::*;
    use pqrascv_nonce_backends::RedisNonceLedger;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NS: AtomicU64 = AtomicU64::new(0);

    fn url() -> Option<String> {
        std::env::var("REDIS_URL").ok()
    }

    /// A ledger in a unique, freshly-flushed key namespace.
    fn ledger(url: &str) -> RedisNonceLedger {
        let n = NS.fetch_add(1, Ordering::Relaxed);
        let prefix = format!("pqrascv:test:{n}:");
        RedisNonceLedger::connect(url, 0)
            .expect("connect redis")
            .with_prefix(prefix)
    }

    #[test]
    fn redis_conformance() {
        let Some(url) = url() else {
            eprintln!("REDIS_URL unset — skipping redis_conformance");
            return;
        };
        assert_fresh_nonce_registers_and_consumes(|| ledger(&url));
        assert_second_consume_rejected(|| ledger(&url));
        assert_unknown_nonce_rejected(|| ledger(&url));
    }

    #[test]
    fn redis_distributed_single_use() {
        let Some(url) = url() else {
            eprintln!("REDIS_URL unset — skipping redis_distributed_single_use");
            return;
        };
        // Two independent connections sharing one Redis + key namespace.
        let n = NS.fetch_add(1, Ordering::Relaxed);
        let prefix = format!("pqrascv:test:dist:{n}:");
        assert_distributed_single_use(|| {
            let a = RedisNonceLedger::connect(&url, 0)
                .unwrap()
                .with_prefix(prefix.clone());
            let b = RedisNonceLedger::connect(&url, 0)
                .unwrap()
                .with_prefix(prefix.clone());
            (a, b)
        });
    }

    #[test]
    fn redis_ttl_expiry() {
        let Some(url) = url() else {
            eprintln!("REDIS_URL unset — skipping redis_ttl_expiry");
            return;
        };
        let mut l = RedisNonceLedger::connect(&url, 1).unwrap();
        let nonce = [0x9Au8; 32];
        l.consume(&nonce).unwrap();
        // Replay within TTL rejected.
        assert_eq!(l.consume(&nonce), Err(PqRascvError::InvalidNonce));
        std::thread::sleep(std::time::Duration::from_millis(1_500));
        // After the 1s Redis EX expiry, the key is gone — consumable again.
        l.consume(&nonce)
            .expect("nonce re-consumable after TTL expiry");
    }
}

// ── Postgres ────────────────────────────────────────────────────────────────

#[cfg(feature = "postgres-backend")]
mod postgres_live {
    use super::*;
    use pqrascv_nonce_backends::PostgresNonceLedger;

    fn conn_str() -> Option<String> {
        std::env::var("POSTGRES_URL").ok()
    }

    fn ledger(conn: &str) -> PostgresNonceLedger {
        let mut l = PostgresNonceLedger::connect(conn, 0).expect("connect postgres");
        l.ensure_schema().unwrap();
        l
    }

    #[test]
    fn postgres_conformance() {
        let Some(conn) = conn_str() else {
            eprintln!("POSTGRES_URL unset — skipping postgres_conformance");
            return;
        };
        // Use distinct nonce values per assertion; the shared table persists.
        assert_fresh_nonce_registers_and_consumes(|| ledger(&conn));
        assert_second_consume_rejected(|| ledger(&conn));
        assert_unknown_nonce_rejected(|| ledger(&conn));
    }

    #[test]
    fn postgres_distributed_single_use() {
        let Some(conn) = conn_str() else {
            eprintln!("POSTGRES_URL unset — skipping postgres_distributed_single_use");
            return;
        };
        assert_distributed_single_use(|| (ledger(&conn), ledger(&conn)));
    }

    #[test]
    fn postgres_ttl_reclaim() {
        let Some(conn) = conn_str() else {
            eprintln!("POSTGRES_URL unset — skipping postgres_ttl_reclaim");
            return;
        };
        let mut l = PostgresNonceLedger::connect(&conn, 60).unwrap();
        l.ensure_schema().unwrap();
        let nonce = [0x8Bu8; 32];
        // Consume at t=1000 with 60s TTL → expires_at=1060.
        l.consume_at(&nonce, 1_000).unwrap();
        // Replay before expiry rejected.
        assert_eq!(l.consume_at(&nonce, 1_030), Err(PqRascvError::InvalidNonce));
        // After expiry, the expired row is reclaimable.
        l.consume_at(&nonce, 2_000)
            .expect("expired row must be reclaimable");
    }
}
