//! Distributed replay-protection backends for PQ-RASCV.
//!
//! This crate provides reference [`NonceLedger`](pqrascv_core::nonce::NonceLedger)
//! implementations backed by shared persistent stores, satisfying the
//! distributed single-use and crash-recovery portions of the
//! [`NonceLedger` TTL & crash-recovery contract](pqrascv_core::nonce).
//!
//! - [`RedisNonceLedger`] — atomic single-use via `SET key val NX EX <ttl>`.
//! - [`PostgresNonceLedger`] — atomic single-use via
//!   `INSERT … ON CONFLICT DO NOTHING` against a `consumed_nonces` table.
//!
//! Both use **synchronous** clients (the `redis` sync `Connection` and the
//! `postgres` sync client) so they implement the synchronous `NonceLedger`
//! trait directly, with no async runtime.
//!
//! # Single-use atomicity
//!
//! Each backend collapses register+consume into a single atomic store
//! operation so that two ledger handles racing on the same nonce — even on
//! different processes/nodes — cannot both succeed:
//!
//! - **Redis**: `SET nonce 1 NX EX ttl` returns `OK` for exactly the first
//!   caller; every later caller gets `nil` and is rejected.
//! - **Postgres**: `INSERT INTO consumed_nonces … ON CONFLICT DO NOTHING`
//!   inserts exactly one row; the loser observes `0` rows affected.
//!
//! # Testing
//!
//! The [`conformance`] module contains a store-agnostic contract suite. It runs
//! against an in-memory fake by default (see the crate's tests). Live-server
//! tests are gated behind the `integration-tests` feature **and** the
//! `REDIS_URL` / `POSTGRES_URL` environment variables, so `cargo test` is green
//! with no services running.

#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod conformance;

#[cfg(feature = "redis-backend")]
mod redis_backend;
#[cfg(feature = "redis-backend")]
pub use redis_backend::RedisNonceLedger;

#[cfg(feature = "postgres-backend")]
mod postgres_backend;
#[cfg(feature = "postgres-backend")]
pub use postgres_backend::PostgresNonceLedger;
