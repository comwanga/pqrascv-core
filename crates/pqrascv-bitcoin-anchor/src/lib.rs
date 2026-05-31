//! Non-custodial Bitcoin anchor transaction building and broadcasting for
//! PQ-RASCV (Phase 7A + 7B).
//!
//! This crate is the std/network-facing companion to the no_std commitment
//! core (`pqrascv-bitcoin-anchor`, directory `crates/bitcoin-anchor`). It does
//! **not** fork or duplicate that core: it reuses [`AnchorCommitment`] and the
//! OP_RETURN format verbatim, and adds:
//!
//! - **7A** [`AnchorBuilder`]: turns a commitment (or any 32-byte artifact
//!   root) into an OP_RETURN `TxOut` and an **unsigned** [`bitcoin::Transaction`]
//!   template assembled from caller-supplied inputs and change outputs.
//!   Non-custodial: no wallet, no key custody, no signing.
//! - **7B** [`Broadcaster`]: an idempotent, retrying broadcast trait with an
//!   always-on [`MockBroadcaster`] and live reference backends
//!   ([`BitcoinCoreRpc`], [`Esplora`], [`Electrum`]) behind the `live-network`
//!   feature.
//!
//! All Bitcoin consensus concerns (script encoding, consensus serialization,
//! txid double-SHA256) are delegated to the `bitcoin` (rust-bitcoin) crate.
//!
//! [`AnchorCommitment`]: pqrascv_bitcoin_anchor::AnchorCommitment
//! [`BitcoinCoreRpc`]: crate::backends::BitcoinCoreRpc
//! [`Esplora`]: crate::backends::Esplora
//! [`Electrum`]: crate::backends::Electrum

#![forbid(unsafe_code)]
// Domain terms like `OP_RETURN`, `SegWit`, `no_std`, `std` recur throughout the
// docs; backtick-quoting each occurrence adds noise without value.
#![allow(clippy::doc_markdown)]

pub mod broadcast;
pub mod builder;
pub mod multi_source;
pub mod oracle;

#[cfg(feature = "live-network")]
pub mod backends;

pub use broadcast::{
    retry_broadcast, BroadcastError, Broadcaster, FeeRate, MockBroadcaster, RetryConfig,
};
pub use builder::{
    AnchorBuilder, AnchorTx, BuildError, ANCHOR_TX_LOCKTIME, ANCHOR_TX_VERSION,
};
pub use multi_source::MultiSourceHeaderOracle;
pub use oracle::{validate_chain, FixtureHeaderOracle, HeaderOracle, OracleError, RETARGET_INTERVAL};

// Re-export the reused core commitment type for convenience so downstream users
// need only depend on this crate at the boundary.
pub use pqrascv_bitcoin_anchor::{AnchorCommitment, ANCHOR_PAYLOAD_SIZE};
