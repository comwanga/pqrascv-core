//! Sovereign Bitcoin Node Identity
//!
//! Provides the explicit cryptographic identity for a Bitcoin node
//! workload, ensuring that the running binary and configuration match
//! the expected trust anchor.

use crate::digest::TypedDigest;
use alloc::string::String;

/// Supported Bitcoin networks for node identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

/// The definitive cryptographic identity of a running Bitcoin node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BitcoinNodeIdentity {
    /// Unique identifier for this specific node deployment.
    pub node_id: String,
    /// The network this node is configured to join.
    pub network: BitcoinNetwork,
    /// The expected version string of Bitcoin Core (e.g., "26.0.0").
    pub bitcoin_core_version: String,
    /// The expected cryptographic digest of the `bitcoind` executable.
    pub expected_binary_hash: TypedDigest,
    /// The expected cryptographic digest of `bitcoin.conf`.
    pub expected_config_hash: TypedDigest,
}

impl BitcoinNodeIdentity {
    /// Creates a new `BitcoinNodeIdentity`.
    #[must_use]
    pub fn new(
        node_id: String,
        network: BitcoinNetwork,
        bitcoin_core_version: String,
        expected_binary_hash: TypedDigest,
        expected_config_hash: TypedDigest,
    ) -> Self {
        Self {
            node_id,
            network,
            bitcoin_core_version,
            expected_binary_hash,
            expected_config_hash,
        }
    }
}
