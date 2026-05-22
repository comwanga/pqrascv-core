//! Bitcoin Runtime Monitor
//!
//! Provides continuous node runtime observation capturing the operational state
//! of the node without participating in Bitcoin consensus validation.

use alloc::string::String;

/// A snapshot of the operational state of a running Bitcoin node.
///
/// **Note:** This reflects workload observability, not consensus validity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BitcoinRuntimeState {
    /// The unique identity of the node being monitored.
    pub node_id: String,
    /// The number of peers currently connected to the node.
    pub peers_connected: u32,
    /// The block height of the chain tip currently known to the node.
    pub chain_tip_height: u64,
    /// Indicates whether the node's mempool is actively accepting transactions.
    pub mempool_enabled: bool,
    /// Indicates whether the RPC interface is enabled and responsive.
    pub rpc_enabled: bool,
    /// Indicates whether the node is running in pruned mode.
    pub pruned: bool,
}

impl BitcoinRuntimeState {
    /// Creates a new `BitcoinRuntimeState`.
    #[must_use]
    pub fn new(
        node_id: String,
        peers_connected: u32,
        chain_tip_height: u64,
        mempool_enabled: bool,
        rpc_enabled: bool,
        pruned: bool,
    ) -> Self {
        Self {
            node_id,
            peers_connected,
            chain_tip_height,
            mempool_enabled,
            rpc_enabled,
            pruned,
        }
    }
}
