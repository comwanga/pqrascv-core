//! Live Operational Node Observation
//!
//! Provides the semantics for tracking a Bitcoin node's lifecycle across time.
//! Detects runtime restarts, workload mutation, configuration drift, and gaps
//! in the continuity of received live evidence streams.

#![cfg(feature = "live-evidence")]

use crate::bitcoin_runtime_monitor::BitcoinRuntimeState;
use crate::freshness::FreshnessStatus;
use alloc::string::String;

/// An operational snapshot of a Bitcoin node's trust state and runtime posture
/// at a specific point in time, derived from real collected evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeObservation {
    pub node_id: String,
    pub observed_at: u64,
    pub runtime_state: BitcoinRuntimeState,
    pub integrity_status: FreshnessStatus,
}

impl NodeObservation {
    /// Constructs a new observation from validated evidence fields.
    pub fn new(
        node_id: String,
        observed_at: u64,
        runtime_state: BitcoinRuntimeState,
        integrity_status: FreshnessStatus,
    ) -> Self {
        Self {
            node_id,
            observed_at,
            runtime_state,
            integrity_status,
        }
    }

    /// Evaluates if this observation represents a discontinuous gap or malicious
    /// rollback compared to the last known observation of this node.
    pub fn check_continuity_against(&self, previous: &NodeObservation) -> Result<(), &'static str> {
        if self.observed_at <= previous.observed_at {
            return Err("observation timestamp monotonicity violated");
        }

        if self.integrity_status == FreshnessStatus::Expired
            || self.integrity_status == FreshnessStatus::ReplaySuspected
        {
            return Err("observation integrity status is unacceptable");
        }

        if self.runtime_state.uptime_seconds < previous.runtime_state.uptime_seconds {
            return Err("runtime uptime reversed, indicating an untracked node restart");
        }

        Ok(())
    }
}
