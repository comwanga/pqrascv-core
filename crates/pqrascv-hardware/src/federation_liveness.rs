use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LivenessFailureReason {
    QuorumStagnation,
    SyncStall,
    PeerStarvation,
    PersistentPartition,
    ConvergenceDegradation,
}

/// Tracks the active liveness and convergence of the federation.
/// Separates correctness (policy) from liveness (availability) to ensure
/// secure operation isn't conflated with available operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationLivenessState {
    pub current_epoch: u64,
    pub last_quorum_timestamp: u64,
    pub active_sync_peers: usize,
    pub required_quorum: usize,
    pub failures: alloc::vec::Vec<LivenessFailureReason>,
}

impl FederationLivenessState {
    #[must_use]
    pub fn is_live(&self, current_timestamp: u64, max_stagnation_window: u64) -> bool {
        if self.active_sync_peers < self.required_quorum {
            return false;
        }

        // Check if the quorum has stagnated beyond the allowed window
        if current_timestamp.saturating_sub(self.last_quorum_timestamp) > max_stagnation_window {
            return false;
        }

        self.failures.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liveness_fails_on_quorum_stagnation() {
        let state = FederationLivenessState {
            current_epoch: 5,
            last_quorum_timestamp: 100,
            active_sync_peers: 5,
            required_quorum: 3,
            failures: vec![],
        };
        // Max window is 50. Current time is 160. Stagnation = 60 > 50.
        assert!(!state.is_live(160, 50));
    }

    #[test]
    fn liveness_fails_on_peer_starvation() {
        let state = FederationLivenessState {
            current_epoch: 5,
            last_quorum_timestamp: 100,
            active_sync_peers: 2,
            required_quorum: 3,
            failures: vec![],
        };
        assert!(!state.is_live(110, 50));
    }
}
