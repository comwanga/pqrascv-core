use serde::{Deserialize, Serialize};

/// Represents an explicit checkpoint in a disaster recovery scenario.
///
/// Disaster recovery checkpoints maintain an append-only chain, providing
/// deterministic restoration boundaries that can be globally audited via Bitcoin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasterRecoveryCheckpoint {
    /// A unique identifier for this recovery checkpoint.
    pub checkpoint_id: String,
    /// The canonical hash of the `FederationSnapshot` that this recovery anchors to.
    pub snapshot_hash: [u8; 32],
    /// The governance epoch at the time of recovery.
    pub recovery_epoch: u64,
    /// The root hash of the reconstructed federation state post-recovery.
    pub federation_state_hash: [u8; 32],
}

impl DisasterRecoveryCheckpoint {
    /// Validates the structural integrity of the recovery checkpoint.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.checkpoint_id.is_empty() {
            return false;
        }

        // Hashes must be populated
        if self.snapshot_hash == [0; 32] || self.federation_state_hash == [0; 32] {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_disaster_recovery_checkpoint() {
        let cp = DisasterRecoveryCheckpoint {
            checkpoint_id: "dr-01".into(),
            snapshot_hash: [1; 32],
            recovery_epoch: 42,
            federation_state_hash: [2; 32],
        };
        assert!(cp.is_valid());
    }

    #[test]
    fn invalid_dr_checkpoint_empty_id() {
        let cp = DisasterRecoveryCheckpoint {
            checkpoint_id: String::new(),
            snapshot_hash: [1; 32],
            recovery_epoch: 42,
            federation_state_hash: [2; 32],
        };
        assert!(!cp.is_valid());
    }

    #[test]
    fn invalid_dr_checkpoint_zeroed_hash() {
        let cp = DisasterRecoveryCheckpoint {
            checkpoint_id: "dr-01".into(),
            snapshot_hash: [0; 32],
            recovery_epoch: 42,
            federation_state_hash: [2; 32],
        };
        assert!(!cp.is_valid());
    }
}
