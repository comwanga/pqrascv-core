use alloc::string::String;
use serde::{Deserialize, Serialize};

/// Represents Bitcoin-anchored proofs of federation recovery actions.
///
/// Anchoring recovery events to Bitcoin ensures global, immutable auditability
/// of the disaster recovery lineage, quorum reformation, and sovereign migrations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryAnchorType {
    /// Anchors a federation snapshot to prove historical state continuity.
    SnapshotAnchor {
        snapshot_id: String,
        snapshot_hash: [u8; 32],
    },
    /// Anchors a disaster recovery checkpoint to prove valid state restoration.
    DisasterRecoveryAnchor {
        checkpoint_id: String,
        recovery_epoch: u64,
        federation_state_hash: [u8; 32],
    },
    /// Anchors a healed partition to prove deterministic divergence resolution.
    PartitionHealingAnchor {
        partition_id: String,
        healed_root: [u8; 32],
    },
    /// Anchors a sovereign federation migration to prove lineage continuity.
    MigrationAnchor {
        source_federation_id: String,
        target_federation_id: String,
        migration_root: [u8; 32],
    },
    /// Anchors a quorum reformation to prove Byzantine-safe threshold evolution.
    QuorumReformationAnchor {
        reformed_quorum_root: [u8; 32],
        governance_epoch: u64,
    },
}

/// A fully constructed Bitcoin anchor for a recovery event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryAnchor {
    /// The specific recovery type being anchored.
    pub anchor_type: RecoveryAnchorType,
    /// The Bitcoin transaction ID (TXID) where this anchor is committed.
    pub txid: [u8; 32],
    /// The block height containing the anchoring transaction.
    pub block_height: u64,
}

impl RecoveryAnchor {
    /// Validates the structural integrity of the recovery anchor.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.txid == [0; 32] {
            return false;
        }

        match &self.anchor_type {
            RecoveryAnchorType::SnapshotAnchor {
                snapshot_id,
                snapshot_hash,
            } => !snapshot_id.is_empty() && *snapshot_hash != [0; 32],
            RecoveryAnchorType::DisasterRecoveryAnchor {
                checkpoint_id,
                federation_state_hash,
                ..
            } => !checkpoint_id.is_empty() && *federation_state_hash != [0; 32],
            RecoveryAnchorType::PartitionHealingAnchor {
                partition_id,
                healed_root,
            } => !partition_id.is_empty() && *healed_root != [0; 32],
            RecoveryAnchorType::MigrationAnchor {
                source_federation_id,
                target_federation_id,
                migration_root,
            } => {
                !source_federation_id.is_empty()
                    && !target_federation_id.is_empty()
                    && *migration_root != [0; 32]
            }
            RecoveryAnchorType::QuorumReformationAnchor {
                reformed_quorum_root,
                ..
            } => *reformed_quorum_root != [0; 32],
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;
    use super::*;

    #[test]
    fn valid_snapshot_anchor() {
        let anchor = RecoveryAnchor {
            anchor_type: RecoveryAnchorType::SnapshotAnchor {
                snapshot_id: "snap-01".into(),
                snapshot_hash: [1; 32],
            },
            txid: [9; 32],
            block_height: 800_000,
        };
        assert!(anchor.is_valid());
    }

    #[test]
    fn invalid_anchor_zero_txid() {
        let anchor = RecoveryAnchor {
            anchor_type: RecoveryAnchorType::SnapshotAnchor {
                snapshot_id: "snap-01".into(),
                snapshot_hash: [1; 32],
            },
            txid: [0; 32],
            block_height: 800_000,
        };
        assert!(!anchor.is_valid());
    }

    #[test]
    fn invalid_migration_anchor() {
        let anchor = RecoveryAnchor {
            anchor_type: RecoveryAnchorType::MigrationAnchor {
                source_federation_id: "".into(),
                target_federation_id: "fed-02".into(),
                migration_root: [1; 32],
            },
            txid: [9; 32],
            block_height: 800_000,
        };
        assert!(!anchor.is_valid());
    }
}
