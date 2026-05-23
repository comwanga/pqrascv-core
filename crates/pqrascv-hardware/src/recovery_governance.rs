use serde::{Deserialize, Serialize};

/// Specifies explicit, verifiable governance actions taken during federation recovery.
///
/// All recovery actions are treated as append-only and must be signed by authorized
/// governance members. Silent auto-resolution of recovery states is forbidden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryGovernanceAction {
    /// Approves a specific healing decision for a detected partition.
    ApprovePartitionHealing { partition_id: String },
    /// Approves the reformation of a failed or deprecated quorum.
    ApproveQuorumReformation { reformed_quorum_root: [u8; 32] },
    /// Approves a disaster recovery checkpoint as canonical.
    ApproveRecoveryCheckpoint { checkpoint_id: String },
    /// Approves sovereign migration to a new federation topology.
    ApproveFederationMigration { target_federation_id: String },
    /// Explicitly rejects a proposed recovery state, marking it invalid.
    RejectRecoveryState { reason: String },
}

/// Represents a signed, unforgeable recovery governance event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryGovernanceEvent {
    /// The specific recovery action being authorized.
    pub action: RecoveryGovernanceAction,
    /// The identity of the governance member authorizing the action.
    pub authorizer_id: String,
    /// The governance epoch in which this action was signed.
    pub epoch: u64,
    /// Cryptographic signature over the action, `authorizer_id`, and epoch.
    pub signature: alloc::vec::Vec<u8>,
}

impl RecoveryGovernanceEvent {
    /// Validates the structural integrity of the governance event.
    /// (Cryptographic signature verification would occur at a higher policy layer).
    #[must_use]
    pub fn is_structurally_valid(&self) -> bool {
        if self.authorizer_id.is_empty() {
            return false;
        }

        if self.signature.is_empty() {
            return false;
        }

        match &self.action {
            RecoveryGovernanceAction::ApprovePartitionHealing { partition_id } => {
                !partition_id.is_empty()
            }
            RecoveryGovernanceAction::ApproveQuorumReformation { reformed_quorum_root } => {
                *reformed_quorum_root != [0; 32]
            }
            RecoveryGovernanceAction::ApproveRecoveryCheckpoint { checkpoint_id } => {
                !checkpoint_id.is_empty()
            }
            RecoveryGovernanceAction::ApproveFederationMigration { target_federation_id } => {
                !target_federation_id.is_empty()
            }
            RecoveryGovernanceAction::RejectRecoveryState { reason } => !reason.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_recovery_governance_event() {
        let ev = RecoveryGovernanceEvent {
            action: RecoveryGovernanceAction::ApprovePartitionHealing {
                partition_id: "part-01".into(),
            },
            authorizer_id: "gov-auth-1".into(),
            epoch: 5,
            signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        assert!(ev.is_structurally_valid());
    }

    #[test]
    fn invalid_event_empty_signature() {
        let ev = RecoveryGovernanceEvent {
            action: RecoveryGovernanceAction::ApprovePartitionHealing {
                partition_id: "part-01".into(),
            },
            authorizer_id: "gov-auth-1".into(),
            epoch: 5,
            signature: vec![],
        };
        assert!(!ev.is_structurally_valid());
    }

    #[test]
    fn invalid_event_empty_partition_id() {
        let ev = RecoveryGovernanceEvent {
            action: RecoveryGovernanceAction::ApprovePartitionHealing {
                partition_id: "".into(),
            },
            authorizer_id: "gov-auth-1".into(),
            epoch: 5,
            signature: vec![0xDE, 0xAD],
        };
        assert!(!ev.is_structurally_valid());
    }
}
