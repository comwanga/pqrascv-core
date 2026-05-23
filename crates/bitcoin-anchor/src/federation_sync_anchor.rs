use alloc::string::String;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FederationSyncAnchor {
    SnapshotAnchor {
        snapshot_id: String,
        manifest_root: [u8; 32],
    },
    ReconstructionAnchor {
        epoch: u64,
        reconstructed_state_root: [u8; 32],
    },
    LivenessAnchor {
        epoch: u64,
        liveness_state_hash: [u8; 32],
    },
    GovernanceAnchor {
        action_hash: [u8; 32],
        authorizer_id: String,
    },
}

impl FederationSyncAnchor {
    pub fn is_valid(&self) -> bool {
        match self {
            Self::SnapshotAnchor {
                snapshot_id,
                manifest_root,
            } => !snapshot_id.is_empty() && *manifest_root != [0; 32],
            Self::ReconstructionAnchor {
                reconstructed_state_root,
                ..
            } => *reconstructed_state_root != [0; 32],
            Self::LivenessAnchor {
                liveness_state_hash,
                ..
            } => *liveness_state_hash != [0; 32],
            Self::GovernanceAnchor {
                action_hash,
                authorizer_id,
            } => *action_hash != [0; 32] && !authorizer_id.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    #[test]
    fn invalid_snapshot_anchor_rejected() {
        let anchor = FederationSyncAnchor::SnapshotAnchor {
            snapshot_id: "".into(),
            manifest_root: [0; 32],
        };
        assert!(!anchor.is_valid());
    }
}
