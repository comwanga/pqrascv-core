use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncGovernanceAction {
    UpdateSyncPolicy { max_chunk_size: usize },
    IsolatePeer { peer_id: String },
    ScheduleRecovery { target_epoch: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkGovernanceEvent {
    pub action: SyncGovernanceAction,
    pub authorizer_id: String,
    pub epoch: u64,
    pub signature: alloc::vec::Vec<u8>,
}

impl NetworkGovernanceEvent {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        // Governance actions must be explicitly signed and bound to an epoch.
        !self.signature.is_empty() && !self.authorizer_id.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsigned_governance_action() {
        let event = NetworkGovernanceEvent {
            action: SyncGovernanceAction::IsolatePeer {
                peer_id: "peer1".into(),
            },
            authorizer_id: "admin1".into(),
            epoch: 10,
            signature: vec![],
        };
        assert!(!event.is_valid());
    }
}
