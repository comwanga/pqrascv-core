use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconstructedFederationState {
    pub federation_id: String,
    pub epoch: u64,
    pub state_root: [u8; 32],
    pub is_verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconstructionReport {
    pub reconstructed_epoch: u64,
    pub matched_checkpoint: bool,
    pub ambiguous_paths_rejected: usize,
}

impl ReconstructedFederationState {
    pub fn verify_continuity(&self, previous_state_root: [u8; 32]) -> Result<(), &'static str> {
        if !self.is_verified {
            return Err("State is not cryptographically verified");
        }
        // In a real implementation, we would verify the Merkle path from previous to current
        if previous_state_root == [0; 32] && self.epoch > 0 {
            return Err("Missing lineage to previous state");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unverified_reconstruction() {
        let state = ReconstructedFederationState {
            federation_id: "fed1".into(),
            epoch: 1,
            state_root: [1; 32],
            is_verified: false,
        };
        assert!(state.verify_continuity([0; 32]).is_err());
    }
}
