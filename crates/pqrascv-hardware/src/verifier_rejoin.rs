use serde::{Deserialize, Serialize};

/// Represents cryptographic proof provided by a verifier attempting to rejoin the federation after downtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejoinProof {
    /// The identity of the verifier attempting to rejoin.
    pub verifier_id: String,
    /// The last governance epoch this verifier was synchronized with.
    pub last_known_epoch: u64,
    /// The minimum required retained checkpoint root proving historical continuity depth.
    pub retained_checkpoint_root: [u8; 32],
    /// The root of the verifier's local timeline.
    pub timeline_root: [u8; 32],
    /// The root of the verifier's local governance state.
    pub governance_root: [u8; 32],
    /// Proof of the verifier's recovery lineage ancestry.
    pub lineage_proof_root: [u8; 32],
}

impl RejoinProof {
    /// Validates a rejoin attempt against the federation's current consensus state.
    ///
    /// # Arguments
    /// * `current_epoch` - The active governance epoch.
    /// * `is_revoked` - Whether this verifier identity has been revoked.
    /// * `expected_lineage` - The required recovery lineage for the given `last_known_epoch`.
    /// * `is_hlc_synchronized` - Whether the verifier has successfully synchronized its Hybrid Logical Clock.
    #[must_use]
    pub fn is_valid_rejoin(
        &self,
        current_epoch: u64,
        is_revoked: bool,
        expected_lineage: &[u8; 32],
        is_hlc_synchronized: bool,
    ) -> bool {
        // A revoked verifier can NEVER rejoin.
        if is_revoked {
            return false;
        }

        // Verifier must not be claiming a future epoch.
        if self.last_known_epoch > current_epoch {
            return false;
        }

        // Must prove recovery lineage.
        if self.lineage_proof_root != *expected_lineage {
            return false;
        }

        // Time semantics must be synchronized before joining consensus.
        if !is_hlc_synchronized {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_rejoin_proof() {
        let proof = RejoinProof {
            verifier_id: "ver-01".into(),
            last_known_epoch: 10,
            retained_checkpoint_root: [1; 32],
            timeline_root: [2; 32],
            governance_root: [3; 32],
            lineage_proof_root: [4; 32],
        };

        assert!(proof.is_valid_rejoin(12, false, &[4; 32], true));
    }

    #[test]
    fn revoked_verifier_rejected() {
        let proof = RejoinProof {
            verifier_id: "ver-01".into(),
            last_known_epoch: 10,
            retained_checkpoint_root: [1; 32],
            timeline_root: [2; 32],
            governance_root: [3; 32],
            lineage_proof_root: [4; 32],
        };

        // is_revoked = true
        assert!(!proof.is_valid_rejoin(12, true, &[4; 32], true));
    }

    #[test]
    fn unsynchronized_hlc_rejected() {
        let proof = RejoinProof {
            verifier_id: "ver-01".into(),
            last_known_epoch: 10,
            retained_checkpoint_root: [1; 32],
            timeline_root: [2; 32],
            governance_root: [3; 32],
            lineage_proof_root: [4; 32],
        };

        // is_hlc_synchronized = false
        assert!(!proof.is_valid_rejoin(12, false, &[4; 32], false));
    }

    #[test]
    fn invalid_lineage_rejected() {
        let proof = RejoinProof {
            verifier_id: "ver-01".into(),
            last_known_epoch: 10,
            retained_checkpoint_root: [1; 32],
            timeline_root: [2; 32],
            governance_root: [3; 32],
            lineage_proof_root: [5; 32], // Doesn't match expected [4; 32]
        };

        assert!(!proof.is_valid_rejoin(12, false, &[4; 32], true));
    }
}
