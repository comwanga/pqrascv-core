use serde::{Deserialize, Serialize};

/// Represents the recovery and reformation of a Byzantine quorum.
///
/// Quorum reformation is a distinct, append-only governance event.
/// It prevents hidden federation replacements by requiring explicit cryptographic linkages
/// to the previous quorum state, even if the membership or thresholds have changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReformedQuorum {
    /// The cryptographic root of the previous (failed or deprecated) quorum.
    pub previous_quorum_root: [u8; 32],
    /// The cryptographic root of the newly reformed quorum.
    pub reformed_quorum_root: [u8; 32],
    /// The set of verifier identities participating in the new quorum.
    pub participating_verifiers: alloc::vec::Vec<String>,
    /// The governance epoch in which this reformation was enacted.
    pub governance_epoch: u64,
}

impl ReformedQuorum {
    /// Validates the structure of the reformed quorum.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        // A quorum must have participants.
        if self.participating_verifiers.is_empty() {
            return false;
        }

        // Roots must not be empty/zeroed unless this is the genesis quorum,
        // but this struct specifically represents *reformation* of an existing quorum.
        if self.previous_quorum_root == [0; 32] || self.reformed_quorum_root == [0; 32] {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_quorum_reformation() {
        let reformed = ReformedQuorum {
            previous_quorum_root: [1; 32],
            reformed_quorum_root: [2; 32],
            participating_verifiers: vec!["ver-01".into(), "ver-02".into(), "ver-03".into()],
            governance_epoch: 15,
        };

        assert!(reformed.is_valid());
    }

    #[test]
    fn invalid_reformation_no_participants() {
        let reformed = ReformedQuorum {
            previous_quorum_root: [1; 32],
            reformed_quorum_root: [2; 32],
            participating_verifiers: vec![],
            governance_epoch: 15,
        };

        assert!(!reformed.is_valid());
    }

    #[test]
    fn invalid_reformation_genesis_roots() {
        let reformed = ReformedQuorum {
            previous_quorum_root: [0; 32],
            reformed_quorum_root: [2; 32],
            participating_verifiers: vec!["ver-01".into()],
            governance_epoch: 15,
        };

        assert!(!reformed.is_valid());
    }
}
