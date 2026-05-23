use serde::{Deserialize, Serialize};

/// Explicitly models the ancestry of federation recovery operations.
///
/// Ensures deterministic historical reconstruction, forensic federation analysis,
/// and unbroken migration lineage tracing. Prevents fragmented histories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryLineage {
    /// The canonical root hash representing the current recovery state.
    pub lineage_root: [u8; 32],
    /// The cryptographic root of the preceding recovery state, if any.
    /// This forces an append-only, tamper-evident lineage structure.
    pub parent_lineage: Option<[u8; 32]>,
    /// The governance epoch at which this lineage state was asserted.
    pub recovery_epoch: u64,
}

impl RecoveryLineage {
    /// Validates the structure of the recovery lineage.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        // Lineage root cannot be empty
        if self.lineage_root == [0; 32] {
            return false;
        }

        // If a parent exists, it cannot be empty
        if let Some(parent) = self.parent_lineage {
            if parent == [0; 32] {
                return false;
            }

            // A lineage cannot reference itself
            if parent == self.lineage_root {
                return false;
            }
        }

        true
    }

    /// Checks if this lineage correctly extends a given parent lineage.
    #[must_use]
    pub fn extends(&self, parent: &RecoveryLineage) -> bool {
        if self.recovery_epoch <= parent.recovery_epoch {
            return false;
        }

        if let Some(expected_parent) = self.parent_lineage {
            expected_parent == parent.lineage_root
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_recovery_lineage() {
        let lineage = RecoveryLineage {
            lineage_root: [1; 32],
            parent_lineage: Some([2; 32]),
            recovery_epoch: 10,
        };
        assert!(lineage.is_valid());
    }

    #[test]
    fn invalid_lineage_zero_root() {
        let lineage = RecoveryLineage {
            lineage_root: [0; 32],
            parent_lineage: None,
            recovery_epoch: 10,
        };
        assert!(!lineage.is_valid());
    }

    #[test]
    fn invalid_lineage_self_reference() {
        let lineage = RecoveryLineage {
            lineage_root: [1; 32],
            parent_lineage: Some([1; 32]),
            recovery_epoch: 10,
        };
        assert!(!lineage.is_valid());
    }

    #[test]
    fn valid_lineage_extension() {
        let parent = RecoveryLineage {
            lineage_root: [1; 32],
            parent_lineage: None,
            recovery_epoch: 1,
        };

        let child = RecoveryLineage {
            lineage_root: [2; 32],
            parent_lineage: Some([1; 32]),
            recovery_epoch: 2,
        };

        assert!(child.extends(&parent));
    }
}
