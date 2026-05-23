use serde::{Deserialize, Serialize};

/// Represents explicit evidence of a Byzantine partition or federation divergence.
///
/// Partitions must never merge silently. This evidence structure preserves
/// conflicting histories while bounding memory usage by referencing deeper
/// divergence history through `lineage_reference_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionEvidence {
    /// A unique identifier for this partition event.
    pub partition_id: String,
    /// The immediate fork roots representing the split in consensus or state.
    pub conflicting_roots: alloc::vec::Vec<[u8; 32]>,
    /// The governance epoch in which the divergence was detected.
    pub divergence_epoch: u64,
    /// A cryptographic reference to the deeper historical lineage of this divergence.
    /// This ensures unbounded historical events aren't held in-memory, while remaining verifiable.
    pub lineage_reference_root: [u8; 32],
}

impl PartitionEvidence {
    /// Creates a new `PartitionEvidence` requiring explicit tracking of conflicting state roots.
    #[must_use]
    pub fn new(
        partition_id: String,
        conflicting_roots: alloc::vec::Vec<[u8; 32]>,
        divergence_epoch: u64,
        lineage_reference_root: [u8; 32],
    ) -> Self {
        Self {
            partition_id,
            conflicting_roots,
            divergence_epoch,
            lineage_reference_root,
        }
    }

    /// Validates that the evidence explicitly identifies a conflict.
    /// A valid partition MUST contain at least two conflicting roots.
    #[must_use]
    pub fn is_valid_conflict(&self) -> bool {
        // A conflict requires at least two divergent paths
        if self.conflicting_roots.len() < 2 {
            return false;
        }

        // The roots must be distinct
        for i in 0..self.conflicting_roots.len() {
            for j in (i + 1)..self.conflicting_roots.len() {
                if self.conflicting_roots[i] == self.conflicting_roots[j] {
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_evidence_requires_two_roots() {
        let ev = PartitionEvidence::new("part-01".into(), vec![[1; 32]], 5, [9; 32]);
        assert!(!ev.is_valid_conflict());
    }

    #[test]
    fn partition_evidence_rejects_identical_roots() {
        let ev = PartitionEvidence::new("part-01".into(), vec![[1; 32], [1; 32]], 5, [9; 32]);
        assert!(!ev.is_valid_conflict());
    }

    #[test]
    fn partition_evidence_accepts_valid_divergence() {
        let ev = PartitionEvidence::new("part-01".into(), vec![[1; 32], [2; 32]], 5, [9; 32]);
        assert!(ev.is_valid_conflict());
    }
}
