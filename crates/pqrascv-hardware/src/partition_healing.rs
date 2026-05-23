use serde::{Deserialize, Serialize};

/// Represents the explicit governance decision made to heal a partition.
/// Silent auto-merging is strictly forbidden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionHealingDecision {
    /// One path was selected as canonical; the other is permanently dropped from consensus.
    Canonicalized,
    /// The conflicting branches are placed in quarantine until further forensic review.
    Quarantined,
    /// The proposed healing state was rejected by governance quorum.
    Rejected,
    /// The divergence is too complex and requires manual sovereign intervention.
    ManualInterventionRequired,
}

/// A report detailing the reconciliation of a detected partition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionHealingReport {
    /// The ID of the partition this report addresses.
    pub partition_id: String,
    /// The explicit governance decision reached.
    pub healing_decision: PartitionHealingDecision,
    /// If canonicalized, the resulting unified root hash of the healed state.
    pub healed_root: Option<[u8; 32]>,
}

impl PartitionHealingReport {
    /// Validates the structural integrity of the healing report.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        // If canonicalized, there MUST be a healed root.
        if self.healing_decision == PartitionHealingDecision::Canonicalized {
            self.healed_root.is_some()
        } else {
            // Otherwise, we shouldn't have a healed root asserted (it's either quarantined or manual)
            self.healed_root.is_none()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healing_report_validates_canonicalization() {
        let valid_report = PartitionHealingReport {
            partition_id: "part-01".into(),
            healing_decision: PartitionHealingDecision::Canonicalized,
            healed_root: Some([1; 32]),
        };
        assert!(valid_report.is_valid());

        let invalid_report = PartitionHealingReport {
            partition_id: "part-02".into(),
            healing_decision: PartitionHealingDecision::Canonicalized,
            healed_root: None,
        };
        assert!(!invalid_report.is_valid());
    }

    #[test]
    fn healing_report_validates_non_canonical() {
        let valid_quarantine = PartitionHealingReport {
            partition_id: "part-03".into(),
            healing_decision: PartitionHealingDecision::Quarantined,
            healed_root: None,
        };
        assert!(valid_quarantine.is_valid());

        let invalid_quarantine = PartitionHealingReport {
            partition_id: "part-04".into(),
            healing_decision: PartitionHealingDecision::Quarantined,
            healed_root: Some([2; 32]), // Should not have a healed root
        };
        assert!(!invalid_quarantine.is_valid());
    }
}
