//! Cross-Federation Reconciliation
//!
//! Provides strictly observational synchronization logic between independent
//! sovereign federations.
//!
//! # Core Invariant
//!
//! Cross-federation reconciliation must NEVER auto-merge conflicting states or
//! automatically resolve quorum disagreements. It exists exclusively to expose
//! divergence, overlap, and conflict topology without compromising sovereign
//! federation independence.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// The observational report of a cross-federation comparison.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossFederationReport {
    /// The unique identifier of the local federation evaluating the comparison.
    pub local_federation_id: String,
    /// The unique identifier of the external federation being evaluated.
    pub external_federation_id: String,
    /// Indicates whether the two federations are fully converged (identical active state hashes).
    pub converged: bool,
    /// Indicates whether explicit conflicts or forks were detected.
    pub conflicts_detected: bool,
    /// A collection of state hashes where the two federations diverged.
    pub divergence_points: Vec<[u8; 32]>,
}

impl CrossFederationReport {
    /// Evaluates the relationship between two federation states and returns an
    /// observational report.
    ///
    /// The state hashes are assumed to be canonical representations of the active
    /// trust states of the respective federations.
    #[must_use]
    pub fn evaluate(
        local_id: String,
        external_id: String,
        local_state_hash: &[u8; 32],
        external_state_hash: &[u8; 32],
        known_divergences: &[[u8; 32]],
    ) -> Self {
        let converged = local_state_hash == external_state_hash;

        let mut divergence_points = Vec::new();
        if !converged {
            // In a full implementation, we'd traverse the timeline DAGs to find the
            // exact fork point. Here we just record the known divergence points or
            // the differing tips.
            divergence_points.extend_from_slice(known_divergences);
            if known_divergences.is_empty() {
                // If no historical traversal is available, the tips themselves are divergent
                divergence_points.push(*local_state_hash);
                divergence_points.push(*external_state_hash);
            }
        }

        Self {
            local_federation_id: local_id,
            external_federation_id: external_id,
            converged,
            conflicts_detected: !converged,
            divergence_points,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convergence_evaluation() {
        let report = CrossFederationReport::evaluate(
            "FedA".into(),
            "FedB".into(),
            &[0xAA; 32],
            &[0xAA; 32],
            &[],
        );

        assert!(report.converged);
        assert!(!report.conflicts_detected);
        assert!(report.divergence_points.is_empty());
    }

    #[test]
    fn divergence_evaluation_no_auto_merge() {
        let report = CrossFederationReport::evaluate(
            "FedA".into(),
            "FedB".into(),
            &[0xAA; 32],
            &[0xBB; 32],
            &[[0xCC; 32]], // A known historical divergence point
        );

        // Crucial invariant: never auto-merges, only exposes conflicts
        assert!(!report.converged);
        assert!(report.conflicts_detected);
        assert_eq!(report.divergence_points.len(), 1);
        assert_eq!(report.divergence_points[0], [0xCC; 32]);
    }
}
