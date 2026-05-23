//! Full-system consistency validation pass.
//!
//! Detects divergence drift, missing anchors, invalid epoch transitions,
//! and broken quorum lineage by validating the global `AuditTrace` against
//! the current federation state.

use crate::audit_trace::{AuditTrace, TraceEvent};
use crate::digest::TypedDigest;

/// Validates the global consistency of the federation.
pub struct ConsistencyChecker;

impl ConsistencyChecker {
    /// Performs a full-system consistency validation pass.
    ///
    /// Checks that:
    /// 1. The `AuditTrace` is structurally sound and cryptographically verified.
    /// 2. The latest root in the `AuditTrace` matches the expected federation state root.
    /// 3. Epoch transitions are strictly monotonic and unbroken.
    /// 4. No anchors are missing (e.g., `SnapshotSealed` events are properly sequenced).
    ///
    /// # Errors
    /// Returns a `&'static str` detailing the inconsistency if one is found.
    pub fn validate_system_consistency(
        trace: &AuditTrace,
        expected_state_root: &TypedDigest,
    ) -> Result<(), &'static str> {
        // 1. Structural integrity
        if !trace.verify_integrity() {
            return Err("AuditTrace structural integrity verification failed");
        }

        // 2. Divergence drift check
        if &trace.latest_root != expected_state_root {
            return Err("Divergence drift detected: trace latest root does not match the expected state root");
        }

        let mut last_epoch = None;
        let mut has_quorum = false;

        // 3 & 4. Epoch monotonicity and lineage checks
        for event in &trace.events {
            match event {
                TraceEvent::QuorumFormed { epoch, .. } => {
                    if let Some(last) = last_epoch {
                        if *epoch <= last {
                            return Err("Invalid epoch transition: non-monotonic or duplicate epoch detected");
                        }
                    }
                    last_epoch = Some(*epoch);
                    has_quorum = true;
                }
                TraceEvent::SnapshotSealed {
                    finality_state,
                    confirmation_depth,
                    ..
                } => {
                    if !has_quorum {
                        return Err("Broken quorum lineage: SnapshotSealed without a preceding QuorumFormed");
                    }
                    if finality_state == "PendingAnchor" || finality_state == "Included" {
                        return Err("Finalized state assumption rejected: commitment is below StrongFinality");
                    }
                    if finality_state == "WeakFinality" {
                        return Err(
                            "Divergence warning: WeakFinality state used as canonical root",
                        );
                    }
                    if confirmation_depth.unwrap_or(0) == 0 {
                        return Err("Missing explicit confirmation depth validation for closure");
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::DigestAlgorithm;

    #[test]
    fn test_valid_consistency() {
        let genesis = TypedDigest::new(DigestAlgorithm::Sha3_256, [1; 32]);
        let mut trace = AuditTrace::new(genesis);

        trace.append_event(TraceEvent::QuorumFormed {
            epoch: 1,
            quorum_hash: TypedDigest::new(DigestAlgorithm::Sha3_256, [2; 32]),
        });

        trace.append_event(TraceEvent::SnapshotSealed {
            snapshot_id: [3; 32],
            snapshot_hash: TypedDigest::new(DigestAlgorithm::Sha3_256, [4; 32]),
            anchor_height: Some(100),
            confirmation_depth: Some(6),
            finality_state: alloc::string::String::from("IrreversibleFinality"),
        });

        assert_eq!(
            ConsistencyChecker::validate_system_consistency(&trace, &trace.latest_root),
            Ok(())
        );
    }

    #[test]
    fn test_divergence_drift() {
        let genesis = TypedDigest::new(DigestAlgorithm::Sha3_256, [1; 32]);
        let trace = AuditTrace::new(genesis);

        let wrong_root = TypedDigest::new(DigestAlgorithm::Sha3_256, [99; 32]);

        assert_eq!(
            ConsistencyChecker::validate_system_consistency(&trace, &wrong_root),
            Err("Divergence drift detected: trace latest root does not match the expected state root")
        );
    }

    #[test]
    fn test_non_monotonic_epoch() {
        let genesis = TypedDigest::new(DigestAlgorithm::Sha3_256, [1; 32]);
        let mut trace = AuditTrace::new(genesis);

        trace.append_event(TraceEvent::QuorumFormed {
            epoch: 5,
            quorum_hash: TypedDigest::new(DigestAlgorithm::Sha3_256, [2; 32]),
        });

        trace.append_event(TraceEvent::QuorumFormed {
            epoch: 4, // Invalid!
            quorum_hash: TypedDigest::new(DigestAlgorithm::Sha3_256, [3; 32]),
        });

        assert_eq!(
            ConsistencyChecker::validate_system_consistency(&trace, &trace.latest_root),
            Err("Invalid epoch transition: non-monotonic or duplicate epoch detected")
        );
    }

    #[test]
    fn test_broken_quorum_lineage() {
        let genesis = TypedDigest::new(DigestAlgorithm::Sha3_256, [1; 32]);
        let mut trace = AuditTrace::new(genesis);

        // Snapshot sealed without a quorum formed first!
        trace.append_event(TraceEvent::SnapshotSealed {
            snapshot_id: [3; 32],
            snapshot_hash: TypedDigest::new(DigestAlgorithm::Sha3_256, [4; 32]),
            anchor_height: Some(100),
            confirmation_depth: Some(6),
            finality_state: alloc::string::String::from("IrreversibleFinality"),
        });

        assert_eq!(
            ConsistencyChecker::validate_system_consistency(&trace, &trace.latest_root),
            Err("Broken quorum lineage: SnapshotSealed without a preceding QuorumFormed")
        );
    }
}
