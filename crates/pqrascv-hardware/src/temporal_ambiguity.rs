//! Temporal Ambiguity Evidence
//!
//! Provides the mechanism for verifiers to report observed violations
//! in temporal synchronization, such as skew limit breaches, monotonic
//! logical clock failures, or out-of-order epoch progressions.

use crate::{digest::TypedDigest, federation_time::HybridLogicalClock};
use serde::{Deserialize, Serialize};

/// Cryptographic evidence that a verifier or component has violated
/// temporal convergence rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalAmbiguityEvidence {
    /// The ID of the verifier observing the violation.
    pub observing_verifier_id: String,
    /// The ID of the verifier that committed the violation.
    pub violating_verifier_id: String,
    /// The clock reading that triggered the violation.
    pub violating_clock: HybridLogicalClock,
    /// The reference clock against which the violation was measured.
    pub reference_clock: HybridLogicalClock,
    /// A description of the violation type (e.g., "`ExceedsSkew`", "`NonMonotonic`").
    pub violation_type: String,
    /// Optional hash of the associated event/state.
    pub event_hash: Option<TypedDigest>,
    /// Cryptographic signature of the observer over this evidence.
    #[serde(with = "serde_bytes")]
    pub observer_signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporal_ambiguity_evidence_serialize() {
        let ev = TemporalAmbiguityEvidence {
            observing_verifier_id: "v1".into(),
            violating_verifier_id: "v2".into(),
            violating_clock: HybridLogicalClock {
                logical_counter: 10,
                physical_timestamp: 2000,
                signature: vec![0x11],
            },
            reference_clock: HybridLogicalClock {
                logical_counter: 10,
                physical_timestamp: 1000,
                signature: vec![0x22],
            },
            violation_type: "ExceedsSkew".into(),
            event_hash: None,
            observer_signature: vec![0xFF],
        };

        // Assert it roundtrips
        let mut bytes = alloc::vec::Vec::new();
        ciborium::into_writer(&ev, &mut bytes).unwrap();
        let decoded: TemporalAmbiguityEvidence = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(ev, decoded);
    }
}
