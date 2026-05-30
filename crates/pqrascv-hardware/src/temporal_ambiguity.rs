//! Temporal Ambiguity Evidence
//!
//! Provides the mechanism for verifiers to report observed violations
//! in temporal synchronization, such as skew limit breaches, monotonic
//! logical clock failures, or out-of-order epoch progressions.
//!
//! # Known Limitation — Unverified Observer Signature
//!
//! [`TemporalAmbiguityEvidence::observer_signature`] is present as a field
//! but is **never cryptographically verified** anywhere in this codebase.
//!
//! **Operational consequence:** any process with the ability to construct or
//! deserialize a `TemporalAmbiguityEvidence` value can claim any
//! `observing_verifier_id` and supply an arbitrary (including empty) signature.
//! The evidence is indistinguishable from genuinely observer-signed evidence.
//!
//! This means:
//! - A malicious or compromised component can fabricate temporal violation
//!   reports against any verifier without possessing that verifier's signing key.
//! - Consumers of this struct must not treat the presence of a non-empty
//!   `observer_signature` as proof of authenticity.
//!
//! **Mitigation / hardening path:** callers that use this evidence for
//! governance decisions (e.g., excluding a verifier from a federation) must
//! verify `observer_signature` against the public key of the claimed
//! `observing_verifier_id` before acting on the report. Cryptographic
//! verification is not yet implemented in this module.

use crate::{digest::TypedDigest, federation_time::HybridLogicalClock};
use serde::{Deserialize, Serialize};

/// Cryptographic evidence that a verifier or component has violated
/// temporal convergence rules.
///
/// # Security Note
///
/// The `observer_signature` field is stored but never verified by this crate.
/// See the module-level documentation for the full Known Limitation.
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
    ///
    /// **Not verified by this crate.** Callers that use this evidence for
    /// governance decisions must verify this signature independently.
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

    // Documents the unverified-observer-signature gap: any caller can construct
    // evidence with an arbitrary observer_id and an invalid/empty signature.
    // The struct is accepted without complaint because no verification exists.
    // Consumers must not treat this evidence as authenticated without verifying
    // observer_signature against the claimed observing_verifier_id's public key.
    #[test]
    fn fabricated_evidence_with_empty_signature_is_accepted() {
        let fabricated = TemporalAmbiguityEvidence {
            observing_verifier_id: "trusted-verifier-impersonated".into(),
            violating_verifier_id: "victim".into(),
            violating_clock: HybridLogicalClock {
                logical_counter: 1,
                physical_timestamp: 9999,
                signature: vec![],
            },
            reference_clock: HybridLogicalClock {
                logical_counter: 1,
                physical_timestamp: 1000,
                signature: vec![],
            },
            violation_type: "NonMonotonic".into(),
            event_hash: None,
            observer_signature: vec![], // empty — no signing key required
        };

        // No verification is performed; the struct is valid as-is.
        assert_eq!(fabricated.observer_signature, Vec::<u8>::new());
        assert_eq!(
            fabricated.observing_verifier_id,
            "trusted-verifier-impersonated"
        );
    }
}
