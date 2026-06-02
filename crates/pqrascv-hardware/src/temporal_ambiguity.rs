//! Temporal Ambiguity Evidence
//!
//! Provides the mechanism for verifiers to report observed violations
//! in temporal synchronization, such as skew limit breaches, monotonic
//! logical clock failures, or out-of-order epoch progressions.
//!
//! # Observer Signature Verification
//!
//! [`TemporalAmbiguityEvidence::observer_signature`] is an ML-DSA-65 signature
//! by the observing verifier over the canonical
//! [`observer_payload`](crate::federation_auth::observer_payload), which binds
//! every field of the report (observer id, accused id, both clocks, violation
//! type, event hash). Before acting on a report, callers **must** authenticate
//! it with [`TemporalAmbiguityEvidence::is_authentic`] (federation lookup) or
//! [`TemporalAmbiguityEvidence::verify_observer_signature`] (explicit key).
//!
//! **Why this matters:** without verification, any process able to construct a
//! `TemporalAmbiguityEvidence` value could claim any `observing_verifier_id`
//! and fabricate temporal-violation reports against any verifier — a forged
//! report could exclude an honest verifier from the federation. Signature
//! verification binds the report to a key the claimed observer actually holds,
//! and tampering with any field invalidates the signature.

use alloc::vec::Vec;

use crate::federation_auth::{observer_payload, verify_ml_dsa, CTX_OBSERVER};
use crate::verifier_federation::VerifierFederation;
use crate::{digest::TypedDigest, federation_time::HybridLogicalClock};
use serde::{Deserialize, Serialize};

/// Cryptographic evidence that a verifier or component has violated
/// temporal convergence rules.
///
/// # Security Note
///
/// The `observer_signature` field must be authenticated before the evidence is
/// acted upon — see [`Self::is_authentic`]. The module-level documentation
/// describes the canonical payload and threat model.
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
    /// ML-DSA-65 signature of the observer over the canonical
    /// [`observer_payload`](crate::federation_auth::observer_payload).
    ///
    /// Authenticate via [`Self::is_authentic`] before acting on the evidence.
    #[serde(with = "serde_bytes")]
    pub observer_signature: Vec<u8>,
}

impl TemporalAmbiguityEvidence {
    /// The canonical bytes the observer signs — every report field bound
    /// together so tampering with any one invalidates the signature.
    #[must_use]
    fn signing_payload(&self) -> Vec<u8> {
        observer_payload(
            &self.observing_verifier_id,
            &self.violating_verifier_id,
            &self.violating_clock,
            &self.reference_clock,
            &self.violation_type,
            self.event_hash.as_ref(),
        )
    }

    /// Verifies `observer_signature` against an explicitly supplied observer
    /// public key. Returns `false` for any mismatch or malformed input.
    #[must_use]
    pub fn verify_observer_signature(&self, observer_public_key: &[u8]) -> bool {
        verify_ml_dsa(
            &self.signing_payload(),
            CTX_OBSERVER,
            observer_public_key,
            &self.observer_signature,
        )
    }

    /// Authenticates the evidence against a federation: the claimed
    /// `observing_verifier_id` must be a member, and its key must verify the
    /// signature. Returns `false` if the observer is not a member or the
    /// signature does not verify — fail-closed against fabricated reports.
    #[must_use]
    pub fn is_authentic(&self, federation: &VerifierFederation) -> bool {
        federation
            .members
            .iter()
            .find(|m| m.verifier_id == self.observing_verifier_id)
            .is_some_and(|m| self.verify_observer_signature(&m.public_key))
    }
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

    use crate::federation_auth::{sign_ml_dsa, test_keys::keypair, CTX_OBSERVER};
    use crate::verifier_federation::{QuorumPolicy, VerifierFederation};
    use crate::verifier_identity::VerifierIdentity;

    fn clock(counter: u64, ts: u64) -> HybridLogicalClock {
        HybridLogicalClock {
            logical_counter: counter,
            physical_timestamp: ts,
            signature: vec![],
        }
    }

    fn evidence(observer: &str, signature: Vec<u8>) -> TemporalAmbiguityEvidence {
        TemporalAmbiguityEvidence {
            observing_verifier_id: observer.into(),
            violating_verifier_id: "victim".into(),
            violating_clock: clock(1, 9999),
            reference_clock: clock(1, 1000),
            violation_type: "NonMonotonic".into(),
            event_hash: None,
            observer_signature: signature,
        }
    }

    fn one_member_federation(observer: &str, vk: Vec<u8>) -> VerifierFederation {
        VerifierFederation {
            federation_id: "fed".into(),
            members: vec![VerifierIdentity {
                verifier_id: observer.into(),
                organization: "Org".into(),
                public_key: vk,
                ml_kem_public_key: None,
                capabilities: vec![],
            }],
            quorum_policy: QuorumPolicy::Majority,
        }
    }

    /// Signs `ev` as its claimed observer using `seed`.
    fn sign_as_observer(ev: &TemporalAmbiguityEvidence, seed: &[u8; 32]) -> Vec<u8> {
        sign_ml_dsa(&ev.signing_payload(), CTX_OBSERVER, seed).unwrap()
    }

    // A genuinely observer-signed report authenticates against the federation.
    #[test]
    fn authentic_evidence_verifies() {
        let (seed, vk) = keypair();
        let mut ev = evidence("v-observer", vec![]);
        ev.observer_signature = sign_as_observer(&ev, &seed);
        let fed = one_member_federation("v-observer", vk);
        assert!(ev.is_authentic(&fed));
    }

    // FIXED: a fabricated report with an empty signature is now REJECTED. An
    // attacker can no longer impersonate an observer to file false reports.
    #[test]
    fn fabricated_evidence_with_empty_signature_is_rejected() {
        let (_seed, vk) = keypair();
        let fabricated = evidence("v-observer", vec![]); // empty signature
        let fed = one_member_federation("v-observer", vk);
        assert!(!fabricated.is_authentic(&fed));
    }

    // A report signed by the wrong key (an impersonator) does not authenticate
    // against the claimed observer's federation key.
    #[test]
    fn wrong_key_signature_is_rejected() {
        let (attacker_seed, _attacker_vk) = keypair();
        let (_seed, observer_vk) = keypair();
        let mut ev = evidence("v-observer", vec![]);
        ev.observer_signature = sign_as_observer(&ev, &attacker_seed); // wrong key
        let fed = one_member_federation("v-observer", observer_vk);
        assert!(!ev.is_authentic(&fed));
    }

    // Tampering with any bound field after signing invalidates the signature.
    #[test]
    fn tampered_field_invalidates_signature() {
        let (seed, vk) = keypair();
        let mut ev = evidence("v-observer", vec![]);
        ev.observer_signature = sign_as_observer(&ev, &seed);
        // Flip the accused verifier after signing.
        ev.violating_verifier_id = "different-victim".into();
        assert!(!ev.verify_observer_signature(&vk));
    }

    // An observer that is not a federation member is rejected even with an
    // otherwise valid self-signature.
    #[test]
    fn non_member_observer_is_rejected() {
        let (seed, vk) = keypair();
        let mut ev = evidence("ghost", vec![]);
        ev.observer_signature = sign_as_observer(&ev, &seed);
        // Federation knows "v-observer", not "ghost".
        let fed = one_member_federation("v-observer", vk);
        assert!(!ev.is_authentic(&fed));
    }
}
