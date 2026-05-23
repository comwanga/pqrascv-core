//! Anti-Equivocation Detection
//!
//! Provides deterministic detection and proof of verifier equivocation.
//! Equivocation occurs when a verifier signs two differing trust states
//! for the same sequence number within the same consensus scope.
//!
//! # Canonical Contradiction Semantics
//!
//! A contradiction is formally defined as:
//! 1. Same verifier identity
//! 2. Same monotonic sequence number
//! 3. Differing canonical `state_hash`
//!
//! We explicitly *do not* transmit full divergent histories, as this would
//! cause transport amplification and complicate deterministic verification.
//! Two minimal signed commitments are sufficient to generate irrefutable
//! evidence of Byzantine behavior.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A minimal, standalone commitment by a verifier to a specific state hash
/// at a specific sequence. Used as the primitive for equivocation detection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedStateCommitment {
    /// The identity of the verifier making the commitment.
    pub verifier_id: String,
    /// The consensus scope (e.g. federation zone or policy domain).
    pub consensus_scope: String,
    /// The canonical sequence number of the commitment.
    pub sequence: u64,
    /// The canonical hash of the state being committed to.
    pub state_hash: crate::digest::TypedDigest,
    /// The verifier's signature over `(verifier_id || sequence || state_hash)`.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Durable forensic evidence that a verifier has equivocated.
/// Contains exactly two conflicting commitments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    /// The identity of the equivocating verifier.
    pub verifier_id: String,
    /// The sequence number at which the equivocation occurred.
    pub sequence: u64,
    /// The two conflicting commitments that prove equivocation.
    pub conflicting_commitments: [SignedStateCommitment; 2],
    /// The Unix timestamp when this equivocation was detected/assembled.
    pub detected_at: u64,
}

impl EquivocationEvidence {
    /// Evaluates if two commitments constitute valid equivocation evidence.
    ///
    /// # Errors
    /// Returns an error if the commitments do not form a canonical contradiction.
    pub fn try_from_commitments(
        a: SignedStateCommitment,
        b: SignedStateCommitment,
        detected_at: u64,
    ) -> Result<Self, &'static str> {
        if a.verifier_id != b.verifier_id {
            return Err("commitments belong to different verifiers");
        }
        if a.consensus_scope != b.consensus_scope {
            return Err("commitments belong to different consensus scopes");
        }
        if a.sequence != b.sequence {
            return Err("commitments are for different sequences");
        }
        if a.state_hash == b.state_hash {
            return Err("commitments have identical state hashes; no equivocation");
        }

        let verifier_id = a.verifier_id.clone();
        let sequence = a.sequence;

        Ok(Self {
            verifier_id,
            sequence,
            // To ensure canonical ordering of evidence, we sort the commitments
            // by their state hashes.
            conflicting_commitments: if a.state_hash < b.state_hash {
                [a, b]
            } else {
                [b, a]
            },
            detected_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_commitment(vid: &str, scope: &str, seq: u64, hash: u8) -> SignedStateCommitment {
        SignedStateCommitment {
            verifier_id: vid.into(),
            consensus_scope: scope.into(),
            sequence: seq,
            state_hash: crate::digest::TypedDigest::new(
                crate::digest::DigestAlgorithm::Sha3_256,
                [hash; 32],
            ),
            signature: vec![0xff],
        }
    }

    #[test]
    fn valid_equivocation_evidence() {
        let a = mock_commitment("v1", "global", 100, 0xAA);
        let b = mock_commitment("v1", "global", 100, 0xBB);

        let ev = EquivocationEvidence::try_from_commitments(a.clone(), b.clone(), 12345).unwrap();
        assert_eq!(ev.verifier_id, "v1");
        assert_eq!(ev.sequence, 100);
        assert_eq!(ev.conflicting_commitments[0].state_hash.value[0], 0xAA);
        assert_eq!(ev.conflicting_commitments[1].state_hash.value[0], 0xBB);
    }

    #[test]
    fn invalid_equivocation_different_verifiers() {
        let a = mock_commitment("v1", "global", 100, 0xAA);
        let b = mock_commitment("v2", "global", 100, 0xBB);
        assert!(EquivocationEvidence::try_from_commitments(a, b, 1).is_err());
    }

    #[test]
    fn invalid_equivocation_different_sequences() {
        let a = mock_commitment("v1", "global", 100, 0xAA);
        let b = mock_commitment("v1", "global", 101, 0xBB);
        assert!(EquivocationEvidence::try_from_commitments(a, b, 1).is_err());
    }

    #[test]
    fn invalid_equivocation_identical_hashes() {
        let a = mock_commitment("v1", "global", 100, 0xAA);
        let b = mock_commitment("v1", "global", 100, 0xAA);
        assert!(EquivocationEvidence::try_from_commitments(a, b, 1).is_err());
    }
}
