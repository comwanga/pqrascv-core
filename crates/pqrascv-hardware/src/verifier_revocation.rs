//! Verifier Revocation Semantics
//!
//! Provides deterministic revocation of compromised or malicious verifier
//! identities across the federation. Revocations are epoch-bound and sequence-bound
//! to prevent timeline reconciliation ambiguity.
//!
//! # Sequence Binding
//!
//! A revocation specifies an `effective_from_sequence`. Signatures and quorum
//! contributions from the revoked verifier *after* this sequence are cryptographically
//! valid but governance-invalid. Signatures *before* this sequence remain valid to
//! preserve historical forensic auditability and prevent rollback attacks.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// The documented reason for revoking a verifier's authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    Equivocation,
    KeyCompromise,
    GovernanceViolation,
    TopologyViolation,
    ByzantineBehavior,
    ExpiredAuthority,
    ManualEmergencyRevocation,
}

/// A formal, signed notification revoking a verifier's authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierRevocation {
    /// The unique identifier of the verifier being revoked.
    pub verifier_id: String,
    /// The governance epoch in which this revocation was issued.
    pub revocation_epoch: u64,
    /// The exact sequence number at which this revocation takes effect.
    /// Contributions after this sequence are invalid.
    pub effective_from_sequence: u64,
    /// The identities of the verifiers/authorities that signed this revocation.
    pub revoked_by: Vec<String>,
    /// The reason for revocation.
    pub reason: RevocationReason,
    /// The Unix timestamp when this revocation was generated.
    pub timestamp: u64,
    /// The aggregate quorum signature authorizing the revocation.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// A compact proof of a revocation for efficient transport or anchoring.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationProof {
    /// The canonical hash of the `VerifierRevocation` struct.
    pub revocation_hash: crate::digest::TypedDigest,
    /// The aggregate federation signature authorizing the revocation.
    #[serde(with = "serde_bytes")]
    pub federation_signature: Vec<u8>,
}

impl VerifierRevocation {
    /// Evaluates if a given sequence number is bound by this revocation.
    ///
    /// # Returns
    /// - `true` if the sequence is >= `effective_from_sequence` (the verifier was revoked).
    /// - `false` if the sequence is < `effective_from_sequence` (historical signatures are preserved).
    #[must_use]
    pub fn is_revoked_at_sequence(&self, sequence: u64) -> bool {
        sequence >= self.effective_from_sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_preserves_historical_auditability() {
        let revocation = VerifierRevocation {
            verifier_id: "verifier-bad".into(),
            revocation_epoch: 5,
            effective_from_sequence: 100,
            revoked_by: vec!["authority-1".into()],
            reason: RevocationReason::ByzantineBehavior,
            timestamp: 1_700_000_000,
            signature: vec![0xff],
        };

        // Sequence before revocation is NOT revoked (history preserved)
        assert!(!revocation.is_revoked_at_sequence(99));

        // Sequence at or after revocation IS revoked
        assert!(revocation.is_revoked_at_sequence(100));
        assert!(revocation.is_revoked_at_sequence(101));
    }
}
