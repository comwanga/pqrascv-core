//! Governance Anchoring
//!
//! Separates governance and lifecycle anchoring semantics from runtime attestation
//! (`IncrementalAnchor`). Provides Bitcoin-auditable immutability for verifier
//! revocations, equivocation proofs, topology changes, and epoch transitions.

use alloc::string::String;
use alloc::vec::Vec;

/// Identifies the specific type of governance event being anchored.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GovernanceEventType {
    /// Anchoring a verifier revocation.
    Revocation { revocation_hash: [u8; 32] },
    /// Anchoring forensic evidence of equivocation.
    Equivocation { evidence_hash: [u8; 32] },
    /// Anchoring a change in the federation topology.
    TopologyTransition { topology_hash: [u8; 32] },
    /// Anchoring a governance epoch boundary.
    EpochTransition { transition_hash: [u8; 32] },
}

/// A dedicated Bitcoin anchor for federation governance events.
///
/// Proves federation authority, revocation lineage, and epoch continuity,
/// leaving runtime sequence integrity to `IncrementalAnchor`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GovernanceAnchor {
    /// The unique identifier of the quorum certificate backing this governance action.
    pub quorum_certificate_id: String,
    /// The specific governance event being immutably anchored.
    pub event_type: GovernanceEventType,
    /// The Unix timestamp when this anchor was generated.
    pub anchored_at: u64,
    /// The active governance epoch at the time of anchoring.
    pub policy_epoch: u64,
    /// The verifier identity that submitted this anchor.
    pub submitter_id: String,
    /// Aggregate quorum signature proving federation consensus for the action.
    #[serde(with = "serde_bytes")]
    pub quorum_signature: Vec<u8>,
}

impl GovernanceAnchor {
    /// Creates a new GovernanceAnchor.
    #[must_use]
    pub fn new(
        quorum_certificate_id: String,
        event_type: GovernanceEventType,
        anchored_at: u64,
        policy_epoch: u64,
        submitter_id: String,
        quorum_signature: Vec<u8>,
    ) -> Self {
        Self {
            quorum_certificate_id,
            event_type,
            anchored_at,
            policy_epoch,
            submitter_id,
            quorum_signature,
        }
    }

    /// Serializes the governance anchor into canonical leaf bytes for inclusion
    /// in the Merkle Aggregator.
    #[must_use]
    pub fn to_leaf_bytes(&self) -> Vec<u8> {
        // Simplified deterministic serialization for the leaf
        let mut buf = Vec::new();
        let cert_id_bytes = self.quorum_certificate_id.as_bytes();
        buf.extend_from_slice(&(cert_id_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(cert_id_bytes);

        match &self.event_type {
            GovernanceEventType::Revocation { revocation_hash } => {
                buf.push(0x01);
                buf.extend_from_slice(revocation_hash);
            }
            GovernanceEventType::Equivocation { evidence_hash } => {
                buf.push(0x02);
                buf.extend_from_slice(evidence_hash);
            }
            GovernanceEventType::TopologyTransition { topology_hash } => {
                buf.push(0x03);
                buf.extend_from_slice(topology_hash);
            }
            GovernanceEventType::EpochTransition { transition_hash } => {
                buf.push(0x04);
                buf.extend_from_slice(transition_hash);
            }
        }

        buf.extend_from_slice(&self.anchored_at.to_be_bytes());
        buf.extend_from_slice(&self.policy_epoch.to_be_bytes());

        let sub_id_bytes = self.submitter_id.as_bytes();
        buf.extend_from_slice(&(sub_id_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(sub_id_bytes);

        buf.extend_from_slice(&(self.quorum_signature.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.quorum_signature);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_anchor_leaf_determinism() {
        let anchor = GovernanceAnchor::new(
            "cert-123".into(),
            GovernanceEventType::Revocation {
                revocation_hash: [0xAA; 32],
            },
            1_700_000_000,
            5,
            "v1".into(),
            vec![0x01, 0x02, 0x03],
        );
        let bytes1 = anchor.to_leaf_bytes();
        let bytes2 = anchor.to_leaf_bytes();
        assert_eq!(bytes1, bytes2);
    }
}
