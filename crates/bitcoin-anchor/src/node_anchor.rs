//! Sovereign Bitcoin Node Anchoring
//!
//! Provides the data structures and serialization logic required to anchor
//! the continuous attestation state of a sovereign Bitcoin node into the
//! Bitcoin blockchain.

use alloc::vec::Vec;

/// Represents an anchor transaction embedding the node's attestation state.
///
/// This serves as the ultimate on-chain proof of the node's operational integrity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeAttestationAnchor {
    /// The unique attestation session ID being anchored.
    pub session_id: alloc::string::String,
    /// The canonical hash of the `AttestedNodeReport` being anchored.
    pub report_hash: [u8; 32],
    /// The block height at which this anchor was created/intended.
    pub block_height: u64,
}

impl NodeAttestationAnchor {
    /// Serializes the anchor into an `OP_RETURN` compatible payload.
    ///
    /// For Phase 3.0, we just demonstrate a simple binary layout.
    #[must_use]
    pub fn to_op_return_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        // Magic bytes "PQRASCV_NODE" (or similar short prefix)
        payload.extend_from_slice(b"PQNODE");
        payload.extend_from_slice(&self.block_height.to_be_bytes());
        payload.extend_from_slice(&self.report_hash);
        payload
    }
}
