//! Bitcoin OP_RETURN anchoring for PQ-RASCV attestation audit trails.
//!
//! # Architecture
//!
//! ```text
//! Attestation Quotes (N per batch)
//!       │  SHA3-256(quote_cbor) per quote
//!       ▼
//! MerkleAggregator::add_quote_hash()
//!       │  binary Merkle tree over quote hashes
//!       ▼
//! MerkleAggregator::root() → [u8; 32]
//!       │
//!       ▼
//! AnchorCommitment::new(merkle_root)
//!       │  OP_RETURN: "PQRASCV" || version || merkle_root[0..32]
//!       ▼
//! Bitcoin transaction (broadcast via node RPC or Electrum)
//!       │
//!       ▼
//! InclusionProof { txid, block_height, merkle_path, ... }
//!       │
//!       ▼
//! SpvVerifier::verify(proof, quote_hash) → Ok(BlockHeight)
//! ```
//!
//! # OP_RETURN Format
//!
//! ```text
//! OP_RETURN <magic: 7 bytes "PQRASCV"> <version: 1 byte 0x02> <merkle_root: 32 bytes>
//! Total: 40 bytes (well within the 80-byte OP_RETURN limit)
//! ```
//!
//! # Security Properties
//!
//! - **Immutable**: Bitcoin's proof-of-work makes rewriting history infeasible.
//! - **Decentralized**: No single party controls the audit log.
//! - **Offline-verifiable**: SPV proofs can be verified without a full node.
//! - **Sovereign**: Operators run their own Bitcoin node for full verification.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;

pub mod federation;
pub mod federation_sync_anchor;
pub mod finality_anchor;
pub mod governance_anchor;
pub mod incremental_anchor;
pub mod key_registry_anchor;
pub mod merkle;
pub mod node_anchor;
pub mod proof;
pub mod recovery_anchor;

pub mod timeline;

pub use federation::FederationBatchAggregator;
pub use finality_anchor::FinalityCommitment;
pub use governance_anchor::{GovernanceAnchor, GovernanceEventType};
pub use incremental_anchor::IncrementalAnchor;
pub use key_registry_anchor::{AnchoredVerifierKey, VerifierRegistrationState};
pub use merkle::MerkleAggregator;
pub use node_anchor::NodeAttestationAnchor;
pub use proof::{InclusionProof, SpvVerifier};
pub use recovery_anchor::{RecoveryAnchor, RecoveryAnchorType};
pub use timeline::{TimelineInclusionProof, TimelineMerkleAggregator, TimelineSpvVerifier};

// ── OP_RETURN constants ───────────────────────────────────────────────────

/// Magic prefix identifying a PQ-RASCV OP_RETURN output.
pub const ANCHOR_MAGIC: &[u8; 7] = b"PQRASCV";

/// Protocol version byte embedded in the OP_RETURN payload.
pub const ANCHOR_VERSION: u8 = 0x02;

/// Total OP_RETURN payload size: 7 (magic) + 1 (version) + 32 (full Merkle root) = 40 bytes.
pub const ANCHOR_PAYLOAD_SIZE: usize = 40;

// ── AnchorCommitment ──────────────────────────────────────────────────────

/// An OP_RETURN payload committing to a Merkle root of attestation quote hashes.
///
/// Embed this in a Bitcoin transaction output to create an immutable,
/// decentralized timestamp for a batch of attestation quotes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorCommitment {
    /// The full 32-byte Merkle root (stored for local reference).
    pub merkle_root: [u8; 32],
}

impl AnchorCommitment {
    /// Creates a new anchor commitment from a Merkle root.
    #[must_use]
    pub fn new(merkle_root: [u8; 32]) -> Self {
        Self { merkle_root }
    }

    /// Serializes to the 40-byte OP_RETURN payload.
    ///
    /// Format: `"PQRASCV" || 0x02 || merkle_root[0..32]` (full 32 bytes)
    #[must_use]
    pub fn to_op_return_payload(&self) -> [u8; ANCHOR_PAYLOAD_SIZE] {
        let mut payload = [0u8; ANCHOR_PAYLOAD_SIZE];
        payload[..7].copy_from_slice(ANCHOR_MAGIC);
        payload[7] = ANCHOR_VERSION;
        payload[8..40].copy_from_slice(&self.merkle_root); // full 32 bytes
        payload
    }

    /// Parses an OP_RETURN payload, returning the commitment if valid.
    ///
    /// Returns `None` if the magic or version does not match.
    #[must_use]
    pub fn from_op_return_payload(payload: &[u8]) -> Option<Self> {
        if payload.len() < ANCHOR_PAYLOAD_SIZE {
            return None;
        }
        if &payload[..7] != ANCHOR_MAGIC {
            return None;
        }
        if payload[7] != ANCHOR_VERSION {
            return None;
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&payload[8..40]);
        Some(Self { merkle_root: root })
    }

    /// Returns `true` if this commitment's root exactly matches `full_root`.
    #[must_use]
    pub fn matches_full_root(&self, full_root: &[u8; 32]) -> bool {
        self.merkle_root == *full_root // full 256-bit comparison
    }
}

// ── AnchorRecord ─────────────────────────────────────────────────────────

/// A confirmed Bitcoin anchor record, stored in the local anchor database.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AnchorRecord {
    /// Bitcoin transaction ID (32 bytes, little-endian).
    #[serde(with = "serde_bytes")]
    pub txid: Vec<u8>,
    /// Bitcoin block height at which the transaction was confirmed.
    pub block_height: u32,
    /// Unix seconds of the block timestamp.
    pub block_time: u32,
    /// Full 32-byte Merkle root of the attested quote batch.
    pub merkle_root: [u8; 32],
    /// Number of confirmations at last check.
    pub confirmations: u32,
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_return_roundtrip() {
        let root = [0x42u8; 32];
        let commitment = AnchorCommitment::new(root);
        let payload = commitment.to_op_return_payload();
        assert_eq!(&payload[..7], b"PQRASCV");
        assert_eq!(payload[7], 0x02);
        assert_eq!(&payload[8..40], &root[..]);
    }

    #[test]
    fn from_op_return_rejects_wrong_magic() {
        let mut payload = [0u8; 40];
        payload[..7].copy_from_slice(b"INVALID");
        assert!(AnchorCommitment::from_op_return_payload(&payload).is_none());
    }

    #[test]
    fn from_op_return_rejects_wrong_version() {
        let mut payload = [0u8; 40];
        payload[..7].copy_from_slice(b"PQRASCV");
        payload[7] = 0x01; // wrong version
        assert!(AnchorCommitment::from_op_return_payload(&payload).is_none());
    }

    #[test]
    fn matches_full_root() {
        let root = [0xabu8; 32];
        let commitment = AnchorCommitment::new(root);
        assert!(commitment.matches_full_root(&root));
    }

    #[test]
    fn full_32_byte_root_committed() {
        let root = [0xabu8; 32];
        let commitment = AnchorCommitment::new(root);
        let payload = commitment.to_op_return_payload();
        assert_eq!(&payload[8..40], &root, "all 32 root bytes must appear in OP_RETURN payload");
        assert_eq!(payload.len(), 40);
    }

    #[test]
    fn roots_differing_only_after_byte_20_produce_distinct_commitments() {
        let mut root_a = [0u8; 32];
        let mut root_b = [0u8; 32];
        root_a[..20].fill(0x42);
        root_b[..20].fill(0x42);
        root_b[20] = 0x01; // differs only beyond the old 20-byte boundary
        let c_a = AnchorCommitment::new(root_a);
        let c_b = AnchorCommitment::new(root_b);
        assert_ne!(c_a.to_op_return_payload(), c_b.to_op_return_payload());
        assert!(!c_a.matches_full_root(&root_b));
    }
}
