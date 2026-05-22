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
//!       │  OP_RETURN: "PQRASCV" || version || merkle_root[0..20]
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
//! OP_RETURN <magic: 7 bytes "PQRASCV"> <version: 1 byte 0x02> <merkle_root: 20 bytes>
//! Total: 28 bytes (well within the 80-byte OP_RETURN limit)
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
pub mod merkle;
pub mod node_anchor;
pub mod proof;
pub mod timeline;

pub use federation::FederationBatchAggregator;
pub use merkle::MerkleAggregator;
pub use node_anchor::NodeAttestationAnchor;
pub use proof::{InclusionProof, SpvVerifier};
pub use timeline::{TimelineInclusionProof, TimelineMerkleAggregator, TimelineSpvVerifier};

// ── OP_RETURN constants ───────────────────────────────────────────────────

/// Magic prefix identifying a PQ-RASCV OP_RETURN output.
pub const ANCHOR_MAGIC: &[u8; 7] = b"PQRASCV";

/// Protocol version byte embedded in the OP_RETURN payload.
pub const ANCHOR_VERSION: u8 = 0x02;

/// Total OP_RETURN payload size: 7 (magic) + 1 (version) + 20 (root prefix).
pub const ANCHOR_PAYLOAD_SIZE: usize = 28;

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

    /// Serializes to the 28-byte OP_RETURN payload.
    ///
    /// Format: `"PQRASCV" || 0x02 || merkle_root[0..20]`
    ///
    /// We truncate the Merkle root to 20 bytes to stay well within the
    /// 80-byte OP_RETURN limit while leaving room for future extensions.
    /// The full root is stored off-chain in the anchor database.
    #[must_use]
    pub fn to_op_return_payload(&self) -> [u8; ANCHOR_PAYLOAD_SIZE] {
        let mut payload = [0u8; ANCHOR_PAYLOAD_SIZE];
        payload[..7].copy_from_slice(ANCHOR_MAGIC);
        payload[7] = ANCHOR_VERSION;
        payload[8..28].copy_from_slice(&self.merkle_root[..20]);
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
        // We only have the first 20 bytes of the root in the OP_RETURN.
        // The full root must be looked up from the local anchor database.
        let mut partial_root = [0u8; 32];
        partial_root[..20].copy_from_slice(&payload[8..28]);
        Some(Self {
            merkle_root: partial_root,
        })
    }

    /// Returns `true` if the first 20 bytes of `full_root` match this commitment.
    ///
    /// Used to correlate an OP_RETURN commitment with a locally stored full root.
    #[must_use]
    pub fn matches_full_root(&self, full_root: &[u8; 32]) -> bool {
        self.merkle_root[..20] == full_root[..20]
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
        assert_eq!(&payload[8..28], &root[..20]);
    }

    #[test]
    fn from_op_return_rejects_wrong_magic() {
        let mut payload = [0u8; 28];
        payload[..7].copy_from_slice(b"INVALID");
        assert!(AnchorCommitment::from_op_return_payload(&payload).is_none());
    }

    #[test]
    fn from_op_return_rejects_wrong_version() {
        let mut payload = [0u8; 28];
        payload[..7].copy_from_slice(b"PQRASCV");
        payload[7] = 0x01; // wrong version
        assert!(AnchorCommitment::from_op_return_payload(&payload).is_none());
    }

    #[test]
    fn matches_full_root() {
        let root = [0xabu8; 32];
        let commitment = AnchorCommitment::new({
            let mut partial = [0u8; 32];
            partial[..20].copy_from_slice(&root[..20]);
            partial
        });
        assert!(commitment.matches_full_root(&root));
    }
}
