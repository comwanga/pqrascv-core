//! Bitcoin SPV validation for continuous attestation timeline events.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::merkle::{MerkleProofPath, ProofStep};
use crate::proof::{SpvError, TxMerklePath};

/// Double-SHA256 as used in Bitcoin.
fn sha256d(data: &[u8]) -> [u8; 32] {
    let first: [u8; 32] = Sha256::digest(data).into();
    Sha256::digest(first).into()
}

/// Aggregates timeline event hashes into a Merkle tree for Bitcoin anchoring.
#[derive(Default)]
pub struct TimelineMerkleAggregator {
    /// Canonical hashes of transparency events in this batch.
    event_hashes: Vec<[u8; 32]>,
}

impl TimelineMerkleAggregator {
    /// Creates an empty timeline event aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a timeline event hash to the current batch.
    pub fn add_event_hash(&mut self, hash: [u8; 32]) {
        self.event_hashes.push(hash);
    }

    /// Returns the number of events in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.event_hashes.len()
    }

    /// Returns `true` if the batch contains no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.event_hashes.is_empty()
    }

    /// Computes the double-SHA256 Merkle root of the batch.
    #[must_use]
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.event_hashes.is_empty() {
            return None;
        }

        // Convert events to Bitcoin-compatible leaf hashes: SHA256d(event_hash)
        let mut nodes: Vec<[u8; 32]> = self.event_hashes.iter().map(|h| sha256d(h)).collect();

        while nodes.len() > 1 {
            let mut next_level = Vec::with_capacity(nodes.len().div_ceil(2));
            let mut i = 0;
            while i < nodes.len() {
                let left = nodes[i];
                let right = if i + 1 < nodes.len() {
                    nodes[i + 1]
                } else {
                    nodes[i]
                };
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&left);
                combined[32..].copy_from_slice(&right);
                next_level.push(sha256d(&combined));
                i += 2;
            }
            nodes = next_level;
        }

        Some(nodes[0])
    }

    /// Generates a Merkle inclusion proof for the event at `index`.
    #[must_use]
    pub fn inclusion_proof(&self, index: usize) -> Option<MerkleProofPath> {
        if index >= self.event_hashes.len() {
            return None;
        }

        let mut nodes: Vec<[u8; 32]> = self.event_hashes.iter().map(|h| sha256d(h)).collect();
        let leaf_hash = nodes[index];
        let mut path = Vec::new();
        let mut current_index = index;

        while nodes.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                (current_index + 1).min(nodes.len() - 1)
            } else {
                current_index - 1
            };

            path.push(ProofStep {
                sibling_hash: nodes[sibling_index],
                is_left: current_index % 2 != 0,
            });

            let mut next_level = Vec::with_capacity(nodes.len().div_ceil(2));
            let mut i = 0;
            while i < nodes.len() {
                let left = nodes[i];
                let right = if i + 1 < nodes.len() {
                    nodes[i + 1]
                } else {
                    nodes[i]
                };
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&left);
                combined[32..].copy_from_slice(&right);
                next_level.push(sha256d(&combined));
                i += 2;
            }
            current_index /= 2;
            nodes = next_level;
        }

        Some(MerkleProofPath {
            leaf_hash,
            path,
            root: nodes[0],
        })
    }
}

/// A complete inclusion proof linking a timeline event to a Bitcoin block.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TimelineInclusionProof {
    /// Bitcoin block height.
    pub block_height: u32,
    /// Bitcoin block header (80 bytes).
    #[serde(with = "serde_bytes")]
    pub block_header: Vec<u8>,
    /// Merkle proof path from the anchor transaction to the block's Merkle root.
    pub tx_merkle_path: TxMerklePath,
    /// The full timeline Merkle root committed in the anchor OP_RETURN.
    pub timeline_merkle_root: [u8; 32],
    /// Merkle proof path from the event hash to the timeline Merkle root.
    pub event_merkle_path: MerkleProofPath,
}

/// Verifies Bitcoin SPV inclusion proofs for timeline anchors.
pub struct TimelineSpvVerifier {
    /// Minimum number of block confirmations.
    pub min_confirmations: u32,
    /// Current Bitcoin chain tip height.
    pub chain_tip_height: u32,
}

impl TimelineSpvVerifier {
    /// Creates a new timeline SPV verifier.
    #[must_use]
    pub fn new(min_confirmations: u32, chain_tip_height: u32) -> Self {
        Self {
            min_confirmations,
            chain_tip_height,
        }
    }

    /// Verifies that a timeline event hash is anchored in Bitcoin.
    ///
    /// # Errors
    ///
    /// Returns `SpvError` if verification fails.
    pub fn verify(
        &self,
        proof: &TimelineInclusionProof,
        event_hash: &[u8; 32],
    ) -> Result<u32, SpvError> {
        let confirmations = self
            .chain_tip_height
            .saturating_sub(proof.block_height)
            .saturating_add(1);
        if confirmations < self.min_confirmations {
            return Err(SpvError::InsufficientConfirmations {
                got: confirmations,
                required: self.min_confirmations,
            });
        }

        if proof.block_header.len() < 80 {
            return Err(SpvError::InvalidBlockHeader);
        }
        let mut header_merkle_root = [0u8; 32];
        header_merkle_root.copy_from_slice(&proof.block_header[36..68]);

        if header_merkle_root != proof.tx_merkle_path.block_merkle_root {
            return Err(SpvError::MerkleRootMismatch);
        }

        if !proof.tx_merkle_path.verify() {
            return Err(SpvError::TxNotInBlock);
        }

        if proof.event_merkle_path.root != proof.timeline_merkle_root {
            return Err(SpvError::MerkleRootMismatch);
        }

        let expected_leaf = {
            let first: [u8; 32] = Sha256::digest(event_hash).into();
            let second: [u8; 32] = Sha256::digest(first).into();
            second
        };

        if proof.event_merkle_path.leaf_hash != expected_leaf {
            return Err(SpvError::QuoteNotInAnchor); // Reused error type to preserve errors interface
        }

        if !proof.event_merkle_path.verify() {
            return Err(SpvError::QuoteNotInAnchor);
        }

        Ok(proof.block_height)
    }
}
