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

/// RFC6962 leaf hash: `SHA256d(0x00 || data)`
fn timeline_leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(0x00u8);
    buf.extend_from_slice(data);
    sha256d(&buf)
}

/// RFC6962 internal hash: `SHA256d(0x01 || left || right)`
fn timeline_internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = 0x01u8;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    sha256d(&buf)
}

/// Advances one tree level: pairs use `timeline_internal_hash`; last odd node
/// is promoted unchanged (no duplication — prevents CVE-2012-2459).
fn timeline_next_layer(nodes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(nodes.len().div_ceil(2));
    let mut i = 0;
    while i + 1 < nodes.len() {
        out.push(timeline_internal_hash(&nodes[i], &nodes[i + 1]));
        i += 2;
    }
    if nodes.len() % 2 == 1 {
        out.push(nodes[nodes.len() - 1]);
    }
    out
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

    /// Computes the RFC6962 Merkle root of the batch.
    #[must_use]
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.event_hashes.is_empty() {
            return None;
        }
        let mut nodes: Vec<[u8; 32]> = self
            .event_hashes
            .iter()
            .map(|h| timeline_leaf_hash(h))
            .collect();
        while nodes.len() > 1 {
            nodes = timeline_next_layer(&nodes);
        }
        Some(nodes[0])
    }

    /// Generates a Merkle inclusion proof for the event at `index`.
    #[must_use]
    pub fn inclusion_proof(&self, index: usize) -> Option<MerkleProofPath> {
        if index >= self.event_hashes.len() {
            return None;
        }

        let mut nodes: Vec<[u8; 32]> = self
            .event_hashes
            .iter()
            .map(|h| timeline_leaf_hash(h))
            .collect();
        let leaf = nodes[index];
        let mut path = Vec::new();
        let mut idx = index;

        while nodes.len() > 1 {
            let is_last_odd = idx == nodes.len() - 1 && nodes.len() % 2 == 1;
            if is_last_odd {
                path.push(ProofStep {
                    sibling_hash: None,
                    is_left: false,
                });
            } else {
                let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
                path.push(ProofStep {
                    sibling_hash: Some(nodes[sibling]),
                    is_left: idx % 2 != 0,
                });
            }
            nodes = timeline_next_layer(&nodes);
            idx /= 2;
        }

        Some(MerkleProofPath {
            leaf_hash: leaf,
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
    pub min_confirmations: u32,
    pub chain_tip_height: u32,
    /// Maximum acceptable target as compact `bits`.
    /// Set to `0` to skip PoW (unit tests with fake headers only).
    /// Bitcoin mainnet genesis: `0x1d00ffff`.
    pub max_target_bits: u32,
}

impl TimelineSpvVerifier {
    /// Creates a new timeline SPV verifier.
    #[must_use]
    pub fn new(min_confirmations: u32, chain_tip_height: u32) -> Self {
        Self {
            min_confirmations,
            chain_tip_height,
            max_target_bits: 0x1d00_ffff,
        }
    }

    /// Override the maximum target bits (lower = more secure).
    #[must_use]
    pub fn with_max_target_bits(mut self, bits: u32) -> Self {
        self.max_target_bits = bits;
        self
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
        // Proof-of-work validation (skip only when max_target_bits == 0, for tests)
        if self.max_target_bits != 0
            && !crate::proof::validate_proof_of_work(&proof.block_header, self.max_target_bits)
        {
            return Err(SpvError::InsufficientProofOfWork);
        }

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

        let expected_leaf = timeline_leaf_hash(event_hash);

        if proof.event_merkle_path.leaf_hash != expected_leaf {
            return Err(SpvError::QuoteNotInAnchor); // Reused error type to preserve errors interface
        }

        if !proof.event_merkle_path.verify() {
            return Err(SpvError::QuoteNotInAnchor);
        }

        Ok(proof.block_height)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_pow_helpers_are_accessible_from_timeline() {
        // bits_to_target: mainnet genesis bits → 256-byte target (non-None)
        assert!(crate::proof::bits_to_target(0x1d00ffff).is_some());
        // validate_proof_of_work: zero-length header → false
        assert!(!crate::proof::validate_proof_of_work(&[], 0x1d00ffff));
    }

    #[test]
    fn cve_2012_2459_duplicate_node_attack_rejected() {
        let mut agg3 = TimelineMerkleAggregator::new();
        agg3.add_event_hash([0x01u8; 32]);
        agg3.add_event_hash([0x02u8; 32]);
        agg3.add_event_hash([0x03u8; 32]);

        let mut agg4 = TimelineMerkleAggregator::new();
        agg4.add_event_hash([0x01u8; 32]);
        agg4.add_event_hash([0x02u8; 32]);
        agg4.add_event_hash([0x03u8; 32]);
        agg4.add_event_hash([0x03u8; 32]);

        assert_ne!(
            agg3.root(),
            agg4.root(),
            "CVE-2012-2459: 3-event and [A,B,C,C] trees must not share a root"
        );
    }

    #[test]
    fn leaf_prefix_differs_from_internal_prefix() {
        let data = [0x42u8; 32];
        assert_ne!(
            timeline_leaf_hash(&data),
            timeline_internal_hash(&data, &data),
            "RFC6962 prefixes must produce distinct leaf vs internal hashes"
        );
    }

    #[test]
    fn inclusion_proof_verifies_all_indices_after_domain_sep() {
        let mut agg = TimelineMerkleAggregator::new();
        for i in 0u8..8 {
            agg.add_event_hash([i; 32]);
        }
        for i in 0..8 {
            let proof = agg.inclusion_proof(i).unwrap();
            assert!(proof.verify(), "proof for index {i} must verify");
            assert_eq!(proof.root, agg.root().unwrap());
        }
    }

    #[test]
    fn inclusion_proof_odd_count_verifies() {
        let mut agg = TimelineMerkleAggregator::new();
        for i in 0u8..5 {
            agg.add_event_hash([i; 32]);
        }
        for i in 0..5 {
            let proof = agg.inclusion_proof(i).unwrap();
            assert!(proof.verify(), "odd-tree proof for index {i} must verify");
        }
    }

    #[test]
    fn timeline_spv_verifier_rejects_zero_work_header() {
        let event_hash = [0xA1u8; 32];
        let mut agg = TimelineMerkleAggregator::new();
        agg.add_event_hash(event_hash);
        let timeline_root = agg.root().unwrap();
        let event_proof = agg.inclusion_proof(0).unwrap();

        let mut header = vec![0u8; 80];
        header[36..68].copy_from_slice(&timeline_root);
        // bits field at bytes 72-75 is zero — invalid PoW

        let tx_path = crate::proof::TxMerklePath {
            txid: timeline_root,
            steps: alloc::vec![],
            block_merkle_root: timeline_root,
        };
        let proof = TimelineInclusionProof {
            block_height: 800_000,
            block_header: header,
            tx_merkle_path: tx_path,
            timeline_merkle_root: timeline_root,
            event_merkle_path: event_proof,
        };

        let verifier = TimelineSpvVerifier::new(1, 800_001);
        assert!(
            matches!(
                verifier.verify(&proof, &event_hash),
                Err(SpvError::InsufficientProofOfWork)
            ),
            "zero-work header must be rejected by TimelineSpvVerifier"
        );
    }

    #[test]
    fn timeline_spv_verifier_accepts_proof_with_pow_skipped() {
        let event_hash = [0xB2u8; 32];
        let mut agg = TimelineMerkleAggregator::new();
        agg.add_event_hash(event_hash);
        let timeline_root = agg.root().unwrap();
        let event_proof = agg.inclusion_proof(0).unwrap();

        let mut header = vec![0u8; 80];
        header[36..68].copy_from_slice(&timeline_root);

        let tx_path = crate::proof::TxMerklePath {
            txid: timeline_root,
            steps: alloc::vec![],
            block_merkle_root: timeline_root,
        };
        let proof = TimelineInclusionProof {
            block_height: 800_000,
            block_header: header,
            tx_merkle_path: tx_path,
            timeline_merkle_root: timeline_root,
            event_merkle_path: event_proof,
        };

        let verifier = TimelineSpvVerifier::new(1, 800_000).with_max_target_bits(0);
        assert!(
            verifier.verify(&proof, &event_hash).is_ok(),
            "PoW-skipped verifier must accept a valid proof"
        );
    }
}
