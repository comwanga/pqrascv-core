//! Binary Merkle tree aggregation for attestation quote batches.
//!
//! Uses double-SHA256 (Bitcoin's native hash) for the Merkle tree so that
//! the root can be verified by any Bitcoin SPV client without additional
//! hash function support.
//!
//! # Leaf hashing
//!
//! Each leaf is `SHA256d(SHA3-256(quote_cbor))` — we first hash the quote
//! with SHA3-256 (the PQ-RASCV canonical hash), then double-SHA256 the result
//! to produce a Bitcoin-compatible leaf hash.
//!
//! # Tree construction
//!
//! Standard Bitcoin Merkle tree: pairs of nodes are hashed together left-to-right.
//! If the number of nodes at a level is odd, the last node is duplicated.

extern crate alloc;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Double-SHA256 as used in Bitcoin.
fn sha256d(data: &[u8]) -> [u8; 32] {
    let first: [u8; 32] = Sha256::digest(data).into();
    Sha256::digest(first).into()
}

/// Aggregates attestation quote hashes into a Merkle tree.
///
/// # Example
///
/// ```rust
/// use pqrascv_bitcoin_anchor::MerkleAggregator;
///
/// let mut agg = MerkleAggregator::new();
/// agg.add_quote_hash([0x01u8; 32]);
/// agg.add_quote_hash([0x02u8; 32]);
/// let root = agg.root().unwrap();
/// ```
#[derive(Default)]
pub struct MerkleAggregator {
    /// SHA3-256 hashes of quote CBOR bytes, one per quote.
    quote_hashes: Vec<[u8; 32]>,
}

impl MerkleAggregator {
    /// Creates an empty aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a SHA3-256 quote hash to the batch.
    pub fn add_quote_hash(&mut self, hash: [u8; 32]) {
        self.quote_hashes.push(hash);
    }

    /// Returns the number of quotes in the current batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.quote_hashes.len()
    }

    /// Returns `true` if no quotes have been added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.quote_hashes.is_empty()
    }

    /// Computes the Merkle root of the current batch.
    ///
    /// Returns `None` if the batch is empty.
    ///
    /// The root is a double-SHA256 Merkle root over Bitcoin-compatible leaf
    /// hashes derived from the SHA3-256 quote hashes.
    #[must_use]
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.quote_hashes.is_empty() {
            return None;
        }

        let mut nodes: Vec<[u8; 32]> = self.quote_hashes.iter().map(|h| sha256d(h)).collect();

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

    /// Generates a Merkle inclusion proof for the quote at `index`.
    ///
    /// Returns `None` if `index` is out of bounds or the batch is empty.
    #[must_use]
    pub fn inclusion_proof(&self, index: usize) -> Option<MerkleProofPath> {
        if index >= self.quote_hashes.len() {
            return None;
        }

        let mut nodes: Vec<[u8; 32]> = self.quote_hashes.iter().map(|h| sha256d(h)).collect();

        let leaf_hash = nodes[index];
        let mut path = Vec::new();
        let mut current_index = index;

        while nodes.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                // Left node — sibling is to the right (or duplicate if last).
                (current_index + 1).min(nodes.len() - 1)
            } else {
                // Right node — sibling is to the left.
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

/// A single step in a Merkle inclusion proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProofStep {
    /// The sibling node's hash.
    pub sibling_hash: [u8; 32],
    /// `true` if the sibling is to the left of the current node.
    pub is_left: bool,
}

/// A Merkle inclusion proof path for a single quote.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MerkleProofPath {
    /// The leaf hash (double-SHA256 of the SHA3-256 quote hash).
    pub leaf_hash: [u8; 32],
    /// Proof steps from leaf to root.
    pub path: Vec<ProofStep>,
    /// The computed Merkle root.
    pub root: [u8; 32],
}

impl MerkleProofPath {
    /// Verifies this proof path, returning `true` if the leaf is in the tree.
    #[must_use]
    pub fn verify(&self) -> bool {
        let mut current = self.leaf_hash;
        for step in &self.path {
            let mut combined = [0u8; 64];
            if step.is_left {
                combined[..32].copy_from_slice(&step.sibling_hash);
                combined[32..].copy_from_slice(&current);
            } else {
                combined[..32].copy_from_slice(&current);
                combined[32..].copy_from_slice(&step.sibling_hash);
            }
            current = sha256d(&combined);
        }
        current == self.root
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_aggregator_returns_none() {
        assert!(MerkleAggregator::new().root().is_none());
    }

    #[test]
    fn single_quote_root_is_sha256d_of_leaf() {
        let mut agg = MerkleAggregator::new();
        let hash = [0x42u8; 32];
        agg.add_quote_hash(hash);
        let root = agg.root().unwrap();
        assert_eq!(root, sha256d(&hash));
    }

    #[test]
    fn two_quotes_produce_deterministic_root() {
        let mut agg1 = MerkleAggregator::new();
        agg1.add_quote_hash([0x01u8; 32]);
        agg1.add_quote_hash([0x02u8; 32]);

        let mut agg2 = MerkleAggregator::new();
        agg2.add_quote_hash([0x01u8; 32]);
        agg2.add_quote_hash([0x02u8; 32]);

        assert_eq!(agg1.root(), agg2.root());
    }

    #[test]
    fn order_matters_for_root() {
        let mut agg1 = MerkleAggregator::new();
        agg1.add_quote_hash([0x01u8; 32]);
        agg1.add_quote_hash([0x02u8; 32]);

        let mut agg2 = MerkleAggregator::new();
        agg2.add_quote_hash([0x02u8; 32]);
        agg2.add_quote_hash([0x01u8; 32]);

        assert_ne!(agg1.root(), agg2.root());
    }

    #[test]
    fn inclusion_proof_verifies() {
        let mut agg = MerkleAggregator::new();
        for i in 0u8..8 {
            agg.add_quote_hash([i; 32]);
        }
        for i in 0..8 {
            let proof = agg.inclusion_proof(i).unwrap();
            assert!(proof.verify(), "proof for index {i} must verify");
            assert_eq!(proof.root, agg.root().unwrap());
        }
    }

    #[test]
    fn inclusion_proof_out_of_bounds_returns_none() {
        let mut agg = MerkleAggregator::new();
        agg.add_quote_hash([0x01u8; 32]);
        assert!(agg.inclusion_proof(1).is_none());
    }
}
