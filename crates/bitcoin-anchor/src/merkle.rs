//! Binary Merkle tree aggregation for attestation quote batches.
//!
//! Implements RFC6962-style prefix-separated hashing to prevent second-preimage
//! attacks (CVE-2012-2459). Odd-level nodes are promoted unchanged rather than
//! duplicated with themselves.
//!
//! # Hash functions
//!
//! - Leaf:     `SHA256d(0x00 || sha3_256_quote_hash)`
//! - Internal: `SHA256d(0x01 || left_hash || right_hash)`

extern crate alloc;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first: [u8; 32] = Sha256::digest(data).into();
    Sha256::digest(first).into()
}

/// RFC6962 leaf hash: `SHA256d(0x00 || data)`
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(data);
    sha256d(&buf)
}

/// RFC6962 internal hash: `SHA256d(0x01 || left || right)`
fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = INTERNAL_PREFIX;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    sha256d(&buf)
}

/// Advances a layer of nodes using RFC6962 rules:
/// pairs are hashed with `internal_hash`; the last odd node is promoted unchanged.
fn next_layer(nodes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(nodes.len().div_ceil(2));
    let mut i = 0;
    while i + 1 < nodes.len() {
        out.push(internal_hash(&nodes[i], &nodes[i + 1]));
        i += 2;
    }
    if nodes.len() % 2 == 1 {
        out.push(nodes[nodes.len() - 1]); // promote last node unchanged
    }
    out
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
    quote_hashes: Vec<[u8; 32]>,
}

impl MerkleAggregator {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    pub fn add_quote_hash(&mut self, hash: [u8; 32]) {
        self.quote_hashes.push(hash);
    }

    #[must_use]
    pub fn len(&self) -> usize { self.quote_hashes.len() }

    #[must_use]
    pub fn is_empty(&self) -> bool { self.quote_hashes.is_empty() }

    #[must_use]
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.quote_hashes.is_empty() { return None; }
        let mut nodes: Vec<[u8; 32]> = self.quote_hashes.iter().map(|h| leaf_hash(h)).collect();
        while nodes.len() > 1 {
            nodes = next_layer(&nodes);
        }
        Some(nodes[0])
    }

    #[must_use]
    pub fn inclusion_proof(&self, index: usize) -> Option<MerkleProofPath> {
        if index >= self.quote_hashes.len() { return None; }

        let mut nodes: Vec<[u8; 32]> = self.quote_hashes.iter().map(|h| leaf_hash(h)).collect();
        let leaf = nodes[index];
        let mut path = Vec::new();
        let mut idx = index;

        while nodes.len() > 1 {
            let is_last_odd = idx == nodes.len() - 1 && nodes.len() % 2 == 1;
            if is_last_odd {
                // Promoted — no sibling at this level
                path.push(ProofStep { sibling_hash: None, is_left: false });
            } else {
                let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
                path.push(ProofStep {
                    sibling_hash: Some(nodes[sibling]),
                    is_left: idx % 2 != 0,
                });
            }
            nodes = next_layer(&nodes);
            idx /= 2;
        }

        Some(MerkleProofPath { leaf_hash: leaf, path, root: nodes[0] })
    }
}

/// A single step in a Merkle inclusion proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProofStep {
    /// Sibling hash. `None` if this node was promoted (no sibling at this level).
    pub sibling_hash: Option<[u8; 32]>,
    /// `true` if the sibling is to the left of the current node.
    pub is_left: bool,
}

/// A Merkle inclusion proof path for a single quote.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MerkleProofPath {
    pub leaf_hash: [u8; 32],
    pub path: Vec<ProofStep>,
    pub root: [u8; 32],
}

impl MerkleProofPath {
    #[must_use]
    pub fn verify(&self) -> bool {
        let mut current = self.leaf_hash;
        for step in &self.path {
            current = match step.sibling_hash {
                None => current, // promoted: no change
                Some(sib) => {
                    if step.is_left {
                        internal_hash(&sib, &current)
                    } else {
                        internal_hash(&current, &sib)
                    }
                }
            };
        }
        current == self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_aggregator_returns_none() {
        assert!(MerkleAggregator::new().root().is_none());
    }

    #[test]
    fn single_quote_root_is_leaf_hash() {
        let mut agg = MerkleAggregator::new();
        let hash = [0x42u8; 32];
        agg.add_quote_hash(hash);
        assert_eq!(agg.root().unwrap(), leaf_hash(&hash));
    }

    #[test]
    fn two_quotes_produce_deterministic_root() {
        let make = || {
            let mut a = MerkleAggregator::new();
            a.add_quote_hash([0x01u8; 32]);
            a.add_quote_hash([0x02u8; 32]);
            a
        };
        assert_eq!(make().root(), make().root());
    }

    #[test]
    fn order_matters_for_root() {
        let mut a1 = MerkleAggregator::new();
        a1.add_quote_hash([0x01u8; 32]);
        a1.add_quote_hash([0x02u8; 32]);
        let mut a2 = MerkleAggregator::new();
        a2.add_quote_hash([0x02u8; 32]);
        a2.add_quote_hash([0x01u8; 32]);
        assert_ne!(a1.root(), a2.root());
    }

    #[test]
    fn inclusion_proof_verifies_all_indices() {
        let mut agg = MerkleAggregator::new();
        for i in 0u8..8 { agg.add_quote_hash([i; 32]); }
        for i in 0..8 {
            let proof = agg.inclusion_proof(i).unwrap();
            assert!(proof.verify(), "proof for index {i} must verify");
            assert_eq!(proof.root, agg.root().unwrap());
        }
    }

    #[test]
    fn inclusion_proof_verifies_odd_count() {
        let mut agg = MerkleAggregator::new();
        for i in 0u8..5 { agg.add_quote_hash([i; 32]); }
        for i in 0..5 {
            let proof = agg.inclusion_proof(i).unwrap();
            assert!(proof.verify(), "odd-tree proof for index {i} must verify");
        }
    }

    #[test]
    fn cve_2012_2459_duplicate_node_attack_rejected() {
        let mut agg3 = MerkleAggregator::new();
        agg3.add_quote_hash([0x01u8; 32]);
        agg3.add_quote_hash([0x02u8; 32]);
        agg3.add_quote_hash([0x03u8; 32]);

        let mut agg4 = MerkleAggregator::new();
        agg4.add_quote_hash([0x01u8; 32]);
        agg4.add_quote_hash([0x02u8; 32]);
        agg4.add_quote_hash([0x03u8; 32]);
        agg4.add_quote_hash([0x03u8; 32]);

        assert_ne!(
            agg3.root(),
            agg4.root(),
            "CVE-2012-2459: 3-leaf and [A,B,C,C] trees must not share a root"
        );
    }

    #[test]
    fn leaf_hash_differs_from_internal_hash_of_same_data() {
        let data = [0x42u8; 32];
        assert_ne!(
            leaf_hash(&data),
            internal_hash(&data, &data),
            "prefix domain separation must produce distinct hashes"
        );
    }

    #[test]
    fn inclusion_proof_out_of_bounds_returns_none() {
        let mut agg = MerkleAggregator::new();
        agg.add_quote_hash([0x01u8; 32]);
        assert!(agg.inclusion_proof(1).is_none());
    }
}
