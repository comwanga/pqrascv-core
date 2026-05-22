//! Federation Event Merkle Aggregator
//!
//! Provides a double-SHA256 Merkle tree aggregator for batching federation
//! audit events (governance actions, quorum decisions, policy epoch hashes)
//! into a single root that can be committed to Bitcoin via
//! [`crate::AnchorCommitment`].
//!
//! # Bitcoin is AUDIT ONLY
//!
//! This module does NOT make any trust decisions or influence policy
//! evaluation. Its sole purpose is to produce Merkle roots suitable for
//! Bitcoin `OP_RETURN` anchoring, providing cryptographic proof of
//! event existence at a point in time.
//!
//! # Hash Function
//!
//! Uses double-SHA256 (Bitcoin's native hash) for leaf and node hashing,
//! consistent with [`crate::merkle::MerkleAggregator`].

extern crate alloc;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

// ── FederationBatchAggregator ─────────────────────────────────────────────

/// Merkle aggregator for federation audit events.
///
/// Accumulates event hashes from governance actions, quorum decisions, and
/// policy epoch commitments, then produces a single 32-byte Merkle root for
/// Bitcoin anchoring.
///
/// # Usage
///
/// ```
/// use pqrascv_bitcoin_anchor::federation::FederationBatchAggregator;
///
/// let mut agg = FederationBatchAggregator::new();
/// agg.add_governance_event([0x01u8; 32]);
/// agg.add_quorum_decision([0x02u8; 32]);
/// agg.add_policy_epoch(7, [0x03u8; 32]);
/// let root = agg.batch_root();
/// assert!(root.is_some());
/// ```
#[derive(Debug, Default)]
pub struct FederationBatchAggregator {
    leaves: Vec<[u8; 32]>,
}

impl FederationBatchAggregator {
    /// Creates an empty aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of events added so far.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.leaves.len()
    }

    /// Adds the hash of a governance event to the batch.
    ///
    /// The hash must be a SHA3-256 digest of the serialized
    /// [`pqrascv_hardware::governance::GovernanceRecord`] (or equivalent).
    pub fn add_governance_event(&mut self, event_hash: [u8; 32]) {
        self.leaves.push(Self::domain_tag(b"gov:", event_hash));
    }

    /// Adds the hash of a quorum decision to the batch.
    ///
    /// The hash must be a SHA3-256 digest of the serialized
    /// [`pqrascv_hardware::distributed_consensus::ConsensusEvaluation`].
    pub fn add_quorum_decision(&mut self, decision_hash: [u8; 32]) {
        self.leaves.push(Self::domain_tag(b"qrm:", decision_hash));
    }

    /// Adds a policy epoch commitment to the batch.
    ///
    /// `epoch_id` is encoded into the leaf domain tag to bind the epoch
    /// identifier to the hash and prevent cross-epoch substitution.
    pub fn add_policy_epoch(&mut self, epoch_id: u64, epoch_hash: [u8; 32]) {
        let tag = *b"epc:";
        let id_bytes = epoch_id.to_be_bytes();
        // Construct a domain-separated leaf: SHA256(b"epc:" || epoch_id_be || epoch_hash)
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(id_bytes);
        hasher.update(epoch_hash);
        let first: [u8; 32] = hasher.finalize().into();
        // Double-SHA256
        let second: [u8; 32] = Sha256::digest(first).into();
        self.leaves.push(second);
    }

    /// Computes the double-SHA256 Merkle root over all accumulated leaves.
    ///
    /// Returns `None` if no events have been added.
    #[must_use]
    pub fn batch_root(&self) -> Option<[u8; 32]> {
        if self.leaves.is_empty() {
            return None;
        }
        Some(Self::merkle_root(&self.leaves))
    }

    /// Domain-separates a leaf hash with a 4-byte tag and double-SHA256es it.
    fn domain_tag(tag: &[u8; 4], hash: [u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(hash);
        let first: [u8; 32] = hasher.finalize().into();
        Sha256::digest(first).into()
    }

    /// Computes a binary Merkle root using double-SHA256 (Bitcoin-compatible).
    ///
    /// Odd-length layers duplicate the last node (Bitcoin convention).
    fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let mut current: Vec<[u8; 32]> = leaves.to_vec();
        while current.len() > 1 {
            let mut next = Vec::new();
            let mut i = 0;
            while i < current.len() {
                let left = current[i];
                let right = if i + 1 < current.len() {
                    current[i + 1]
                } else {
                    current[i] // duplicate last node for odd-length layers
                };
                let combined = Self::hash_pair(left, right);
                next.push(combined);
                i += 2;
            }
            current = next;
        }
        current[0]
    }

    /// Double-SHA256 of the concatenation of two 32-byte nodes.
    fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        let first: [u8; 32] = hasher.finalize().into();
        Sha256::digest(first).into()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_aggregator_returns_none() {
        let agg = FederationBatchAggregator::new();
        assert!(agg.batch_root().is_none());
    }

    #[test]
    fn single_governance_event_produces_root() {
        let mut agg = FederationBatchAggregator::new();
        agg.add_governance_event([0x01u8; 32]);
        assert!(agg.batch_root().is_some());
    }

    #[test]
    fn deterministic_root() {
        let mut agg1 = FederationBatchAggregator::new();
        agg1.add_governance_event([0x01u8; 32]);
        agg1.add_quorum_decision([0x02u8; 32]);
        agg1.add_policy_epoch(5, [0x03u8; 32]);

        let mut agg2 = FederationBatchAggregator::new();
        agg2.add_governance_event([0x01u8; 32]);
        agg2.add_quorum_decision([0x02u8; 32]);
        agg2.add_policy_epoch(5, [0x03u8; 32]);

        assert_eq!(agg1.batch_root(), agg2.batch_root());
    }

    #[test]
    fn different_inputs_produce_different_roots() {
        let mut agg1 = FederationBatchAggregator::new();
        agg1.add_governance_event([0x01u8; 32]);

        let mut agg2 = FederationBatchAggregator::new();
        agg2.add_governance_event([0x02u8; 32]);

        assert_ne!(agg1.batch_root(), agg2.batch_root());
    }

    #[test]
    fn policy_epoch_domain_separated_by_id() {
        let mut agg1 = FederationBatchAggregator::new();
        agg1.add_policy_epoch(1, [0xAAu8; 32]);

        let mut agg2 = FederationBatchAggregator::new();
        agg2.add_policy_epoch(2, [0xAAu8; 32]); // same hash, different epoch

        assert_ne!(
            agg1.batch_root(),
            agg2.batch_root(),
            "different epoch IDs must produce different roots"
        );
    }

    #[test]
    fn event_count_tracks_additions() {
        let mut agg = FederationBatchAggregator::new();
        assert_eq!(agg.event_count(), 0);
        agg.add_governance_event([0x01u8; 32]);
        agg.add_quorum_decision([0x02u8; 32]);
        agg.add_policy_epoch(3, [0x03u8; 32]);
        assert_eq!(agg.event_count(), 3);
    }
}
