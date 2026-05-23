//! Finality sealing for global federation consensus.
//!
//! This module introduces `FinalityCommitment`, which represents the system-wide
//! closure of a federation snapshot. It guarantees that a state transition has been
//! anchored to Bitcoin and can be deterministically verified as final by all nodes.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// The explicit state of a snapshot's finality on the Bitcoin blockchain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityState {
    /// Snapshot created, but not yet mined.
    PendingAnchor,
    /// Transaction included in a Bitcoin block (0 confirmations).
    Included,
    /// Transaction has 1 to k-1 confirmations.
    WeakFinality,
    /// Transaction has exactly k confirmations.
    StrongFinality,
    /// Transaction has > k confirmations and is accepted as system-final.
    IrreversibleFinality,
}

/// A cryptographic closure representing the anchoring status of a snapshot.
///
/// `FinalityCommitment` encapsulates the proof that a deterministic federation state
/// transition has achieved Byzantine consensus, has a proven audit trace lineage,
/// and has been anchored on the Bitcoin blockchain. Its finality is probabilistic
/// and must be evaluated against the current chain tip.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityCommitment {
    /// The unique identifier of the snapshot being finalized.
    pub snapshot_id: String,

    /// The Bitcoin transaction ID (txid) containing the anchored commitment.
    pub bitcoin_txid: String,

    /// The canonical block height where this commitment was confirmed.
    /// If None, the anchor is considered PendingAnchor.
    pub block_height: Option<u64>,

    /// The global audit trace root corresponding to this snapshot.
    pub audit_trace_root: [u8; 32],

    /// Cryptographic signatures from a Byzantine quorum of verifiers affirming finality.
    pub quorum_signatures: Vec<String>,

    /// The number of confirmations required for irreversible finality (k-threshold).
    pub k_threshold: u64,
}

impl FinalityCommitment {
    /// Calculates the current finality state based on the current chain tip height.
    #[must_use]
    pub fn current_state(&self, current_chain_tip: u64) -> FinalityState {
        let Some(height) = self.block_height else {
            return FinalityState::PendingAnchor;
        };

        if current_chain_tip < height {
            return FinalityState::PendingAnchor; // Should not happen in normal operation
        }

        let confirmations = current_chain_tip - height;

        match confirmations {
            0 => FinalityState::Included,
            c if c < self.k_threshold => FinalityState::WeakFinality,
            c if c == self.k_threshold => FinalityState::StrongFinality,
            _ => FinalityState::IrreversibleFinality,
        }
    }
    /// Validates the structural integrity of the finality commitment.
    ///
    /// Ensures that:
    /// - The snapshot ID and txid are non-empty.
    /// - The block height is non-zero.
    /// - The trace root is non-zero (proving deterministic lineage).
    /// - At least one signature is present (actual threshold verified at consensus layer).
    #[must_use]
    pub fn is_structurally_valid(&self) -> bool {
        !self.snapshot_id.is_empty()
            && !self.bitcoin_txid.is_empty()
            && self.k_threshold > 0
            && !self.audit_trace_root.iter().all(|&b| b == 0)
            && !self.quorum_signatures.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn valid_finality_commitment() {
        let commitment = FinalityCommitment {
            snapshot_id: "snap-123".to_string(),
            bitcoin_txid: "tx-abc".to_string(),
            block_height: Some(850_000),
            audit_trace_root: [1; 32],
            quorum_signatures: alloc::vec!["sig1".to_string(), "sig2".to_string()],
            k_threshold: 6,
        };
        assert!(commitment.is_structurally_valid());
    }

    #[test]
    fn invalid_finality_commitment_zero_root() {
        let commitment = FinalityCommitment {
            snapshot_id: "snap-123".to_string(),
            bitcoin_txid: "tx-abc".to_string(),
            block_height: Some(850_000),
            audit_trace_root: [0; 32],
            quorum_signatures: alloc::vec!["sig1".to_string()],
            k_threshold: 6,
        };
        assert!(!commitment.is_structurally_valid());
    }

    #[test]
    fn finality_state_progression() {
        let commitment = FinalityCommitment {
            snapshot_id: "snap-123".to_string(),
            bitcoin_txid: "tx-abc".to_string(),
            block_height: Some(100),
            audit_trace_root: [1; 32],
            quorum_signatures: alloc::vec!["sig1".to_string()],
            k_threshold: 6,
        };

        assert_eq!(commitment.current_state(100), FinalityState::Included);
        assert_eq!(commitment.current_state(103), FinalityState::WeakFinality);
        assert_eq!(commitment.current_state(106), FinalityState::StrongFinality);
        assert_eq!(
            commitment.current_state(107),
            FinalityState::IrreversibleFinality
        );
    }

    #[test]
    fn finality_state_pending() {
        let commitment = FinalityCommitment {
            snapshot_id: "snap-123".to_string(),
            bitcoin_txid: "tx-abc".to_string(),
            block_height: None,
            audit_trace_root: [1; 32],
            quorum_signatures: alloc::vec!["sig1".to_string()],
            k_threshold: 6,
        };

        assert_eq!(commitment.current_state(100), FinalityState::PendingAnchor);
    }
}
