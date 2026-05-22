//! Incremental Bitcoin Anchoring
//!
//! Extends the base anchoring semantics to support continuous runtime streams.
//! Instead of anchoring large snapshot batches, this anchors compact
//! `checkpoint_root` and `stream_root` summaries, allowing a node's entire
//! operational history to be efficiently verified via SPV inclusion proofs.
//!
//! # Consensus Binding (Issue 6 Fix)
//!
//! An anchor that records only mathematical roots (hashes) proves "truth of data"
//! — that specific bytes existed — but NOT "truth of agreement" — that a verifier
//! quorum approved those bytes as valid.
//!
//! `IncrementalAnchor` now binds:
//!
//! - `verifier_id`: identifies the verifier originating this anchor.
//! - `policy_epoch`: the federated policy epoch that was active when the anchor
//!   was approved, binding the anchor to the governance state that validated it.
//! - `quorum_signature`: an ML-DSA (or equivalent) aggregate signature from the
//!   verifier quorum over the canonical anchor bytes. This proves federation
//!   agreement, not just data existence.
//!
//! Together these transform the Bitcoin anchor from a data timestamping mechanism
//! into a provable consensus commitment.

use alloc::string::String;
use alloc::vec::Vec;

/// A compact, consensus-bound Bitcoin anchor representing a specific point in a
/// node's continuous runtime integrity stream.
///
/// The `quorum_signature` binds this anchor to the approval of the verifier
/// federation at `policy_epoch`, preventing unilateral anchoring.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IncrementalAnchor {
    /// The canonical rolling hash of the last compacted checkpoint.
    pub checkpoint_root: [u8; 32],
    /// The canonical rolling hash of the active, uncompacted stream.
    pub stream_root: [u8; 32],
    /// The Unix timestamp when this anchor was generated for inclusion.
    pub anchored_at: u64,
    /// The verifier identity that originated this anchor submission.
    pub verifier_id: String,
    /// The federated policy epoch active at time of anchor creation.
    /// Binds the anchor to the governance state that validated the stream.
    pub policy_epoch: u64,
    /// ML-DSA (or equivalent) aggregate quorum signature over the canonical
    /// anchor bytes. Proves federation agreement rather than unilateral anchoring.
    /// In a full implementation: ML-DSA.Sign(anchor_bytes, quorum_keys).
    #[serde(with = "serde_bytes")]
    pub quorum_signature: Vec<u8>,
}

impl IncrementalAnchor {
    /// Creates a new consensus-bound incremental anchor.
    ///
    /// # Parameters
    ///
    /// - `checkpoint_root`: rolling hash of the last compacted checkpoint.
    /// - `stream_root`: rolling hash of the active un-compacted stream.
    /// - `anchored_at`: Unix timestamp of anchor creation.
    /// - `verifier_id`: originating verifier identifier.
    /// - `policy_epoch`: federated policy epoch at time of anchor.
    /// - `quorum_signature`: ML-DSA aggregate quorum signature bytes.
    #[must_use]
    pub fn new(
        checkpoint_root: [u8; 32],
        stream_root: [u8; 32],
        anchored_at: u64,
        verifier_id: String,
        policy_epoch: u64,
        quorum_signature: Vec<u8>,
    ) -> Self {
        Self {
            checkpoint_root,
            stream_root,
            anchored_at,
            verifier_id,
            policy_epoch,
            quorum_signature,
        }
    }

    /// Serializes the anchor into a deterministic byte array suitable for
    /// aggregation into the standard `MerkleAggregator`.
    ///
    /// The canonical byte layout is:
    /// ```text
    /// [checkpoint_root: 32] || [stream_root: 32] || [anchored_at: 8 BE]
    ///   || [policy_epoch: 8 BE] || [verifier_id len: 4 BE] || [verifier_id bytes]
    ///   || [quorum_signature len: 4 BE] || [quorum_signature bytes]
    /// ```
    #[must_use]
    pub fn to_leaf_bytes(&self) -> Vec<u8> {
        let vid_bytes = self.verifier_id.as_bytes();
        let mut buf = Vec::with_capacity(
            32 + 32 + 8 + 8 + 4 + vid_bytes.len() + 4 + self.quorum_signature.len(),
        );
        buf.extend_from_slice(&self.checkpoint_root);
        buf.extend_from_slice(&self.stream_root);
        buf.extend_from_slice(&self.anchored_at.to_be_bytes());
        buf.extend_from_slice(&self.policy_epoch.to_be_bytes());
        buf.extend_from_slice(&(vid_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(vid_bytes);
        buf.extend_from_slice(&(self.quorum_signature.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.quorum_signature);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn anchor_to_leaf_bytes_is_deterministic() {
        let anchor = IncrementalAnchor::new(
            [0xAB; 32],
            [0xCD; 32],
            1_700_000_000,
            "verifier-alpha".into(),
            7,
            vec![0x01, 0x02, 0x03],
        );
        let bytes1 = anchor.to_leaf_bytes();
        let bytes2 = anchor.to_leaf_bytes();
        assert_eq!(bytes1, bytes2);

        // Ensure quorum_signature is included in the leaf
        assert!(bytes1.windows(3).any(|w| w == [0x01, 0x02, 0x03]));
    }

    #[test]
    fn anchor_leaf_bytes_differ_by_policy_epoch() {
        let anchor_a =
            IncrementalAnchor::new([0xAB; 32], [0xCD; 32], 1_000, "v1".into(), 1, vec![0xFF]);
        let anchor_b =
            IncrementalAnchor::new([0xAB; 32], [0xCD; 32], 1_000, "v1".into(), 2, vec![0xFF]);
        assert_ne!(anchor_a.to_leaf_bytes(), anchor_b.to_leaf_bytes());
    }

    #[test]
    fn anchor_leaf_bytes_differ_by_verifier_id() {
        let anchor_a = IncrementalAnchor::new(
            [0xAB; 32],
            [0xCD; 32],
            1_000,
            "verifier-A".into(),
            1,
            vec![0xFF],
        );
        let anchor_b = IncrementalAnchor::new(
            [0xAB; 32],
            [0xCD; 32],
            1_000,
            "verifier-B".into(),
            1,
            vec![0xFF],
        );
        assert_ne!(anchor_a.to_leaf_bytes(), anchor_b.to_leaf_bytes());
    }
}
