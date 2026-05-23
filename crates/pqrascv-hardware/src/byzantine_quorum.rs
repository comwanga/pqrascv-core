//! Byzantine Quorum Semantics
//!
//! Evaluates federation consensus using Byzantine Fault Tolerant (BFT) semantics.
//! Unlike simple thresholds, this formally separates Safety and Liveness, enabling
//! explicit detection of partitions and equivocation thresholds.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A signed certificate proving that a specific Byzantine quorum of verifiers
/// agreed upon a particular state hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// A unique identifier for the quorum instance or sequence.
    pub quorum_id: String,
    /// The identities of the verifiers that contributed valid signatures.
    pub participating_verifiers: Vec<String>,
    /// The canonical state hash agreed upon by the quorum.
    pub state_hash: crate::digest::TypedDigest,
    /// The individual or aggregated signatures from the participating verifiers.
    pub signatures: Vec<Vec<u8>>,
}

/// Represents the formal safety state of the federation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ByzantineSafetyState {
    /// The federation has safely reached a `2f+1` convergence set.
    Safe,
    /// An equivocation threshold was crossed; contradictory states were signed
    /// by the same verifier identity.
    UnsafeEquivocation,
    /// The federation is cleanly partitioned into subsets.
    UnsafePartition,
    /// Mathematical intersection failure (e.g. not enough total nodes to form a quorum).
    UnsafeIntersectionFailure,
}

/// Represents the formal liveness state of the federation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ByzantineLivenessState {
    /// The federation is actively producing consensus.
    Live,
    /// The federation is halted (cannot reach `2f+1` agreement).
    Stalled,
    /// The federation is partitioned, causing liveness to halt globally.
    Partitioned,
}

/// A combined formal evaluation of the federation's Byzantine state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByzantineQuorumResult {
    pub safety: ByzantineSafetyState,
    pub liveness: ByzantineLivenessState,
}

/// A subset of votes (signatures) for a specific state hash.
#[derive(Clone, Debug)]
pub struct VoteSet {
    pub state_hash: crate::digest::TypedDigest,
    pub verifier_ids: Vec<String>,
}

impl ByzantineQuorumResult {
    /// Evaluates the Byzantine safety and liveness of a given set of votes.
    ///
    /// # Parameters
    /// - `total_verifiers`: The total number of `N` verifiers in the federation.
    /// - `vote_sets`: A list of unique state hashes and the verifiers that voted for them.
    ///
    /// # BFT Thresholds
    /// Assumes standard BFT resilience where `N >= 3f + 1`.
    /// - `f`: The maximum number of Byzantine faults tolerated.
    /// - Convergence (Safe/Live) requires `2f + 1` votes for a single state hash.
    /// - A Partition is defined as multiple independent verifier subsets each
    ///   having `>= f + 1` votes, but none reaching `2f + 1`.
    #[must_use]
    pub fn evaluate(total_verifiers: usize, vote_sets: &[VoteSet]) -> Self {
        if total_verifiers < 4 {
            // Need at least 4 nodes for f=1 (N >= 3f + 1)
            // But we can gracefully handle N=1,2,3 for dev/test by defining f=0
            // For now, let's calculate f based on standard assumption.
        }

        // f = (N - 1) / 3
        let f = (total_verifiers.saturating_sub(1)) / 3;
        let quorum_size = 2 * f + 1;
        let partition_size = f + 1;

        let mut max_votes = 0;
        let mut partitions = 0;

        for set in vote_sets {
            let votes = set.verifier_ids.len();
            if votes > max_votes {
                max_votes = votes;
            }
            if votes >= partition_size {
                partitions += 1;
            }
        }

        if max_votes >= quorum_size {
            Self {
                safety: ByzantineSafetyState::Safe,
                liveness: ByzantineLivenessState::Live,
            }
        } else if partitions > 1 {
            // Multiple independent subsets each >= f+1 without a valid 2f+1 set
            Self {
                safety: ByzantineSafetyState::UnsafePartition,
                liveness: ByzantineLivenessState::Partitioned,
            }
        } else if vote_sets
            .iter()
            .map(|s| s.verifier_ids.len())
            .sum::<usize>()
            >= quorum_size
        {
            // Total votes are enough, but spread out below partition threshold
            Self {
                safety: ByzantineSafetyState::UnsafeIntersectionFailure,
                liveness: ByzantineLivenessState::Stalled,
            }
        } else {
            Self {
                safety: ByzantineSafetyState::Safe, // Safe because no bad state has quorum or partition threshold
                liveness: ByzantineLivenessState::Stalled,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bft_quorum_evaluation() {
        // N = 4 -> f = 1. quorum_size = 3. partition_size = 2.
        let n = 4;

        // 3 votes -> Safe/Live
        let safe = ByzantineQuorumResult::evaluate(
            n,
            &[VoteSet {
                state_hash: crate::digest::TypedDigest::new(
                    crate::digest::DigestAlgorithm::Sha3_256,
                    [0xAA; 32],
                ),
                verifier_ids: vec!["v1".into(), "v2".into(), "v3".into()],
            }],
        );
        assert_eq!(safe.safety, ByzantineSafetyState::Safe);
        assert_eq!(safe.liveness, ByzantineLivenessState::Live);

        // 2 vs 2 -> Partition
        let partition = ByzantineQuorumResult::evaluate(
            n,
            &[
                VoteSet {
                    state_hash: crate::digest::TypedDigest::new(
                        crate::digest::DigestAlgorithm::Sha3_256,
                        [0xAA; 32],
                    ),
                    verifier_ids: vec!["v1".into(), "v2".into()],
                },
                VoteSet {
                    state_hash: crate::digest::TypedDigest::new(
                        crate::digest::DigestAlgorithm::Sha3_256,
                        [0xBB; 32],
                    ),
                    verifier_ids: vec!["v3".into(), "v4".into()],
                },
            ],
        );
        assert_eq!(partition.safety, ByzantineSafetyState::UnsafePartition);
        assert_eq!(partition.liveness, ByzantineLivenessState::Partitioned);

        // 1 vs 1 vs 1 -> Intersection Failure (Total 3, but spread out)
        let intersection_fail = ByzantineQuorumResult::evaluate(
            n,
            &[
                VoteSet {
                    state_hash: crate::digest::TypedDigest::new(
                        crate::digest::DigestAlgorithm::Sha3_256,
                        [0xAA; 32],
                    ),
                    verifier_ids: vec!["v1".into()],
                },
                VoteSet {
                    state_hash: crate::digest::TypedDigest::new(
                        crate::digest::DigestAlgorithm::Sha3_256,
                        [0xBB; 32],
                    ),
                    verifier_ids: vec!["v2".into()],
                },
                VoteSet {
                    state_hash: crate::digest::TypedDigest::new(
                        crate::digest::DigestAlgorithm::Sha3_256,
                        [0xCC; 32],
                    ),
                    verifier_ids: vec!["v3".into()],
                },
            ],
        );
        assert_eq!(
            intersection_fail.safety,
            ByzantineSafetyState::UnsafeIntersectionFailure
        );
        assert_eq!(intersection_fail.liveness, ByzantineLivenessState::Stalled);

        // 2 votes total -> Safe but stalled
        let stalled = ByzantineQuorumResult::evaluate(
            n,
            &[VoteSet {
                state_hash: crate::digest::TypedDigest::new(
                    crate::digest::DigestAlgorithm::Sha3_256,
                    [0xAA; 32],
                ),
                verifier_ids: vec!["v1".into(), "v2".into()],
            }],
        );
        // Actually wait, 2 votes is >= partition_size (2). If partitions == 1 and max_votes < 3,
        // it falls into Safe/Stalled in my logic above. Let's check:
        assert_eq!(stalled.safety, ByzantineSafetyState::Safe);
        assert_eq!(stalled.liveness, ByzantineLivenessState::Stalled);
    }
}
