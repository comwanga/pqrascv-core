//! Byzantine Quorum Semantics
//!
//! Evaluates federation consensus using Byzantine Fault Tolerant (BFT) semantics.
//! Unlike simple thresholds, this formally separates Safety and Liveness, enabling
//! explicit detection of partitions and equivocation thresholds.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::federation_auth::{quorum_payload, verify_ml_dsa, CTX_QUORUM};
use crate::verifier_federation::VerifierFederation;

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
    /// The individual signatures from the participating verifiers, positionally
    /// aligned with `participating_verifiers`. Each is an ML-DSA-65 signature
    /// over the canonical [`quorum_payload`] for `(quorum_id, state_hash, verifier_id)`.
    pub signatures: Vec<Vec<u8>>,
}

impl QuorumCertificate {
    /// Returns the set of participating verifiers whose signature authentically
    /// covers this certificate's `(quorum_id, state_hash)` under their
    /// federation `public_key`.
    ///
    /// Verifiers that are not federation members, that carry an invalid or
    /// missing signature, or that are listed without a positionally-aligned
    /// signature are excluded. Each member is returned at most once. This is the
    /// authentication gate that must run before a certificate's voters are fed
    /// into [`ByzantineQuorumResult::evaluate`] — unauthenticated voters never
    /// contribute to safety or liveness.
    #[must_use]
    pub fn verified_voters(&self, federation: &VerifierFederation) -> BTreeSet<String> {
        let member_keys: BTreeMap<&str, &[u8]> = federation
            .members
            .iter()
            .map(|m| (m.verifier_id.as_str(), m.public_key.as_slice()))
            .collect();
        let mut verified = BTreeSet::new();
        for (verifier_id, signature) in self
            .participating_verifiers
            .iter()
            .zip(self.signatures.iter())
        {
            if let Some(public_key) = member_keys.get(verifier_id.as_str()) {
                let payload = quorum_payload(&self.quorum_id, &self.state_hash, verifier_id);
                if verify_ml_dsa(&payload, CTX_QUORUM, public_key, signature) {
                    verified.insert(verifier_id.clone());
                }
            }
        }
        verified
    }

    /// Builds a [`VoteSet`] for this certificate's state hash containing **only**
    /// the cryptographically verified voters. Use this — not the raw
    /// `participating_verifiers` — when feeding [`ByzantineQuorumResult::evaluate`].
    #[must_use]
    pub fn authenticated_vote_set(&self, federation: &VerifierFederation) -> VoteSet {
        VoteSet {
            state_hash: self.state_hash,
            verifier_ids: self.verified_voters(federation).into_iter().collect(),
        }
    }
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

        // Detect equivocation: any verifier ID appearing in 2+ VoteSets.
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for set in vote_sets {
            let deduped: BTreeSet<&str> = set.verifier_ids.iter().map(String::as_str).collect();
            for id in &deduped {
                if !seen.insert(id) {
                    return Self {
                        safety: ByzantineSafetyState::UnsafeEquivocation,
                        liveness: ByzantineLivenessState::Stalled,
                    };
                }
            }
        }

        let mut max_votes = 0;
        let mut partitions = 0;
        let mut total_votes = 0;

        for set in vote_sets {
            // Deduplicate within each VoteSet to prevent vote-count inflation.
            let votes = set
                .verifier_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                .len();
            if votes > max_votes {
                max_votes = votes;
            }
            if votes >= partition_size {
                partitions += 1;
            }
            total_votes += votes;
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
        } else if total_votes >= quorum_size {
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

    // ── Adversarial tests ────────────────────────────────────────────────────

    #[test]
    fn vote_count_inflation_via_duplicate_ids_is_rejected() {
        // N=7 → f=2, quorum_size=5, partition_size=3.
        // Only 2 distinct verifiers (v1, v2) — below quorum and partition threshold.
        // Duplicating IDs must NOT inflate the count above quorum_size.
        let result = ByzantineQuorumResult::evaluate(
            7,
            &[VoteSet {
                state_hash: crate::digest::TypedDigest::new(
                    crate::digest::DigestAlgorithm::Sha3_256,
                    [0xAA; 32],
                ),
                verifier_ids: vec![
                    "v1".into(),
                    "v1".into(),
                    "v1".into(),
                    "v2".into(),
                    "v2".into(),
                ],
            }],
        );
        // After deduplication: 2 distinct verifiers < quorum_size(5) and < partition_size(3)
        assert_eq!(result.safety, ByzantineSafetyState::Safe);
        assert_eq!(result.liveness, ByzantineLivenessState::Stalled);
    }

    #[test]
    fn equivocation_detected_across_vote_sets() {
        // N=4 → f=1, quorum_size=3, partition_size=2.
        // "v1" signs both 0xAA and 0xBB — equivocation must be flagged.
        let result = ByzantineQuorumResult::evaluate(
            4,
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
                    verifier_ids: vec!["v1".into(), "v3".into()],
                },
            ],
        );
        assert_eq!(result.safety, ByzantineSafetyState::UnsafeEquivocation);
        assert_eq!(result.liveness, ByzantineLivenessState::Stalled);
    }

    // With N < 4, f = 0, so quorum_size = 1 and partition_size = 1.
    // Any single verifier vote satisfies quorum. This is correct for f=0
    // federations but means small federations offer no Byzantine tolerance.
    #[test]
    fn small_federation_n3_has_f0_quorum_is_one() {
        // N=3 → f=(3-1)/3=0, quorum_size=1, partition_size=1.
        // A single vote is sufficient for Safe/Live.
        let result = ByzantineQuorumResult::evaluate(
            3,
            &[VoteSet {
                state_hash: crate::digest::TypedDigest::new(
                    crate::digest::DigestAlgorithm::Sha3_256,
                    [0xAA; 32],
                ),
                verifier_ids: vec!["v1".into()],
            }],
        );
        assert_eq!(result.safety, ByzantineSafetyState::Safe);
        assert_eq!(result.liveness, ByzantineLivenessState::Live);
    }

    // N=0 (no verifiers) is an edge case: f=0, quorum_size=1. No vote set
    // can satisfy quorum_size of 1, and there are zero partitions, so the
    // evaluator falls into the last branch and returns Safe/Stalled.
    #[test]
    fn zero_verifiers_returns_safe_stalled() {
        let result = ByzantineQuorumResult::evaluate(0, &[]);
        assert_eq!(result.safety, ByzantineSafetyState::Safe);
        assert_eq!(result.liveness, ByzantineLivenessState::Stalled);
    }

    // ── Signature authentication tests ───────────────────────────────────────

    use crate::federation_auth::{sign_ml_dsa, test_keys::keypair, CTX_QUORUM};
    use crate::verifier_federation::{QuorumPolicy, VerifierFederation};
    use crate::verifier_identity::VerifierIdentity;

    fn hash(b: u8) -> crate::digest::TypedDigest {
        crate::digest::TypedDigest::new(crate::digest::DigestAlgorithm::Sha3_256, [b; 32])
    }

    fn signed_federation(n: usize) -> (VerifierFederation, Vec<[u8; 32]>) {
        let mut members = Vec::new();
        let mut seeds = Vec::new();
        for i in 0..n {
            let (seed, vk) = keypair();
            members.push(VerifierIdentity {
                verifier_id: alloc::format!("v{i}"),
                organization: "Org".into(),
                public_key: vk,
                ml_kem_public_key: None,
                capabilities: alloc::vec![],
            });
            seeds.push(seed);
        }
        let fed = VerifierFederation {
            federation_id: "fed".into(),
            members,
            quorum_policy: QuorumPolicy::Majority,
        };
        (fed, seeds)
    }

    fn sign_quorum(
        seed: &[u8; 32],
        quorum_id: &str,
        sh: &crate::digest::TypedDigest,
        vid: &str,
    ) -> Vec<u8> {
        sign_ml_dsa(&quorum_payload(quorum_id, sh, vid), CTX_QUORUM, seed).unwrap()
    }

    // Valid certificate: all three member signatures verify, so verified_voters
    // yields the full set and the authenticated vote set reaches BFT quorum
    // (N=4 ⇒ f=1, quorum_size=3 ⇒ Safe/Live).
    #[test]
    fn valid_quorum_signatures_are_counted() {
        let (fed, seeds) = signed_federation(4);
        let sh = hash(0xAA);
        let cert = QuorumCertificate {
            quorum_id: "q1".into(),
            participating_verifiers: alloc::vec!["v0".into(), "v1".into(), "v2".into()],
            state_hash: sh,
            signatures: alloc::vec![
                sign_quorum(&seeds[0], "q1", &sh, "v0"),
                sign_quorum(&seeds[1], "q1", &sh, "v1"),
                sign_quorum(&seeds[2], "q1", &sh, "v2"),
            ],
        };
        assert_eq!(cert.verified_voters(&fed).len(), 3);
        let result = ByzantineQuorumResult::evaluate(4, &[cert.authenticated_vote_set(&fed)]);
        assert_eq!(result.safety, ByzantineSafetyState::Safe);
        assert_eq!(result.liveness, ByzantineLivenessState::Live);
    }

    // Forged certificate: the three signatures are over the WRONG state hash.
    // None verify, so the authenticated vote set is empty and the forged
    // certificate cannot establish quorum.
    #[test]
    fn forged_quorum_signatures_are_not_counted() {
        let (fed, seeds) = signed_federation(4);
        let real = hash(0xAA);
        let wrong = hash(0xBB);
        let cert = QuorumCertificate {
            quorum_id: "q1".into(),
            participating_verifiers: alloc::vec!["v0".into(), "v1".into(), "v2".into()],
            state_hash: real,
            // Signed over `wrong`, presented against `real`.
            signatures: alloc::vec![
                sign_quorum(&seeds[0], "q1", &wrong, "v0"),
                sign_quorum(&seeds[1], "q1", &wrong, "v1"),
                sign_quorum(&seeds[2], "q1", &wrong, "v2"),
            ],
        };
        assert!(cert.verified_voters(&fed).is_empty());
        let result = ByzantineQuorumResult::evaluate(4, &[cert.authenticated_vote_set(&fed)]);
        // No authenticated voters ⇒ not Safe/Live with a real quorum.
        assert_ne!(result.liveness, ByzantineLivenessState::Live);
    }

    // Non-member signatures are excluded even if internally well-formed.
    #[test]
    fn non_member_quorum_signatures_are_excluded() {
        let (fed, seeds) = signed_federation(4); // members v0..v3
        let sh = hash(0xAA);
        let cert = QuorumCertificate {
            quorum_id: "q1".into(),
            participating_verifiers: alloc::vec!["ghost".into()],
            state_hash: sh,
            // A valid signature, but "ghost" is not a federation member.
            signatures: alloc::vec![sign_quorum(&seeds[0], "q1", &sh, "ghost")],
        };
        assert!(cert.verified_voters(&fed).is_empty());
    }

    // Replay across quorum instances: a signature minted for quorum "q1" does
    // not verify when the certificate claims quorum "q2".
    #[test]
    fn quorum_signature_replayed_across_quorum_id_is_rejected() {
        let (fed, seeds) = signed_federation(4);
        let sh = hash(0xAA);
        let cert = QuorumCertificate {
            quorum_id: "q2".into(),
            participating_verifiers: alloc::vec!["v0".into()],
            state_hash: sh,
            signatures: alloc::vec![sign_quorum(&seeds[0], "q1", &sh, "v0")], // signed for q1
        };
        assert!(cert.verified_voters(&fed).is_empty());
    }

    // A verifier listed without a positionally-aligned signature is dropped
    // (zip truncates to the shorter of the two vectors).
    #[test]
    fn unsigned_listed_verifier_is_dropped() {
        let (fed, seeds) = signed_federation(4);
        let sh = hash(0xAA);
        let cert = QuorumCertificate {
            quorum_id: "q1".into(),
            participating_verifiers: alloc::vec!["v0".into(), "v1".into()],
            state_hash: sh,
            signatures: alloc::vec![sign_quorum(&seeds[0], "q1", &sh, "v0")], // only one sig
        };
        let voters = cert.verified_voters(&fed);
        assert_eq!(voters.len(), 1);
        assert!(voters.contains("v0"));
    }
}
