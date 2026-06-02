//! Distributed Consensus Engine
//!
//! Aggregates per-verifier votes into a deterministic `ConsensusDecision`.
//! Each verifier submits a `VerifierVote` independently; the
//! `ConsensusEvaluation::evaluate` function computes the final decision
//! according to the federation's [`QuorumPolicy`].
//!
//! # Determinism Guarantee
//!
//! Given the same `attestation_id`, `votes`, and `federation`, `evaluate`
//! always produces the same `ConsensusDecision`. There is no randomness,
//! no ordering sensitivity in the decision logic (only vote counts matter),
//! and no external state.
//!
//! # Fail-Closed
//!
//! - If fewer votes are cast than `quorum_required` → `QuorumFailed`.
//! - If votes are split such that neither `trusted_count` nor `untrusted_count`
//!   reaches quorum → `Inconclusive` (not `Trusted`).
//!
//! # Trust Domain Separation
//!
//! Each vote carries `reasons` from the voter's per-domain evaluation. The
//! consensus engine aggregates votes but does NOT merge or collapse the
//! underlying trust domain evaluations.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::federation_auth::{verify_ml_dsa, vote_payload, CTX_VOTE};
use crate::trust_domains::VerificationDecisionReason;
use crate::verifier_federation::VerifierFederation;

// ── VerifierVote ──────────────────────────────────────────────────────────

/// A single verifier's vote on whether an attestation is trustworthy.
///
/// The `reasons` field carries the per-domain decision reasons from the
/// voter's evaluation. These are preserved in the `ConsensusEvaluation`
/// for auditability.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifierVote {
    /// The verifier casting this vote.
    pub verifier_id: String,
    /// `true` if the verifier considers the attestation trustworthy.
    pub trusted: bool,
    /// Reasons (failures or confirmations) behind this vote.
    pub reasons: Vec<VerificationDecisionReason>,
    /// Non-fatal warnings from the voter's evaluation.
    pub warnings: Vec<String>,
    /// ML-DSA-65 signature by the voting verifier over the canonical
    /// [`vote_payload`](crate::federation_auth::vote_payload) binding the
    /// attestation id, verifier id, and trust verdict.
    ///
    /// Defaults to empty for backward compatibility; an empty or invalid
    /// signature means the vote is **not counted** by
    /// [`ConsensusEvaluation::evaluate`].
    #[serde(default, with = "serde_bytes")]
    pub signature: Vec<u8>,
}

// ── ConsensusDecision ─────────────────────────────────────────────────────

/// The final outcome of a distributed consensus evaluation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConsensusDecision {
    /// A quorum of verifiers found the attestation trustworthy.
    Trusted,
    /// A quorum of verifiers found the attestation untrustworthy.
    Untrusted,
    /// Votes are split; neither `Trusted` nor `Untrusted` reached quorum.
    Inconclusive,
    /// Insufficient verifiers participated; quorum cannot be established.
    QuorumFailed {
        /// Number of votes actually cast.
        participating: usize,
        /// Number of votes required by the federation policy.
        required: usize,
    },
}

impl ConsensusDecision {
    /// Returns `true` only when the decision is `Trusted`.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }
}

// ── ConsensusEvaluation ───────────────────────────────────────────────────

/// The aggregate outcome of distributed consensus over a single attestation.
///
/// Created by [`ConsensusEvaluation::evaluate`]. Contains the full vote
/// record for auditability and replay.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsensusEvaluation {
    /// Attestation reference (quote ID, nonce, etc.).
    pub attestation_id: String,
    /// All votes cast by federation members.
    pub verifier_votes: Vec<VerifierVote>,
    /// The final deterministic decision.
    pub final_decision: ConsensusDecision,
    /// Number of votes that were cast.
    pub participating: usize,
    /// Number of votes required by the federation's quorum policy.
    pub quorum_required: usize,
}

impl ConsensusEvaluation {
    /// Evaluates votes against the federation's quorum policy.
    ///
    /// # Authentication
    ///
    /// Before counting, each vote is authenticated:
    /// 1. The `verifier_id` must name a current federation member.
    /// 2. The `signature` must verify against that member's `public_key` over
    ///    the canonical [`vote_payload`] (binding attestation id, verifier, and
    ///    verdict) — so a vote signed for one attestation or verdict cannot be
    ///    replayed for another.
    /// 3. Each member is counted at most once (first valid vote wins), so
    ///    duplicate `verifier_id`s cannot inflate participation or the tally.
    ///
    /// Votes that fail any check are retained in `verifier_votes` for audit but
    /// excluded from `participating` and the decision. `participating` reflects
    /// the number of distinct, authenticated members.
    ///
    /// # Algorithm
    ///
    /// 1. Compute `quorum_required` from `federation.quorum_required()`.
    /// 2. If authenticated participation `< quorum_required` → `QuorumFailed`.
    /// 3. Count authenticated `trusted` votes; if `>= quorum_required` → `Trusted`.
    /// 4. Count authenticated `untrusted` votes; if `>= quorum_required` → `Untrusted`.
    /// 5. Otherwise → `Inconclusive`.
    #[must_use]
    pub fn evaluate(
        attestation_id: String,
        votes: Vec<VerifierVote>,
        federation: &VerifierFederation,
    ) -> Self {
        let quorum_required = federation.quorum_required();

        let member_keys: BTreeMap<&str, &[u8]> = federation
            .members
            .iter()
            .map(|m| (m.verifier_id.as_str(), m.public_key.as_slice()))
            .collect();

        // Authenticate and deduplicate: keep one verdict per member, counting
        // only votes whose signature verifies against the member's key.
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut trusted_count = 0usize;
        let mut untrusted_count = 0usize;
        let mut participating = 0usize;
        for vote in &votes {
            let Some(public_key) = member_keys.get(vote.verifier_id.as_str()) else {
                continue;
            };
            let payload = vote_payload(&attestation_id, &vote.verifier_id, vote.trusted);
            if !verify_ml_dsa(&payload, CTX_VOTE, public_key, &vote.signature) {
                continue;
            }
            if !seen.insert(vote.verifier_id.as_str()) {
                continue; // already counted this member
            }
            participating += 1;
            if vote.trusted {
                trusted_count += 1;
            } else {
                untrusted_count += 1;
            }
        }

        let final_decision = if participating < quorum_required {
            ConsensusDecision::QuorumFailed {
                participating,
                required: quorum_required,
            }
        } else if trusted_count >= quorum_required {
            ConsensusDecision::Trusted
        } else if untrusted_count >= quorum_required {
            ConsensusDecision::Untrusted
        } else {
            ConsensusDecision::Inconclusive
        };

        Self {
            attestation_id,
            verifier_votes: votes,
            final_decision,
            participating,
            quorum_required,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation_auth::{sign_ml_dsa, test_keys::keypair};
    use crate::verifier_federation::QuorumPolicy;
    use crate::verifier_identity::VerifierIdentity;
    use alloc::vec;

    /// Builds a federation of `n` members with real ML-DSA-65 keypairs, plus
    /// their signing seeds (indexed `v0..v{n-1}`).
    fn make_signed_federation(
        n: usize,
        policy: QuorumPolicy,
    ) -> (VerifierFederation, Vec<[u8; 32]>) {
        let mut members = Vec::new();
        let mut seeds = Vec::new();
        for i in 0..n {
            let (seed, vk) = keypair();
            members.push(VerifierIdentity {
                verifier_id: alloc::format!("v{i}"),
                organization: "Org".into(),
                public_key: vk,
                ml_kem_public_key: None,
                capabilities: vec![],
            });
            seeds.push(seed);
        }
        let fed = VerifierFederation {
            federation_id: "fed".into(),
            members,
            quorum_policy: policy,
        };
        (fed, seeds)
    }

    /// Produces a vote from member `idx`, validly signed for `attestation`.
    fn signed_vote(
        fed: &VerifierFederation,
        seeds: &[[u8; 32]],
        idx: usize,
        attestation: &str,
        trusted: bool,
    ) -> VerifierVote {
        let verifier_id = fed.members[idx].verifier_id.clone();
        let payload = vote_payload(attestation, &verifier_id, trusted);
        let signature = sign_ml_dsa(&payload, CTX_VOTE, &seeds[idx]).unwrap();
        let reasons = if trusted {
            vec![VerificationDecisionReason::Success]
        } else {
            vec![VerificationDecisionReason::SecureBootDisabled]
        };
        VerifierVote {
            verifier_id,
            trusted,
            reasons,
            warnings: vec![],
            signature,
        }
    }

    #[test]
    fn quorum_failed_no_votes() {
        let (fed, _seeds) = make_signed_federation(5, QuorumPolicy::Majority);
        let eval = ConsensusEvaluation::evaluate("a1".into(), vec![], &fed);
        assert!(matches!(
            eval.final_decision,
            ConsensusDecision::QuorumFailed {
                participating: 0,
                required: 3
            }
        ));
    }

    #[test]
    fn majority_quorum_trusted() {
        let (fed, s) = make_signed_federation(5, QuorumPolicy::Majority); // requires 3
        let a = "a2";
        let votes = vec![
            signed_vote(&fed, &s, 0, a, true),
            signed_vote(&fed, &s, 1, a, true),
            signed_vote(&fed, &s, 2, a, true),
            signed_vote(&fed, &s, 3, a, false),
            signed_vote(&fed, &s, 4, a, false),
        ];
        let eval = ConsensusEvaluation::evaluate(a.into(), votes, &fed);
        assert_eq!(eval.final_decision, ConsensusDecision::Trusted);
    }

    #[test]
    fn majority_quorum_untrusted() {
        let (fed, s) = make_signed_federation(5, QuorumPolicy::Majority); // requires 3
        let a = "a3";
        let votes = vec![
            signed_vote(&fed, &s, 0, a, false),
            signed_vote(&fed, &s, 1, a, false),
            signed_vote(&fed, &s, 2, a, false),
            signed_vote(&fed, &s, 3, a, true),
            signed_vote(&fed, &s, 4, a, true),
        ];
        let eval = ConsensusEvaluation::evaluate(a.into(), votes, &fed);
        assert_eq!(eval.final_decision, ConsensusDecision::Untrusted);
    }

    #[test]
    fn inconclusive_split() {
        // 5 members, majority = 3; 2 trusted, 2 untrusted, 1 abstained (not cast)
        let (fed, s) = make_signed_federation(5, QuorumPolicy::Majority);
        let a = "a4";
        let votes = vec![
            signed_vote(&fed, &s, 0, a, true),
            signed_vote(&fed, &s, 1, a, true),
            signed_vote(&fed, &s, 2, a, false),
            signed_vote(&fed, &s, 3, a, false),
        ]; // 4 authenticated; quorum=3 satisfied, but 2 vs 2 → inconclusive
        let eval = ConsensusEvaluation::evaluate(a.into(), votes, &fed);
        assert_eq!(eval.final_decision, ConsensusDecision::Inconclusive);
    }

    #[test]
    fn unanimous_one_untrusted_fails() {
        let (fed, s) = make_signed_federation(3, QuorumPolicy::Unanimous);
        let a = "a5";
        let votes = vec![
            signed_vote(&fed, &s, 0, a, true),
            signed_vote(&fed, &s, 1, a, true),
            signed_vote(&fed, &s, 2, a, false),
        ];
        let eval = ConsensusEvaluation::evaluate(a.into(), votes, &fed);
        // trusted_count=2 < 3, untrusted_count=1 < 3 → Inconclusive
        assert_eq!(eval.final_decision, ConsensusDecision::Inconclusive);
    }

    #[test]
    fn threshold_3_of_5_quorum_failed() {
        let (fed, s) = make_signed_federation(5, QuorumPolicy::Threshold(3));
        let a = "a6";
        let votes = vec![
            signed_vote(&fed, &s, 0, a, true),
            signed_vote(&fed, &s, 1, a, true),
        ]; // only 2 < 3
        let eval = ConsensusEvaluation::evaluate(a.into(), votes, &fed);
        assert!(matches!(
            eval.final_decision,
            ConsensusDecision::QuorumFailed { .. }
        ));
    }

    #[test]
    fn is_trusted_convenience() {
        assert!(ConsensusDecision::Trusted.is_trusted());
        assert!(!ConsensusDecision::Untrusted.is_trusted());
        assert!(!ConsensusDecision::Inconclusive.is_trusted());
        assert!(!ConsensusDecision::QuorumFailed {
            participating: 0,
            required: 3
        }
        .is_trusted());
    }

    // ── Adversarial tests ────────────────────────────────────────────────────

    // FIXED: evaluate() now deduplicates by verifier_id, counting each member at
    // most once. A single real verifier's vote, duplicated to fake a quorum, is
    // collapsed to participation=1 — below the quorum of 3.
    #[test]
    fn duplicate_votes_are_deduplicated_to_one() {
        let (fed, s) = make_signed_federation(5, QuorumPolicy::Majority); // quorum = 3
        let a = "dup";
        let votes = vec![
            signed_vote(&fed, &s, 0, a, true),
            signed_vote(&fed, &s, 0, a, true), // duplicate (identical signature)
            signed_vote(&fed, &s, 0, a, true), // duplicate
        ];
        let eval = ConsensusEvaluation::evaluate(a.into(), votes, &fed);
        assert_eq!(eval.participating, 1);
        assert!(matches!(
            eval.final_decision,
            ConsensusDecision::QuorumFailed {
                participating: 1,
                required: 3,
            }
        ));
    }

    // FIXED: evaluate() now checks that voting verifier IDs belong to
    // federation.members. Votes from fabricated identities are excluded entirely,
    // so quorum cannot be satisfied without legitimate member participation.
    #[test]
    fn non_member_votes_are_excluded() {
        let (fed, _s) = make_signed_federation(5, QuorumPolicy::Majority); // quorum = 3
                                                                           // Non-members with arbitrary (here empty) signatures.
        let votes = vec![
            VerifierVote {
                verifier_id: "attacker-1".into(),
                trusted: true,
                reasons: vec![],
                warnings: vec![],
                signature: vec![],
            },
            VerifierVote {
                verifier_id: "attacker-2".into(),
                trusted: true,
                reasons: vec![],
                warnings: vec![],
                signature: vec![],
            },
            VerifierVote {
                verifier_id: "attacker-3".into(),
                trusted: true,
                reasons: vec![],
                warnings: vec![],
                signature: vec![],
            },
        ];
        let eval = ConsensusEvaluation::evaluate("fake".into(), votes, &fed);
        assert_eq!(eval.participating, 0);
        assert!(matches!(
            eval.final_decision,
            ConsensusDecision::QuorumFailed { .. }
        ));
    }

    // Forged vote: a real member's verifier_id paired with a signature over a
    // different verdict (the canonical payload binds `trusted`). The vote is
    // excluded; with too few authenticated votes the decision is QuorumFailed.
    #[test]
    fn forged_vote_signature_is_excluded() {
        let (fed, s) = make_signed_federation(3, QuorumPolicy::Threshold(1));
        let a = "att";
        // Sign trusted=false but present the vote as trusted=true.
        let payload = vote_payload(a, "v0", false);
        let signature = sign_ml_dsa(&payload, CTX_VOTE, &s[0]).unwrap();
        let forged = VerifierVote {
            verifier_id: "v0".into(),
            trusted: true, // mismatch vs the signed verdict
            reasons: vec![],
            warnings: vec![],
            signature,
        };
        let eval = ConsensusEvaluation::evaluate(a.into(), vec![forged], &fed);
        assert_eq!(eval.participating, 0);
        assert!(matches!(
            eval.final_decision,
            ConsensusDecision::QuorumFailed { .. }
        ));
    }

    // Replayed vote: a vote validly signed for attestation "att-A" is replayed
    // into the evaluation of attestation "att-B". The attestation id is bound
    // into the payload, so the signature no longer verifies and the vote is
    // excluded.
    #[test]
    fn vote_replayed_across_attestations_is_excluded() {
        let (fed, s) = make_signed_federation(3, QuorumPolicy::Threshold(1));
        // Validly signed for att-A, but submitted under att-B.
        let replayed = signed_vote(&fed, &s, 0, "att-A", true);
        let eval = ConsensusEvaluation::evaluate("att-B".into(), vec![replayed], &fed);
        assert_eq!(eval.participating, 0);
        assert!(matches!(
            eval.final_decision,
            ConsensusDecision::QuorumFailed { .. }
        ));
    }
}
