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

use alloc::string::String;
use alloc::vec::Vec;

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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    /// # Algorithm
    ///
    /// 1. Compute `quorum_required` from `federation.quorum_required()`.
    /// 2. If `votes.len() < quorum_required` → `QuorumFailed`.
    /// 3. Count `trusted_votes`; if `>= quorum_required` → `Trusted`.
    /// 4. Count `untrusted_votes`; if `>= quorum_required` → `Untrusted`.
    /// 5. Otherwise → `Inconclusive`.
    #[must_use]
    pub fn evaluate(
        attestation_id: String,
        votes: Vec<VerifierVote>,
        federation: &VerifierFederation,
    ) -> Self {
        let quorum_required = federation.quorum_required();
        let participating = votes.len();

        let final_decision = if participating < quorum_required {
            ConsensusDecision::QuorumFailed {
                participating,
                required: quorum_required,
            }
        } else {
            let trusted_count = votes.iter().filter(|v| v.trusted).count();
            let untrusted_count = votes.iter().filter(|v| !v.trusted).count();

            if trusted_count >= quorum_required {
                ConsensusDecision::Trusted
            } else if untrusted_count >= quorum_required {
                ConsensusDecision::Untrusted
            } else {
                ConsensusDecision::Inconclusive
            }
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
    use crate::verifier_federation::QuorumPolicy;
    use crate::verifier_identity::VerifierIdentity;
    use alloc::vec;

    fn make_federation(n: usize, policy: QuorumPolicy) -> VerifierFederation {
        VerifierFederation {
            federation_id: "fed".into(),
            members: (0..n)
                .map(|i| VerifierIdentity {
                    verifier_id: alloc::format!("v{i}"),
                    organization: "Org".into(),
                    public_key: vec![1],
                    capabilities: vec![],
                })
                .collect(),
            quorum_policy: policy,
        }
    }

    fn trusted_vote(id: &str) -> VerifierVote {
        VerifierVote {
            verifier_id: id.into(),
            trusted: true,
            reasons: vec![VerificationDecisionReason::Success],
            warnings: vec![],
        }
    }

    fn untrusted_vote(id: &str) -> VerifierVote {
        VerifierVote {
            verifier_id: id.into(),
            trusted: false,
            reasons: vec![VerificationDecisionReason::SecureBootDisabled],
            warnings: vec![],
        }
    }

    #[test]
    fn quorum_failed_no_votes() {
        let fed = make_federation(5, QuorumPolicy::Majority);
        let eval = ConsensusEvaluation::evaluate("a1".into(), vec![], &fed);
        assert!(matches!(
            eval.final_decision,
            ConsensusDecision::QuorumFailed { participating: 0, required: 3 }
        ));
    }

    #[test]
    fn majority_quorum_trusted() {
        let fed = make_federation(5, QuorumPolicy::Majority); // requires 3
        let votes = vec![
            trusted_vote("v0"),
            trusted_vote("v1"),
            trusted_vote("v2"),
            untrusted_vote("v3"),
            untrusted_vote("v4"),
        ];
        let eval = ConsensusEvaluation::evaluate("a2".into(), votes, &fed);
        assert_eq!(eval.final_decision, ConsensusDecision::Trusted);
    }

    #[test]
    fn majority_quorum_untrusted() {
        let fed = make_federation(5, QuorumPolicy::Majority); // requires 3
        let votes = vec![
            untrusted_vote("v0"),
            untrusted_vote("v1"),
            untrusted_vote("v2"),
            trusted_vote("v3"),
            trusted_vote("v4"),
        ];
        let eval = ConsensusEvaluation::evaluate("a3".into(), votes, &fed);
        assert_eq!(eval.final_decision, ConsensusDecision::Untrusted);
    }

    #[test]
    fn inconclusive_split() {
        // 5 members, majority = 3; 2 trusted, 2 untrusted, 1 abstained (not cast)
        let fed = make_federation(5, QuorumPolicy::Majority);
        let votes = vec![
            trusted_vote("v0"),
            trusted_vote("v1"),
            untrusted_vote("v2"),
            untrusted_vote("v3"),
        ]; // only 4 votes cast; quorum=3 so participation is ok, but 2 vs 2 → inconclusive
        let eval = ConsensusEvaluation::evaluate("a4".into(), votes, &fed);
        assert_eq!(eval.final_decision, ConsensusDecision::Inconclusive);
    }

    #[test]
    fn unanimous_one_untrusted_fails() {
        let fed = make_federation(3, QuorumPolicy::Unanimous);
        let votes = vec![
            trusted_vote("v0"),
            trusted_vote("v1"),
            untrusted_vote("v2"),
        ];
        let eval = ConsensusEvaluation::evaluate("a5".into(), votes, &fed);
        // trusted_count=2 < 3, untrusted_count=1 < 3 → Inconclusive
        assert_eq!(eval.final_decision, ConsensusDecision::Inconclusive);
    }

    #[test]
    fn threshold_3_of_5_quorum_failed() {
        let fed = make_federation(5, QuorumPolicy::Threshold(3));
        let votes = vec![trusted_vote("v0"), trusted_vote("v1")]; // only 2 < 3
        let eval = ConsensusEvaluation::evaluate("a6".into(), votes, &fed);
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
}
