//! Verifier Reputation Tracking (AUDIT ONLY)
//!
//! [`VerifierReputation`] tracks aggregate statistics about a verifier's
//! historical behaviour for audit and monitoring purposes.
//!
//! # CRITICAL CONSTRAINT
//!
//! Reputation data **MUST NOT** influence consensus decisions, policy
//! evaluation, or trust judgments in any form. It exists exclusively as an
//! audit-visibility tool for human operators.
//!
//! This constraint is enforced architecturally: `VerifierReputation` does
//! not implement any trait used by the consensus or policy engines, and
//! `reliability_score()` is explicitly annotated as audit-only.
//!
//! # Intended Use
//!
//! - Display in monitoring dashboards
//! - Manual operator review prior to governance actions
//! - Post-incident forensic analysis

use alloc::string::String;

// ── VerifierReputation ────────────────────────────────────────────────────

/// Aggregate statistics about a verifier's historical behaviour.
///
/// # AUDIT ONLY
///
/// These counters are for human inspection only. They MUST NOT be read by
/// the consensus engine, policy engine, or any automated trust decision
/// pathway. Feeding reputation into consensus would create a covert channel
/// for implicit trust weighting, which violates the explainability invariant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifierReputation {
    /// The verifier whose reputation this tracks.
    pub verifier_id: String,
    /// Count of attestations this verifier evaluated as trustworthy and
    /// whose trust was subsequently confirmed by other means.
    pub successful_verifications: u64,
    /// Count of times this verifier's policy evaluation conflicted with
    /// the federation majority.
    pub policy_conflicts: u64,
    /// Count of times this verifier failed to produce a required transparency
    /// log entry within the expected window.
    pub transparency_failures: u64,
    /// Count of quorum votes this verifier has participated in.
    pub quorum_participations: u64,
    /// Unix seconds of the last update to this reputation record.
    pub last_updated: u64,
}

impl VerifierReputation {
    /// Creates a zeroed reputation record for the given verifier.
    #[must_use]
    pub fn new(verifier_id: String, now: u64) -> Self {
        Self {
            verifier_id,
            successful_verifications: 0,
            policy_conflicts: 0,
            transparency_failures: 0,
            quorum_participations: 0,
            last_updated: now,
        }
    }

    /// Records a successful verification.
    pub fn record_success(&mut self, now: u64) {
        self.successful_verifications = self.successful_verifications.saturating_add(1);
        self.last_updated = now;
    }

    /// Records a policy conflict with the federation majority.
    pub fn record_conflict(&mut self, now: u64) {
        self.policy_conflicts = self.policy_conflicts.saturating_add(1);
        self.last_updated = now;
    }

    /// Records a transparency logging failure.
    pub fn record_transparency_failure(&mut self, now: u64) {
        self.transparency_failures = self.transparency_failures.saturating_add(1);
        self.last_updated = now;
    }

    /// Records participation in a quorum vote.
    pub fn record_quorum_participation(&mut self, now: u64) {
        self.quorum_participations = self.quorum_participations.saturating_add(1);
        self.last_updated = now;
    }

    /// Returns a normalized reliability score in [0.0, 1.0].
    ///
    /// # AUDIT ONLY
    ///
    /// This score is computed as `successful / (successful + conflicts + failures)`.
    /// It is informational and MUST NOT be used to gate or weight any trust
    /// decision, policy rule, or consensus vote.
    ///
    /// Returns `1.0` when the verifier has no recorded events (no evidence of
    /// failure is not evidence of perfection; treat this conservatively).
    #[must_use]
    #[doc = "AUDIT ONLY: must not influence trust decisions or consensus"]
    pub fn reliability_score(&self) -> f64 {
        let total = self
            .successful_verifications
            .saturating_add(self.policy_conflicts)
            .saturating_add(self.transparency_failures);
        if total == 0 {
            return 1.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let score = self.successful_verifications as f64 / total as f64;
        score
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_reputation_is_zeroed() {
        let rep = VerifierReputation::new("v1".into(), 0);
        assert_eq!(rep.successful_verifications, 0);
        assert_eq!(rep.policy_conflicts, 0);
        assert_eq!(rep.transparency_failures, 0);
        assert_eq!(rep.quorum_participations, 0);
    }

    #[test]
    fn reliability_score_no_events() {
        let rep = VerifierReputation::new("v1".into(), 0);
        assert!((rep.reliability_score() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reliability_score_all_success() {
        let mut rep = VerifierReputation::new("v1".into(), 0);
        rep.record_success(1);
        rep.record_success(2);
        rep.record_success(3);
        assert!((rep.reliability_score() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reliability_score_mixed() {
        let mut rep = VerifierReputation::new("v1".into(), 0);
        rep.record_success(1);
        rep.record_success(2);
        rep.record_conflict(3);
        // 2 / (2 + 1 + 0) = 0.666...
        let score = rep.reliability_score();
        assert!(score > 0.66 && score < 0.67);
    }

    #[test]
    fn saturating_add_does_not_overflow() {
        let mut rep = VerifierReputation::new("v1".into(), 0);
        rep.successful_verifications = u64::MAX;
        rep.record_success(1); // should not panic
        assert_eq!(rep.successful_verifications, u64::MAX);
    }

    #[test]
    fn last_updated_tracks_time() {
        let mut rep = VerifierReputation::new("v1".into(), 100);
        rep.record_success(200);
        assert_eq!(rep.last_updated, 200);
        rep.record_conflict(300);
        assert_eq!(rep.last_updated, 300);
    }
}
