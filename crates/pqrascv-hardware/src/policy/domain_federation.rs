use crate::policy::{HardwarePolicyContext, HardwarePolicyError, HardwarePolicyRule};

#[allow(clippy::too_many_lines, clippy::collapsible_match)]
pub fn evaluate_domain_rule(
    rule: &HardwarePolicyRule,
    ctx: &HardwarePolicyContext<'_>,
) -> Result<bool, HardwarePolicyError> {
    match rule {
        // ── Phase 2.9 Federated Trust Rules ──────────────────────────
        HardwarePolicyRule::RequireVerifierFederation => {
            if ctx.federation.is_none() {
                return Err(HardwarePolicyError::VerifierFederationMissing);
            }
        }
        HardwarePolicyRule::RequireConsensusQuorum { min_votes } => {
            let eval = ctx
                .consensus_evaluation
                .ok_or(HardwarePolicyError::VerifierFederationMissing)?;
            if eval.participating < *min_votes {
                return Err(HardwarePolicyError::ConsensusQuorumFailed {
                    decision: eval.final_decision.clone(),
                });
            }
            if !eval.final_decision.is_trusted() {
                return Err(HardwarePolicyError::ConsensusQuorumFailed {
                    decision: eval.final_decision.clone(),
                });
            }
        }
        HardwarePolicyRule::RequireTransparencyConsensus => {
            let report = ctx
                .timeline_reconciliation
                .ok_or(HardwarePolicyError::TransparencyConsensusFailed)?;
            if report.conflicts_detected {
                return Err(HardwarePolicyError::TransparencyConsensusFailed);
            }
        }
        HardwarePolicyRule::RequireFederatedPolicyApproval => {
            let epoch = ctx
                .federated_epoch
                .ok_or(HardwarePolicyError::FederatedPolicyApprovalMissing)?;
            if !epoch.quorum_reached {
                return Err(HardwarePolicyError::FederatedEpochQuorumNotReached {
                    epoch_id: epoch.epoch_id,
                });
            }
        }
        HardwarePolicyRule::RequireTimelineConsistency => {
            let report = ctx
                .timeline_reconciliation
                .ok_or(HardwarePolicyError::TimelineConflictDetected)?;
            if report.conflicts_detected || report.missing_events {
                return Err(HardwarePolicyError::TimelineConflictDetected);
            }
        }
        HardwarePolicyRule::RequireRetentionCompliance => {
            if ctx.compacted_timeline.is_none() && ctx.runtime_stream.is_some() {
                // Very simplistic heuristic mapping for the policy engine context
                return Err(HardwarePolicyError::RetentionComplianceViolated);
            }
        }
        // ── Phase 3.3 Byzantine Federation Convergence ─────────────────
        HardwarePolicyRule::RequireVerifierRevocationChecks => {
            if ctx.revocation_list.is_none() {
                return Err(HardwarePolicyError::VerifierRevoked("Unknown".into()));
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}
