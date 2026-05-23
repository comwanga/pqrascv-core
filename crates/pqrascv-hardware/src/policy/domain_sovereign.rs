use crate::policy::{HardwarePolicyContext, HardwarePolicyError, HardwarePolicyRule};

#[allow(clippy::too_many_lines, clippy::collapsible_match)]
pub fn evaluate_domain_rule(
    rule: &HardwarePolicyRule,
    ctx: &HardwarePolicyContext<'_>,
) -> Result<bool, HardwarePolicyError> {
    match rule {
        // ── Phase 3.0 Sovereign Node Rules ──────────────────────────
        HardwarePolicyRule::RequireBitcoinNodeIdentity => {
            if ctx.bitcoin_node_identity.is_none() {
                return Err(HardwarePolicyError::BitcoinNodeIdentityMissing);
            }
        }
        HardwarePolicyRule::RequireBitcoinWorkloadIntegrity => {
            let id = ctx
                .bitcoin_node_identity
                .ok_or(HardwarePolicyError::BitcoinNodeIdentityMissing)?;
            let evidence = ctx
                .bitcoin_workload_evidence
                .ok_or(HardwarePolicyError::BitcoinWorkloadEvidenceMissing)?;

            if evidence.executable_hash.value != id.expected_binary_hash.value
                || evidence.executable_hash.algorithm != id.expected_binary_hash.algorithm
            {
                return Err(HardwarePolicyError::BitcoinBinaryMismatch {
                    expected: id.expected_binary_hash,
                    got: evidence.executable_hash,
                });
            }
            if evidence.config_hash.value != id.expected_config_hash.value
                || evidence.config_hash.algorithm != id.expected_config_hash.algorithm
            {
                return Err(HardwarePolicyError::UnauthorizedConfigMutation {
                    expected: id.expected_config_hash,
                    got: evidence.config_hash,
                });
            }
        }
        HardwarePolicyRule::RequireNodeRuntimeContinuity => {
            if ctx.bitcoin_runtime_state.is_none() {
                return Err(HardwarePolicyError::BitcoinRuntimeStateMissing);
            }
        }
        HardwarePolicyRule::RequireNodeTransparencyAnchoring => {
            // If there's no transparency proof, we haven't anchored.
            if ctx.transparency_proof.is_none() {
                return Err(HardwarePolicyError::NodeTransparencyWithholding);
            }
        }
        HardwarePolicyRule::RequireFederatedNodeVerification => {
            let eval = ctx
                .consensus_evaluation
                .ok_or(HardwarePolicyError::VerifierFederationMissing)?;
            if !eval.final_decision.is_trusted() {
                return Err(HardwarePolicyError::ConsensusQuorumFailed {
                    decision: eval.final_decision.clone(),
                });
            }
        }
        HardwarePolicyRule::RequireDeterministicNodePolicy => {
            // To assert deterministic policy, we expect the identity to be present
            // (which anchors the chosen policy profile). The actual policy construction
            // from the profile handles the determinism.
            if ctx.bitcoin_node_identity.is_none() {
                return Err(HardwarePolicyError::DeterministicPolicyMissing);
            }
        }
        HardwarePolicyRule::RequireVerifiedBitcoinProcess => {
            #[cfg(feature = "live-evidence")]
            if ctx
                .live_evidence
                .map_or(true, |e| e.process_evidence.is_none())
            {
                return Err(HardwarePolicyError::VerifiedBitcoinProcessMissing);
            }
            #[cfg(not(feature = "live-evidence"))]
            return Err(HardwarePolicyError::VerifiedBitcoinProcessMissing);
        }
        _ => return Ok(false),
    }
    Ok(true)
}
