use crate::policy::{HardwarePolicyContext, HardwarePolicyError, HardwarePolicyRule};

#[allow(clippy::too_many_lines, clippy::collapsible_match)]
pub fn evaluate_domain_rule(
    rule: &HardwarePolicyRule,
    ctx: &HardwarePolicyContext<'_>,
) -> Result<bool, HardwarePolicyError> {
    match rule {
        HardwarePolicyRule::RequireContinuousAttestation {
            expiration_window_secs,
            now_secs,
        } => {
            let session = ctx
                .session
                .ok_or(HardwarePolicyError::ContinuousAttestationSessionMissing)?;
            if !session.active {
                return Err(HardwarePolicyError::ContinuousAttestationSessionInactive);
            }
            if *now_secs < session.last_seen
                || *now_secs - session.last_seen > *expiration_window_secs
            {
                return Err(HardwarePolicyError::ContinuousAttestationExpired {
                    last_seen: session.last_seen,
                    now: *now_secs,
                    window: *expiration_window_secs,
                });
            }
        }
        HardwarePolicyRule::RequireSequenceMonotonicity => {
            let evidence = ctx
                .runtime_attestation
                .ok_or(HardwarePolicyError::RuntimeAttestationEvidenceMissing)?;
            let session = ctx
                .session
                .ok_or(HardwarePolicyError::ContinuousAttestationSessionMissing)?;
            if evidence.sequence_number <= session.sequence_number {
                return Err(HardwarePolicyError::ReplayDetected {
                    got: evidence.sequence_number,
                    expected: session.sequence_number + 1,
                });
            }
            if evidence.sequence_number != session.sequence_number + 1 {
                return Err(HardwarePolicyError::SequenceGapDetected {
                    got: evidence.sequence_number,
                    expected: session.sequence_number + 1,
                });
            }
        }
        HardwarePolicyRule::RequireTransparencyAnchoring => {
            let proof = ctx
                .transparency_proof
                .ok_or(HardwarePolicyError::TransparencyProofMissing)?;
            let verifier = ctx
                .spv_verifier
                .ok_or(HardwarePolicyError::SpvVerifierMissing)?;
            let event = ctx
                .transparency_event
                .ok_or(HardwarePolicyError::TransparencyEventMissing)?;

            let event_hash = event
                .canonical_hash()
                .map_err(|_| HardwarePolicyError::TransparencySerializationFailed)?;
            verifier
                .verify(proof, &event_hash)
                .map_err(HardwarePolicyError::SpvVerificationFailed)?;
        }
        HardwarePolicyRule::RequirePolicyEpoch(expected_epoch) => {
            let evidence = ctx
                .runtime_attestation
                .ok_or(HardwarePolicyError::RuntimeAttestationEvidenceMissing)?;
            if evidence.policy_epoch != *expected_epoch {
                return Err(HardwarePolicyError::PolicyEpochMismatch {
                    expected: *expected_epoch,
                    got: evidence.policy_epoch,
                });
            }
        }
        // ── Phase 3.4 Federation Time Semantics ────────────────────────
        HardwarePolicyRule::RequireLogicalClockSynchronization => {
            if ctx.logical_clock.is_none() {
                return Err(HardwarePolicyError::LogicalClockFailed);
            }
        }
        HardwarePolicyRule::RequireBoundedTimeSkew => {
            if ctx.temporal_ambiguity.is_some() {
                return Err(HardwarePolicyError::TimeSkewExceeded);
            }
        }
        HardwarePolicyRule::RequireAnchoredKeyRegistry => {
            use pqrascv_bitcoin_anchor::key_registry_anchor::VerifierRegistrationState;
            if let Some(state) = ctx.verifier_registration_state {
                if *state != VerifierRegistrationState::Anchored {
                    return Err(HardwarePolicyError::VerifierNotAnchored);
                }
            } else {
                return Err(HardwarePolicyError::VerifierNotAnchored);
            }
        }
        HardwarePolicyRule::RequireEpochKeyBinding => {
            if ctx.epoch_key_binding.is_none() {
                return Err(HardwarePolicyError::EpochKeyBindingInvalid);
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}
