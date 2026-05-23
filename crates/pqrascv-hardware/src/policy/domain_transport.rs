use crate::policy::{HardwarePolicyContext, HardwarePolicyError, HardwarePolicyRule};

#[allow(clippy::too_many_lines, clippy::collapsible_match)]
pub fn evaluate_domain_rule(
    rule: &HardwarePolicyRule,
    ctx: &HardwarePolicyContext<'_>,
) -> Result<bool, HardwarePolicyError> {
    match rule {
        // ── Phase 3.2 Streaming & PQ Federation Rules ─────────────────
        HardwarePolicyRule::RequireDeltaAttestation => {
            if ctx.delta_attestation.is_none() {
                return Err(HardwarePolicyError::DeltaAttestationMissing);
            }
        }
        HardwarePolicyRule::RequirePqFederationTransport => {
            if ctx.pq_session.is_none() {
                return Err(HardwarePolicyError::PqFederationTransportMissing);
            }
        }
        HardwarePolicyRule::RequireFederationMessageSigning => {
            if ctx.federation_envelope.is_none() {
                return Err(HardwarePolicyError::FederationMessageSigningInvalid);
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}
