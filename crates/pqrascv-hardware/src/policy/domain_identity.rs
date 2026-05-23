use crate::policy::{HardwarePolicyContext, HardwarePolicyError, HardwarePolicyRule};

#[allow(clippy::too_many_lines, clippy::collapsible_match)]
pub fn evaluate_domain_rule(
    rule: &HardwarePolicyRule,
    ctx: &HardwarePolicyContext<'_>,
) -> Result<bool, HardwarePolicyError> {
    match rule {
        HardwarePolicyRule::RequireHardwareRootedBackend => {
            if !ctx.backend_type.is_hardware_rooted() {
                return Err(HardwarePolicyError::BackendNotHardwareRooted(
                    ctx.backend_type,
                ));
            }
        }
        HardwarePolicyRule::RequireBackendType(required) => {
            if ctx.backend_type != *required {
                return Err(HardwarePolicyError::WrongBackendType {
                    required: *required,
                    got: ctx.backend_type,
                });
            }
        }
        HardwarePolicyRule::RequireHardwareMonotonicCounter => {
            if !ctx.counter.is_hardware_backed() {
                return Err(HardwarePolicyError::CounterNotHardwareBacked(ctx.counter));
            }
        }
        HardwarePolicyRule::RequireMinCounterValue(min) => match ctx.counter.value() {
            Some(v) if v >= *min => {}
            Some(v) => return Err(HardwarePolicyError::CounterTooLow { got: v, min: *min }),
            None => return Err(HardwarePolicyError::CounterNotHardwareBacked(ctx.counter)),
        },
        HardwarePolicyRule::RequireNonceBinding => {
            if !ctx.supports_nonce_binding {
                return Err(HardwarePolicyError::NonceBindingUnsupported);
            }
        }
        // ── Phase 3.1 Live Evidence Rules ──────────────────────────
        HardwarePolicyRule::RequireLiveTpmEvidence => {
            #[cfg(feature = "live-evidence")]
            if ctx.live_evidence.is_none() {
                return Err(HardwarePolicyError::LiveTpmEvidenceMissing);
            }
            #[cfg(not(feature = "live-evidence"))]
            return Err(HardwarePolicyError::LiveTpmEvidenceMissing);
        }
        _ => return Ok(false),
    }
    Ok(true)
}
