use crate::policy::{HardwarePolicyContext, HardwarePolicyError, HardwarePolicyRule};
use crate::{
    pcr::PcrSemantic,
    runtime_drift::{RuntimeDriftEngine, RuntimeDriftSeverity},
};

#[allow(clippy::too_many_lines, clippy::collapsible_match)]
pub fn evaluate_domain_rule(
    rule: &HardwarePolicyRule,
    ctx: &HardwarePolicyContext<'_>,
) -> Result<bool, HardwarePolicyError> {
    match rule {
        HardwarePolicyRule::RequireNormalizedPcrs => {
            if !ctx.pcr_bank.all_normalized() {
                return Err(HardwarePolicyError::UnnormalizedPcrs);
            }
        }
        HardwarePolicyRule::RequirePcrSemantic(semantic) => {
            if ctx.pcr_bank.get(*semantic).is_none() {
                return Err(HardwarePolicyError::PcrSemanticAbsent(*semantic));
            }
        }
        HardwarePolicyRule::RequirePcrValue { semantic, expected } => {
            let m = ctx
                .pcr_bank
                .get(*semantic)
                .ok_or(HardwarePolicyError::PcrSemanticAbsent(*semantic))?;
            if &m.digest.value != expected {
                return Err(HardwarePolicyError::PcrValueMismatch {
                    semantic: *semantic,
                    expected: *expected,
                    got: m.digest.value,
                });
            }
        }
        HardwarePolicyRule::RequireFirmwareMeasurement => {
            if ctx.pcr_bank.get(PcrSemantic::Firmware).is_none() {
                return Err(HardwarePolicyError::MeasuredBootIncomplete(
                    PcrSemantic::Firmware,
                ));
            }
        }
        HardwarePolicyRule::RequireBootloaderMeasurement => {
            if ctx.pcr_bank.get(PcrSemantic::Bootloader).is_none() {
                return Err(HardwarePolicyError::MeasuredBootIncomplete(
                    PcrSemantic::Bootloader,
                ));
            }
        }
        HardwarePolicyRule::RequireKernelMeasurement => {
            if ctx.pcr_bank.get(PcrSemantic::Kernel).is_none() {
                return Err(HardwarePolicyError::MeasuredBootIncomplete(
                    PcrSemantic::Kernel,
                ));
            }
        }
        HardwarePolicyRule::RequireMeasuredBoot => {
            // Minimum measured boot: Firmware AND Bootloader must be present.
            if ctx.pcr_bank.get(PcrSemantic::Firmware).is_none() {
                return Err(HardwarePolicyError::MeasuredBootIncomplete(
                    PcrSemantic::Firmware,
                ));
            }
            if ctx.pcr_bank.get(PcrSemantic::Bootloader).is_none() {
                return Err(HardwarePolicyError::MeasuredBootIncomplete(
                    PcrSemantic::Bootloader,
                ));
            }
        }
        HardwarePolicyRule::RequireSecureBootState(expected) => {
            let sb = ctx
                .secure_boot
                .ok_or(HardwarePolicyError::SecureBootEvidenceMissing)?;
            if sb.state != *expected {
                return Err(HardwarePolicyError::SecureBootStateMismatch {
                    expected: *expected,
                    got: sb.state,
                });
            }
        }
        HardwarePolicyRule::RequireBootChain(expected) => {
            let bc = ctx
                .boot_chain
                .ok_or(HardwarePolicyError::BootChainEvidenceMissing)?;
            if bc.firmware != expected.firmware {
                return Err(HardwarePolicyError::BootChainFirmwareMismatch {
                    expected: expected.firmware,
                    got: bc.firmware,
                });
            }
            if bc.bootloader != expected.bootloader {
                return Err(HardwarePolicyError::BootChainBootloaderMismatch {
                    expected: expected.bootloader,
                    got: bc.bootloader,
                });
            }
            if bc.kernel != expected.kernel {
                return Err(HardwarePolicyError::BootChainKernelMismatch {
                    expected: expected.kernel,
                    got: bc.kernel,
                });
            }
        }
        HardwarePolicyRule::RequirePlatformProfile {
            profile,
            drift_mode,
            upgrade_baseline,
        } => {
            let report = profile.verify(
                ctx.pcr_bank,
                ctx.secure_boot,
                *drift_mode,
                upgrade_baseline.as_ref(),
            );
            if !report.profile_match {
                return Err(HardwarePolicyError::PlatformProfileMismatch {
                    reason: report.decision_reason,
                });
            }
        }
        HardwarePolicyRule::RequireValidBaselineTransition { current, previous } => {
            if !current.is_valid_successor(previous) {
                return Err(HardwarePolicyError::BaselineRollbackDetected);
            }
        }
        HardwarePolicyRule::RequireRuntimeIntegrity {
            whitelist,
            rolling_upgrades,
        } => {
            let runtime_att = ctx
                .runtime_attestation
                .ok_or(HardwarePolicyError::RuntimeAttestationEvidenceMissing)?;
            let drift_reports = RuntimeDriftEngine::detect_drift(
                &runtime_att.measurements,
                whitelist,
                rolling_upgrades,
            );
            for report in drift_reports {
                if report.severity == RuntimeDriftSeverity::Critical {
                    return Err(HardwarePolicyError::CriticalRuntimeDriftDetected(report));
                }
            }
        }
        HardwarePolicyRule::RequireIma => {
            let ima = ctx
                .ima_evidence
                .ok_or(HardwarePolicyError::ImaEvidenceMissing)?;
            if !ima.ima_enabled {
                return Err(HardwarePolicyError::ImaDisabled);
            }
            if !ima.appraisal_enabled {
                return Err(HardwarePolicyError::ImaAppraisalDisabled);
            }
        }
        HardwarePolicyRule::RequireLiveImaEvidence => {
            // We'd expect IMA evidence or live evidence
            return Err(HardwarePolicyError::LiveImaEvidenceMissing);
        }
        HardwarePolicyRule::RequireSecureBootCollection => {
            #[cfg(feature = "live-evidence")]
            if ctx
                .live_evidence
                .map_or(true, |e| e.secure_boot_state.is_none())
            {
                return Err(HardwarePolicyError::SecureBootCollectionMissing);
            }
            #[cfg(not(feature = "live-evidence"))]
            return Err(HardwarePolicyError::SecureBootCollectionMissing);
        }
        HardwarePolicyRule::RequireFreshRuntimeEvidence => {
            #[cfg(feature = "live-evidence")]
            if let Some(obs) = ctx.live_observation {
                if obs.integrity_status != crate::freshness::FreshnessStatus::Fresh {
                    return Err(HardwarePolicyError::FreshRuntimeEvidenceMissing);
                }
            } else {
                return Err(HardwarePolicyError::FreshRuntimeEvidenceMissing);
            }
            #[cfg(not(feature = "live-evidence"))]
            return Err(HardwarePolicyError::FreshRuntimeEvidenceMissing);
        }
        HardwarePolicyRule::RequireRuntimeObservationContinuity => {
            #[cfg(feature = "live-evidence")]
            if ctx.live_observation.is_none() {
                return Err(HardwarePolicyError::RuntimeObservationContinuityBroken);
            }
            #[cfg(not(feature = "live-evidence"))]
            return Err(HardwarePolicyError::RuntimeObservationContinuityBroken);
        }
        _ => return Ok(false),
    }
    Ok(true)
}
