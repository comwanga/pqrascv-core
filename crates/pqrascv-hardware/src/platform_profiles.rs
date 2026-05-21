//! Platform Profiles
//!
//! Provides platform-aware verification semantics, transitioning away
//! from opaque PCR comparisons toward explicit platform profiling.

use crate::baseline::{ExpectedPcr, PcrBaseline};
use crate::drift::{DriftDetectionEngine, DriftPolicyMode, DriftReport, DriftSeverity};
use crate::pcr::PcrSemantic;
use crate::secure_boot::{SecureBootEvidence, SecureBootState};
use alloc::string::String;
use alloc::vec::Vec;

/// High-level classification of the platform being verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PlatformClass {
    LinuxServer,
    BitcoinNode,
    EmbeddedDevice,
    CloudVm,
    ConfidentialVm,
    BareMetalWorkstation,
}

/// The hardware or hypervisor vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PlatformVendor {
    Dell,
    Lenovo,
    HP,
    Intel,
    AMD,
    Coreboot,
    Qemu,
    Unknown,
}

/// A comprehensive definition of a platform's expected state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlatformProfile {
    /// Unique identifier for this profile.
    pub profile_id: String,
    /// Vendor mapping.
    pub vendor: PlatformVendor,
    /// Platform classification.
    pub platform_class: PlatformClass,
    /// Whether Secure Boot is strictly required for this profile.
    pub secure_boot_required: bool,
    /// The canonical expected measurements.
    pub expected_pcrs: Vec<ExpectedPcr>,
    /// Tracked firmware generation to detect rollbacks.
    pub firmware_generation: u64,
    /// Policy epoch tying the profile to an overarching policy version.
    pub policy_epoch: u64,
}

impl PlatformProfile {
    /// Evaluates incoming evidence (represented by PCR bank, Secure Boot state, etc.) against this profile.
    ///
    /// It returns a `PlatformVerificationReport` that explains the outcome.
    #[must_use]
    pub fn verify(
        &self,
        actual_pcrs: &crate::pcr::TypedPcrBank,
        secure_boot: Option<&SecureBootEvidence>,
        drift_mode: DriftPolicyMode,
        upgrade_baseline: Option<&PcrBaseline>,
    ) -> PlatformVerificationReport {
        let drift_reports = DriftDetectionEngine::detect_drift(self, actual_pcrs, upgrade_baseline);
        let warnings = Vec::new();
        let mut decision_reason = VerificationDecisionReason::Success;

        // 1. Secure Boot checks
        let secure_boot_valid = if self.secure_boot_required {
            if let Some(sb) = secure_boot {
                if sb.state == SecureBootState::Enabled {
                    true
                } else {
                    decision_reason = VerificationDecisionReason::SecureBootDisabled;
                    false
                }
            } else {
                decision_reason = VerificationDecisionReason::SecureBootDisabled;
                false
            }
        } else {
            true
        };

        // 2. Measured Boot checks (PCRs match and no critical drift)
        let mut measured_boot_valid = secure_boot_valid; // start with secure boot status, if SB is invalid we fail
        let mut has_critical_drift = false;
        let mut has_warning_drift = false;
        let mut drift_detected = false;

        for report in &drift_reports {
            drift_detected = true;
            match report.severity {
                DriftSeverity::Critical => {
                    has_critical_drift = true;
                }
                DriftSeverity::Warning => {
                    has_warning_drift = true;
                }
                DriftSeverity::Informational => {}
            }
        }

        // Apply drift policy to determine if measured boot is valid
        if has_critical_drift
            && !DriftDetectionEngine::is_drift_permissible(drift_mode, DriftSeverity::Critical)
        {
            measured_boot_valid = false;
            if decision_reason == VerificationDecisionReason::Success {
                decision_reason = VerificationDecisionReason::CriticalDriftDetected;
            }
        }
        if has_warning_drift
            && !DriftDetectionEngine::is_drift_permissible(drift_mode, DriftSeverity::Warning)
        {
            measured_boot_valid = false;
            if decision_reason == VerificationDecisionReason::Success {
                decision_reason = VerificationDecisionReason::CriticalDriftDetected;
            }
        }

        // Check for missing kernel measurement explicitly if expected
        let has_kernel_expected = self
            .expected_pcrs
            .iter()
            .any(|m| m.semantic == PcrSemantic::Kernel);
        if has_kernel_expected && actual_pcrs.get(PcrSemantic::Kernel).is_none() {
            measured_boot_valid = false;
            if decision_reason == VerificationDecisionReason::Success {
                decision_reason = VerificationDecisionReason::MissingKernelMeasurement;
            }
        }

        let profile_match = secure_boot_valid && measured_boot_valid;

        PlatformVerificationReport {
            profile_match,
            secure_boot_valid,
            measured_boot_valid,
            drift_detected,
            drift_reports,
            warnings,
            decision_reason,
        }
    }
}

/// Explicit reasoning for an attestation verification decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VerificationDecisionReason {
    /// Verification passed all checks.
    Success,
    /// Secure Boot is required but was disabled or in setup mode.
    SecureBootDisabled,
    /// An unauthorized firmware or policy rollback was detected.
    BaselineRollbackDetected,
    /// The firmware generation reported is completely unknown.
    UnknownFirmwareGeneration,
    /// Measurement drift exceeding permissible bounds was detected.
    CriticalDriftDetected,
    /// An expected OS Kernel measurement was missing from the evidence.
    MissingKernelMeasurement,
    /// The supplied Platform Profile is malformed or invalid.
    InvalidPlatformProfile,
    /// The hardware vendor is not supported by the current policy.
    UnsupportedVendor,
}

/// Explanatory report resulting from a platform-aware attestation evaluation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct PlatformVerificationReport {
    /// True if the evidence matches the profile requirements.
    pub profile_match: bool,
    /// True if Secure Boot policy was satisfied.
    pub secure_boot_valid: bool,
    /// True if all measured boot elements align.
    pub measured_boot_valid: bool,
    /// True if any drift (Informational, Warning, or Critical) was observed.
    pub drift_detected: bool,
    /// Any explicit drift observations.
    pub drift_reports: Vec<DriftReport>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Explicit reasoning for the final attestation decision.
    pub decision_reason: VerificationDecisionReason,
}
