//! Drift Detection Engine
//!
//! Handles operational anomaly detection by identifying when a platform's
//! measurements deviate from the expected baseline.

use crate::digest::TypedDigest;
use crate::pcr::PcrSemantic;
use crate::platform_profiles::PlatformProfile;
use crate::baseline::PcrBaseline;
use alloc::vec::Vec;

/// Severity of the detected measurement drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DriftSeverity {
    /// Expected variations or non-security-critical deviations.
    Informational,
    /// Unexpected but potentially benign deviations (e.g., non-critical config changes).
    Warning,
    /// Severe deviations indicating compromise or unauthorized baseline modification.
    Critical,
}

/// Operational policy for handling detected drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DriftPolicyMode {
    /// Logging only. Allows all drift levels for establishing baselines.
    Learning,
    /// Allows Informational and Warning drift (with logs/alerts), but fails on Critical.
    Audit,
    /// Strict enforcement. Fails on both Warning and Critical drift.
    Enforcing,
}

/// A structured report of a single measurement drift.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DriftReport {
    /// The expected digest from the baseline.
    pub expected: TypedDigest,
    /// The actual digest observed.
    pub actual: TypedDigest,
    /// The semantic meaning of the drifted PCR.
    pub semantic: PcrSemantic,
    /// The severity assigned to this drift.
    pub severity: DriftSeverity,
}

/// The engine responsible for evaluating drift against policy.
pub struct DriftDetectionEngine;

impl DriftDetectionEngine {
    /// Evaluates a detected drift against the operational policy mode.
    ///
    /// Returns `true` if the drift is permissible under the current mode,
    /// or `false` if it should cause an attestation failure.
    #[must_use]
    pub fn is_drift_permissible(mode: DriftPolicyMode, severity: DriftSeverity) -> bool {
        match (mode, severity) {
            (DriftPolicyMode::Learning, _)
            | (DriftPolicyMode::Audit, DriftSeverity::Informational | DriftSeverity::Warning)
            | (DriftPolicyMode::Enforcing, DriftSeverity::Informational) => true,
            (DriftPolicyMode::Audit, DriftSeverity::Critical)
            | (DriftPolicyMode::Enforcing, DriftSeverity::Warning | DriftSeverity::Critical) => false,
        }
    }

    /// Detects drift by comparing actual measurements in a PCR bank against the expected PCRs of a platform profile.
    ///
    /// If actual measurements differ from the profile's expected values, a list of `DriftReport` is generated.
    #[must_use]
    pub fn detect_drift(
        profile: &PlatformProfile,
        actual_pcrs: &crate::pcr::TypedPcrBank,
        upgrade_baseline: Option<&PcrBaseline>,
    ) -> Vec<DriftReport> {
        let mut reports = Vec::new();

        for expected in &profile.expected_pcrs {
            if let Some(actual_measurement) = actual_pcrs.get(expected.semantic) {
                if actual_measurement.digest != expected.expected_digest {

                    // Check if it is an authorized transition (upgrade)
                    let is_upgrade = if let Some(upgrade) = upgrade_baseline {
                        let profile_baseline = PcrBaseline {
                            baseline_id: profile.profile_id.clone(),
                            version: profile.policy_epoch,
                            measurements: profile.expected_pcrs.clone(),
                            created_at: 0,
                            supersedes: None,
                        };

                        if upgrade.is_valid_successor(&profile_baseline) {
                            if let Some(upgrade_expected) = upgrade.measurements.iter().find(|m| m.semantic == expected.semantic) {
                                upgrade_expected.expected_digest == actual_measurement.digest
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    let severity = match expected.semantic {
                        PcrSemantic::Firmware | PcrSemantic::Kernel => {
                            if is_upgrade {
                                DriftSeverity::Warning
                            } else {
                                DriftSeverity::Critical
                            }
                        }
                        PcrSemantic::Bootloader => {
                            if is_upgrade {
                                DriftSeverity::Informational
                            } else {
                                DriftSeverity::Warning
                            }
                        }
                        _ => DriftSeverity::Informational,
                    };

                    reports.push(DriftReport {
                        expected: expected.expected_digest,
                        actual: actual_measurement.digest,
                        semantic: expected.semantic,
                        severity,
                    });
                }
            } else {
                reports.push(DriftReport {
                    expected: expected.expected_digest,
                    actual: TypedDigest::new(expected.expected_digest.algorithm, [0; 32]),
                    semantic: expected.semantic,
                    severity: DriftSeverity::Critical,
                });
            }
        }

        reports
    }
}
