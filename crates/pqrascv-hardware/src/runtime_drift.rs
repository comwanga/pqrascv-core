//! Runtime Drift Analysis
//!
//! Evaluates deviations in the running state against whitelists and rolling
//! upgrades to identify anomalies and policy violations.

use crate::digest::TypedDigest;
use alloc::string::String;
use alloc::vec::Vec;

/// Severity level of an observed runtime drift.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum RuntimeDriftSeverity {
    /// Minor or expected deviation (e.g. non-critical config changes).
    Informational,
    /// Medium severity deviation (e.g. staging/rolling upgrades).
    Warning,
    /// Critical security anomaly (e.g. unknown kernel module, unapproved executable).
    Critical,
}

/// Structured details of a runtime drift anomaly.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeDriftReport {
    /// The expected cryptographic digest for this workload path/ID.
    pub expected: TypedDigest,
    /// The actual cryptographic digest observed during attestation.
    pub actual: TypedDigest,
    /// Identification of the workload/process experiencing drift.
    pub workload: String,
    /// The severity level of this drift anomaly.
    pub severity: RuntimeDriftSeverity,
}

/// Operational engine to analyze runtime drift.
pub struct RuntimeDriftEngine;

impl RuntimeDriftEngine {
    /// Compares runtime measurements against a whitelist of approved digests
    /// and a secondary list representing rolling upgrades.
    ///
    /// - An exact match in `whitelist` produces no drift.
    /// - A match in `rolling_upgrades` produces `Warning` drift.
    /// - An unknown digest produces `Critical` drift.
    #[must_use]
    pub fn detect_drift(
        actual: &[crate::runtime_attestation::RuntimeMeasurement],
        whitelist: &[TypedDigest],
        rolling_upgrades: &[TypedDigest],
    ) -> Vec<RuntimeDriftReport> {
        let mut reports = Vec::new();

        for measurement in actual {
            let is_whitelisted = whitelist.iter().any(|d| d == &measurement.digest);
            if !is_whitelisted {
                let is_rolling = rolling_upgrades.iter().any(|d| d == &measurement.digest);
                let severity = if is_rolling {
                    RuntimeDriftSeverity::Warning
                } else {
                    RuntimeDriftSeverity::Critical
                };

                let expected = whitelist.first().copied().unwrap_or_else(|| {
                    TypedDigest::new(crate::digest::DigestAlgorithm::Sha3_256, [0; 32])
                });

                reports.push(RuntimeDriftReport {
                    expected,
                    actual: measurement.digest,
                    workload: measurement.measurement_id.clone(),
                    severity,
                });
            }
        }

        reports
    }
}
