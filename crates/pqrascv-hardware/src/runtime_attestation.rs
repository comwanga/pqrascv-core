//! Runtime Attestation Evidence
//!
//! Provides the core evidence data structures for runtime monitoring,
//! including process/file measurements and policy epochs.

use crate::digest::TypedDigest;
use alloc::string::String;
use alloc::vec::Vec;

/// Classification of runtime measurement domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RuntimeMeasurementDomain {
    KernelModule,
    Executable,
    Library,
    Container,
    Process,
    Filesystem,
}

/// A single runtime measurement (e.g. library, module, or process).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeMeasurement {
    /// Unique identifier for the measured entity (e.g., path, PID, name).
    pub measurement_id: String,
    /// Timestamp when the measurement was taken.
    pub timestamp: u64,
    /// The domain/category of the measured target.
    pub domain: RuntimeMeasurementDomain,
    /// Cryptographic digest of the target.
    pub digest: TypedDigest,
}

/// Collected evidence of runtime state at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeAttestationEvidence {
    /// Measurements observed during this attestation interval.
    pub measurements: Vec<RuntimeMeasurement>,
    /// Strictly monotonic sequence number.
    pub sequence_number: u64,
    /// The active policy epoch this evidence is verified against.
    pub policy_epoch: u64,
}

/// Runtime-aware policy versioning representing an epoch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimePolicyEpoch {
    /// The current policy epoch counter.
    pub epoch: u64,
    /// Unix time from which this epoch is valid.
    pub valid_from: u64,
    /// The epoch this one supersedes.
    pub supersedes: Option<u64>,
}

impl RuntimePolicyEpoch {
    /// Verifies if a transition to this epoch is valid and prevents rollback attacks.
    #[must_use]
    pub fn is_valid_successor(&self, current: &Self) -> bool {
        if self.epoch <= current.epoch {
            return false; // Rollback or replay attempt
        }
        if let Some(superseded) = self.supersedes {
            if superseded != current.epoch {
                return false; // Gap or invalid sequence
            }
        }
        true
    }
}
