//! PCR Baseline Management
//!
//! Provides the data structures required to track and version firmware
//! baselines, manage lifecycle evolution, and prevent malicious rollbacks.

use alloc::string::String;
use alloc::vec::Vec;
use crate::digest::TypedDigest;
use crate::pcr::PcrSemantic;

/// Versioning semantics for a policy or baseline.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PolicyVersion {
    /// Monotonically increasing epoch number. A device must never
    /// accept a policy with an epoch lower than its current state.
    pub epoch: u64,
    /// Unix timestamp of when this policy version was created.
    pub created_at: u64,
    /// The epoch this policy explicitly supersedes, if any.
    pub supersedes: Option<u64>,
}

/// An expected PCR measurement linked to its semantic meaning.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExpectedPcr {
    /// The semantic meaning of this PCR.
    pub semantic: PcrSemantic,
    /// The expected digest value.
    pub expected_digest: TypedDigest,
}

/// Represents a versioned set of expected PCR measurements for a platform.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PcrBaseline {
    /// A unique identifier for this baseline profile.
    pub baseline_id: String,
    /// The epoch or version of this baseline.
    pub version: u64,
    /// The collection of expected PCR values.
    pub measurements: Vec<ExpectedPcr>,
    /// Creation timestamp for auditing.
    pub created_at: u64,
    /// The ID of the baseline this supersedes (enables linked-list style evolution).
    pub supersedes: Option<String>,
}

impl PcrBaseline {
    /// Validates if `self` is a valid successor to `previous_baseline`.
    ///
    /// This strictly enforces anti-rollback by ensuring version monotonicity
    /// and explicit supersession tracking.
    #[must_use]
    pub fn is_valid_successor(&self, previous_baseline: &PcrBaseline) -> bool {
        if self.version <= previous_baseline.version {
            return false;
        }
        if let Some(ref supersedes) = self.supersedes {
            if supersedes != &previous_baseline.baseline_id {
                return false;
            }
        }
        true
    }
}
