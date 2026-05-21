//! Workload Integrity Abstractions
//!
//! Provides descriptors and identity models for workloads running on
//! the platform.
//!
//! **SECURITY NOTE**: This module provides metadata abstractions only. It
//! does NOT claim workload isolation guarantees, memory shielding, or full
//! container/runtime security.

use crate::digest::TypedDigest;
use alloc::string::String;
use alloc::vec::Vec;

/// High-level identity descriptor for a running workload (e.g. Docker container, VM).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkloadIdentity {
    /// Unique identifier of the workload.
    pub workload_id: String,
    /// Cryptographic digest of the workload image/executable.
    pub image_digest: TypedDigest,
    /// Optional identifier of the supply-chain signer.
    pub signer: Option<String>,
}

/// Collected evidence of workloads executing on the platform.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkloadIntegrityEvidence {
    /// List of workloads observed on the system.
    pub workloads: Vec<WorkloadIdentity>,
}
