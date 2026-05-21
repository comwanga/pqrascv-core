//! Runtime Integrity Evidence
//!
//! Provides placeholders and abstractions for post-boot integrity checks,
//! such as Linux IMA (Integrity Measurement Architecture) and EVM/Appraisal.
//!
//! **WARNING**: Measured Boot provides boot-time guarantees. This module
//! is prepared for future runtime semantics but does not yet claim runtime trust.

use alloc::vec::Vec;
use crate::digest::TypedDigest;

/// Evidence of runtime integrity subsystems.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeIntegrityEvidence {
    /// Indicates whether IMA is enabled and enforcing.
    pub ima_enabled: bool,
    /// Indicates whether EVM/Appraisal is enabled.
    pub appraisal_enabled: bool,
    /// A list of runtime measurements observed (e.g., IMA log hashes).
    pub runtime_measurements: Vec<TypedDigest>,
}
