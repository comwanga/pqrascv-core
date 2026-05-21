//! Endorsement Key (EK) validation framework.
//!
//! Provides the abstraction for EK certificate chain validation against
//! manufacturer trust anchors. Actual X.509 parsing and validation should
//! be delegated to a PKI crate, but this module provides the trait and types.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

// ── EkCertChain ───────────────────────────────────────────────────────────

/// Represents a TPM Endorsement Key certificate chain.
///
/// Contains the EK certificate itself and any intermediate CAs provided
/// by the TPM NVRAM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EkCertChain {
    pub ek_cert: Vec<u8>,
    pub intermediates: Vec<Vec<u8>>,
}

impl EkCertChain {
    #[must_use]
    pub fn new(ek_cert: Vec<u8>, intermediates: Vec<Vec<u8>>) -> Self {
        Self {
            ek_cert,
            intermediates,
        }
    }
}

// ── TrustStore ────────────────────────────────────────────────────────────

/// A trust store containing manufacturer Root CAs.
pub trait ManufacturerTrustStore {
    /// Returns the expected manufacturer name (e.g. "IFX", "AMD", "INTC").
    fn manufacturer_name(&self) -> &str;

    /// Validates an EK certificate chain against the trust store.
    ///
    /// The validation must include:
    /// 1. Cryptographic chain of trust to a known root CA.
    /// 2. TPM-specific EK EKU (Extended Key Usage) validation.
    /// 3. Revocation checking (if supported).
    fn validate_ek_chain(&self, chain: &EkCertChain) -> Result<(), EkValidationError>;
}

// ── EkValidationError ─────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EkValidationError {
    /// The EK certificate could not be parsed.
    MalformedCertificate,
    /// The EK certificate is missing the required EKU.
    MissingRequiredEku,
    /// The certificate chain could not be cryptographically verified.
    UntrustedChain,
    /// The EK certificate has been revoked.
    Revoked,
    /// The manufacturer trust store does not support this certificate.
    UnknownManufacturer(String),
}

impl core::fmt::Display for EkValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedCertificate => f.write_str("malformed EK certificate"),
            Self::MissingRequiredEku => f.write_str("EK certificate missing required EKU"),
            Self::UntrustedChain => f.write_str("EK certificate chain could not be verified"),
            Self::Revoked => f.write_str("EK certificate is revoked"),
            Self::UnknownManufacturer(m) => write!(f, "unknown manufacturer: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EkValidationError {}
