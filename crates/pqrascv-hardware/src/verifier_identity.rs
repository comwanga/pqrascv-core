//! Verifier Identity Model
//!
//! A verifier is a first-class cryptographic entity in the federated trust
//! network. Each verifier is identifiable by a certificate, scoped to a set
//! of capabilities, and auditable through transparency logs.
//!
//! # Security Properties
//!
//! - Certificates are time-bounded and must be validated before federation
//!   participation.
//! - Capabilities are declared in the certificate; verifiers may only
//!   participate in federation activities that match their declared capabilities.
//! - Signature bytes are opaque at this layer (structural validation only);
//!   cryptographic signature verification is delegated to the PKI layer.

use alloc::string::String;
use alloc::vec::Vec;

// ── VerifierCapability ────────────────────────────────────────────────────

/// Declared capability of a verifier within the federation.
///
/// Capability filtering ensures that verifiers only participate in activities
/// within their declared scope. A verifier without `PolicyAuthority` cannot
/// approve policy epochs; a verifier without `BitcoinAnchoring` cannot
/// participate in anchoring activities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum VerifierCapability {
    /// Can verify hardware-rooted attestation evidence (TPM, DICE, TDX, SEV-SNP).
    HardwareVerification,
    /// Can verify runtime integrity measurements and continuous attestation.
    RuntimeVerification,
    /// Can evaluate supply-chain provenance and firmware ancestry.
    ProvenanceVerification,
    /// Can submit and verify Bitcoin SPV anchoring proofs.
    BitcoinAnchoring,
    /// Can write to and verify transparency logs.
    TransparencyLogging,
    /// Can propose and approve federated policy epochs.
    PolicyAuthority,
}

// ── VerifierIdentity ──────────────────────────────────────────────────────

/// The stable identity of a verifier within the federated trust network.
///
/// Identity is established by a `VerifierCertificate` from a recognized
/// issuer. The `public_key` field is an opaque byte representation of the
/// verifier's public key (DER, SPKI, or application-defined encoding).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifierIdentity {
    /// Globally unique verifier identifier (e.g. a UUID or DID).
    pub verifier_id: String,
    /// Human-readable organization name for audit display.
    pub organization: String,
    /// Raw public key bytes (opaque; encoding is application-defined).
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// Set of capabilities declared for this verifier.
    pub capabilities: Vec<VerifierCapability>,
}

impl VerifierIdentity {
    /// Returns `true` if this verifier declares the given capability.
    #[must_use]
    pub fn has_capability(&self, cap: VerifierCapability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Validates the structural integrity of the identity.
    ///
    /// Returns an error if any required field is empty.
    pub fn validate_structure(&self) -> Result<(), IdentityError> {
        if self.verifier_id.is_empty() {
            return Err(IdentityError::EmptyVerifierId);
        }
        if self.public_key.is_empty() {
            return Err(IdentityError::EmptyPublicKey);
        }
        if self.capabilities.is_empty() {
            return Err(IdentityError::MissingCapabilities);
        }
        Ok(())
    }
}

// ── VerifierCertificate ───────────────────────────────────────────────────

/// A time-bounded, capability-scoped certificate for a verifier.
///
/// Certificates are issued by a recognized authority (`issued_by`) and
/// govern the verifier's participation window (`valid_from`–`valid_until`).
/// The `signature` field holds an opaque byte signature over the certificate
/// content; cryptographic verification is delegated to the PKI layer.
///
/// # Validation
///
/// All federation operations MUST call `validate(now)` before admitting a
/// certificate holder. Expired or not-yet-valid certificates are rejected.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifierCertificate {
    /// The verifier this certificate was issued to.
    pub verifier_id: String,
    /// Identifier of the issuing authority.
    pub issued_by: String,
    /// Unix seconds at which the certificate becomes valid.
    pub valid_from: u64,
    /// Unix seconds at which the certificate expires (exclusive).
    pub valid_until: u64,
    /// Capabilities granted by this certificate.
    pub capabilities: Vec<VerifierCapability>,
    /// Opaque signature bytes over the certificate content.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl VerifierCertificate {
    /// Returns `true` if this certificate is temporally valid at `now`.
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.valid_from && now < self.valid_until
    }

    /// Returns `true` if this certificate grants the specified capability.
    #[must_use]
    pub fn has_capability(&self, cap: VerifierCapability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Validates the structural integrity of the certificate.
    ///
    /// Checks non-empty fields, non-zero key, valid time range, and
    /// non-empty signature. Does NOT perform cryptographic signature
    /// verification.
    pub fn validate_structure(&self) -> Result<(), CertificateError> {
        if self.verifier_id.is_empty() {
            return Err(CertificateError::EmptyVerifierId);
        }
        if self.issued_by.is_empty() {
            return Err(CertificateError::EmptyIssuer);
        }
        if self.valid_from >= self.valid_until {
            return Err(CertificateError::InvalidTimeRange {
                valid_from: self.valid_from,
                valid_until: self.valid_until,
            });
        }
        if self.capabilities.is_empty() {
            return Err(CertificateError::MissingCapabilities);
        }
        if self.signature.is_empty() {
            return Err(CertificateError::EmptySignature);
        }
        Ok(())
    }

    /// Validates structure and temporal validity.
    pub fn validate(&self, now: u64) -> Result<(), CertificateError> {
        self.validate_structure()?;
        if now < self.valid_from {
            return Err(CertificateError::NotYetValid {
                valid_from: self.valid_from,
                now,
            });
        }
        if now >= self.valid_until {
            return Err(CertificateError::Expired {
                valid_until: self.valid_until,
                now,
            });
        }
        Ok(())
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors from verifier identity validation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IdentityError {
    /// The `verifier_id` field is empty.
    EmptyVerifierId,
    /// The `public_key` field is empty.
    EmptyPublicKey,
    /// No capabilities are declared.
    MissingCapabilities,
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyVerifierId => f.write_str("verifier identity has empty verifier_id"),
            Self::EmptyPublicKey => f.write_str("verifier identity has empty public key"),
            Self::MissingCapabilities => f.write_str("verifier identity declares no capabilities"),
        }
    }
}

/// Errors from certificate validation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CertificateError {
    /// The certificate has expired.
    Expired { valid_until: u64, now: u64 },
    /// The certificate is not yet valid.
    NotYetValid { valid_from: u64, now: u64 },
    /// The `verifier_id` field is empty.
    EmptyVerifierId,
    /// The `issued_by` field is empty.
    EmptyIssuer,
    /// The `valid_from` is not before `valid_until`.
    InvalidTimeRange { valid_from: u64, valid_until: u64 },
    /// No capabilities are granted.
    MissingCapabilities,
    /// The signature field is empty.
    EmptySignature,
}

impl core::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Expired { valid_until, now } => write!(
                f,
                "certificate expired at {valid_until}, current time {now}"
            ),
            Self::NotYetValid { valid_from, now } => write!(
                f,
                "certificate not valid until {valid_from}, current time {now}"
            ),
            Self::EmptyVerifierId => f.write_str("certificate has empty verifier_id"),
            Self::EmptyIssuer => f.write_str("certificate has empty issued_by"),
            Self::InvalidTimeRange {
                valid_from,
                valid_until,
            } => write!(
                f,
                "certificate has invalid time range: valid_from={valid_from} is not before valid_until={valid_until}"
            ),
            Self::MissingCapabilities => f.write_str("certificate grants no capabilities"),
            Self::EmptySignature => f.write_str("certificate has empty signature"),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn make_cert(valid_from: u64, valid_until: u64) -> VerifierCertificate {
        VerifierCertificate {
            verifier_id: "v1".into(),
            issued_by: "root-ca".into(),
            valid_from,
            valid_until,
            capabilities: vec![VerifierCapability::HardwareVerification],
            signature: vec![0xde, 0xad, 0xbe, 0xef],
        }
    }

    #[test]
    fn cert_valid_at_window() {
        let cert = make_cert(100, 200);
        assert!(cert.is_valid_at(100));
        assert!(cert.is_valid_at(150));
        assert!(!cert.is_valid_at(200)); // exclusive upper bound
        assert!(!cert.is_valid_at(99));
    }

    #[test]
    fn cert_validate_rejects_expired() {
        let cert = make_cert(100, 200);
        let err = cert.validate(250).unwrap_err();
        assert!(matches!(err, CertificateError::Expired { .. }));
    }

    #[test]
    fn cert_validate_rejects_not_yet_valid() {
        let cert = make_cert(500, 1000);
        let err = cert.validate(200).unwrap_err();
        assert!(matches!(err, CertificateError::NotYetValid { .. }));
    }

    #[test]
    fn cert_validate_rejects_empty_signature() {
        let cert = VerifierCertificate {
            verifier_id: "v1".into(),
            issued_by: "root-ca".into(),
            valid_from: 0,
            valid_until: 1000,
            capabilities: vec![VerifierCapability::PolicyAuthority],
            signature: vec![],
        };
        assert!(matches!(
            cert.validate_structure().unwrap_err(),
            CertificateError::EmptySignature
        ));
    }

    #[test]
    fn cert_validate_rejects_invalid_time_range() {
        let cert = VerifierCertificate {
            verifier_id: "v1".into(),
            issued_by: "root-ca".into(),
            valid_from: 200,
            valid_until: 200, // same — invalid
            capabilities: vec![VerifierCapability::HardwareVerification],
            signature: vec![1],
        };
        assert!(matches!(
            cert.validate_structure().unwrap_err(),
            CertificateError::InvalidTimeRange { .. }
        ));
    }

    #[test]
    fn identity_validate_structure() {
        let id = VerifierIdentity {
            verifier_id: "v1".into(),
            organization: "ACME".into(),
            public_key: vec![0xab, 0xcd],
            capabilities: vec![VerifierCapability::HardwareVerification],
        };
        assert!(id.validate_structure().is_ok());

        let empty_key = VerifierIdentity {
            public_key: vec![],
            ..id.clone()
        };
        assert!(matches!(
            empty_key.validate_structure().unwrap_err(),
            IdentityError::EmptyPublicKey
        ));
    }

    #[test]
    fn has_capability_check() {
        let id = VerifierIdentity {
            verifier_id: "v1".into(),
            organization: "ACME".into(),
            public_key: vec![1],
            capabilities: vec![
                VerifierCapability::HardwareVerification,
                VerifierCapability::PolicyAuthority,
            ],
        };
        assert!(id.has_capability(VerifierCapability::HardwareVerification));
        assert!(id.has_capability(VerifierCapability::PolicyAuthority));
        assert!(!id.has_capability(VerifierCapability::BitcoinAnchoring));
    }
}
