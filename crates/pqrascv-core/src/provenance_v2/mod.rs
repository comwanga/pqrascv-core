//! External provenance bundles — CI-signed, independently verifiable.
//!
//! # ⚠ NOT_IMPLEMENTED: Sigstore Verification
//!
//! [`ExternalProvenanceBundle`] is a forward-compatible type definition.
//! The `verify_sigstore()` method currently returns
//! `Err(PqRascvError::ProvenanceBundleInvalid)` unconditionally.
//!
//! `PolicyRule::RequireExternalProvenance` is intentionally absent from
//! `PolicyEngineV2::production()` until this is implemented.
//!
//! Implementing this requires integrating `sigstore-rs` (Fulcio + Rekor).
//!
//! # Trust Flow
//!
//! ```text
//! CI/CD Pipeline
//!   ├── builds firmware → firmware.bin
//!   ├── generates in-toto provenance statement
//!   ├── signs with Sigstore OIDC token (GitHub Actions / GitLab CI)
//!   │     └── Fulcio issues short-lived cert bound to OIDC identity
//!   ├── submits to Rekor transparency log → inclusion proof
//!   └── exports ExternalProvenanceBundle { predicate, sigstore_bundle }
//!
//! Device
//!   └── embeds ExternalProvenanceBundle in AttestationQuote
//!       (device signs the quote body, which includes the bundle hash)
//!
//! Verifier
//!   ├── extracts ExternalProvenanceBundle
//!   ├── verifies Sigstore bundle (Fulcio cert chain + Rekor inclusion proof)
//!   ├── verifies builder identity matches policy allowlist
//!   └── verifies firmware hash in provenance == measured firmware hash
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "alloc")]
use crate::error::PqRascvError;

// ── SigstoreBundle ────────────────────────────────────────────────────────

/// A Sigstore bundle containing a CI signature and Rekor transparency proof.
///
/// This is a simplified representation. In production, use the official
/// Sigstore bundle format (protobuf / JSON) and the `sigstore-rs` crate.
#[cfg(feature = "alloc")]
#[non_exhaustive]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SigstoreBundle {
    /// The CI provider's signature over the provenance statement bytes.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,

    /// Fulcio-issued short-lived certificate (DER-encoded X.509).
    ///
    /// Binds the signing key to an OIDC identity (e.g. GitHub Actions workflow).
    #[serde(with = "serde_bytes")]
    pub signing_cert_der: Vec<u8>,

    /// Rekor transparency log entry (JSON-encoded).
    ///
    /// Contains the log index, inclusion proof, and signed entry timestamp.
    pub rekor_entry_json: String,

    /// SHA3-256 of the provenance statement that was signed.
    ///
    /// The verifier checks this matches the actual predicate before verifying
    /// the signature, preventing substitution attacks.
    pub predicate_hash: [u8; 32],
}

// ── ExternalProvenanceBundle ──────────────────────────────────────────────

/// A CI-signed provenance bundle embedded in an attestation quote.
///
/// The device embeds this bundle verbatim — it does NOT re-sign the provenance.
/// The verifier validates the Sigstore bundle independently.
///
/// # Security Properties
///
/// - The `predicate` was signed by the CI provider, not the device.
/// - The `sigstore_bundle.rekor_entry_json` provides a transparency log proof
///   that the signature existed at a specific time.
/// - The verifier cross-checks `predicate.firmware_hash == quote.measurements.firmware_hash`
///   to bind the provenance to the actual running firmware.
#[cfg(feature = "alloc")]
#[non_exhaustive]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ExternalProvenanceBundle {
    /// The in-toto provenance predicate (SLSA v1 format).
    pub predicate: ProvenancePredicate,
    /// Sigstore bundle proving the CI provider signed this predicate.
    pub sigstore_bundle: SigstoreBundle,
}

#[cfg(feature = "alloc")]
impl ExternalProvenanceBundle {
    /// Returns the SLSA level claimed in the predicate.
    #[must_use]
    pub fn slsa_level(&self) -> u8 {
        self.predicate.slsa_level
    }

    /// Returns the builder ID URI from the predicate.
    #[must_use]
    pub fn builder_id(&self) -> &str {
        &self.predicate.builder_id
    }

    /// Returns the firmware hash from the predicate subjects.
    ///
    /// Returns `None` if no subject named `"firmware"` or `"firmware.bin"` exists.
    #[must_use]
    pub fn firmware_hash(&self) -> Option<&[u8; 32]> {
        self.predicate
            .subjects
            .iter()
            .find(|s| s.name == "firmware" || s.name == "firmware.bin")
            .map(|s| &s.digest_sha3_256)
    }

    /// Verifies that the predicate hash in the Sigstore bundle matches the
    /// actual predicate content.
    ///
    /// This must be called before trusting the Sigstore bundle's signature.
    pub fn verify_predicate_hash(&self) -> Result<(), PqRascvError> {
        use sha3::{Digest, Sha3_256};
        let mut buf = Vec::new();
        ciborium::into_writer(&self.predicate, &mut buf)
            .map_err(|_| PqRascvError::SerializationFailed)?;
        let computed: [u8; 32] = Sha3_256::digest(&buf).into();
        if computed != self.sigstore_bundle.predicate_hash {
            return Err(PqRascvError::InvalidProvenance);
        }
        Ok(())
    }

    /// Verifies the Sigstore bundle (Fulcio certificate chain + Rekor inclusion proof).
    ///
    /// # `NOT_IMPLEMENTED`
    ///
    /// Returns `Err(PqRascvError::ProvenanceBundleInvalid)` unconditionally.
    /// Requires `sigstore-rs` integration for full Fulcio + Rekor verification.
    pub fn verify_sigstore(&self) -> Result<(), crate::error::PqRascvError> {
        Err(crate::error::PqRascvError::ProvenanceBundleInvalid)
    }
}

// ── ProvenancePredicate ───────────────────────────────────────────────────

/// SLSA v1 provenance predicate (in-toto format).
///
/// This is the payload that the CI provider signs. The device embeds it
/// verbatim; the verifier validates the CI signature over it.
#[cfg(feature = "alloc")]
#[non_exhaustive]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProvenancePredicate {
    /// Must be `"https://slsa.dev/provenance/v1"`.
    pub predicate_type: String,
    /// URI of the builder (e.g. `"https://github.com/actions/runner"`).
    pub builder_id: String,
    /// Git commit SHA of the build configuration.
    pub build_config_ref: String,
    /// Unix seconds when the build started.
    pub build_started_on: u64,
    /// Unix seconds when the build finished.
    pub build_finished_on: u64,
    /// SHA3-256 of the SBOM document (all-zero if not present).
    pub sbom_hash: [u8; 32],
    /// SLSA level achieved (1–4).
    pub slsa_level: u8,
    /// Attested subjects (firmware artifacts).
    pub subjects: Vec<ProvenanceSubject>,
}

/// A subject in a provenance predicate.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProvenanceSubject {
    /// Artifact name (e.g. `"firmware.bin"`).
    pub name: String,
    /// SHA3-256 digest of the artifact.
    pub digest_sha3_256: [u8; 32],
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::error::PqRascvError;

    fn dummy_bundle() -> ExternalProvenanceBundle {
        ExternalProvenanceBundle {
            predicate: ProvenancePredicate {
                predicate_type: "https://slsa.dev/provenance/v1".to_string(),
                builder_id: "https://ci.test".to_string(),
                build_config_ref: "abc123".to_string(),
                build_started_on: 0,
                build_finished_on: 0,
                sbom_hash: [0u8; 32],
                slsa_level: 2,
                subjects: alloc::vec![],
            },
            sigstore_bundle: SigstoreBundle {
                signature: alloc::vec![],
                signing_cert_der: alloc::vec![],
                rekor_entry_json: alloc::string::String::new(),
                predicate_hash: [0u8; 32],
            },
        }
    }

    #[test]
    fn verify_sigstore_always_returns_not_implemented() {
        let bundle = dummy_bundle();
        assert!(
            matches!(
                bundle.verify_sigstore(),
                Err(PqRascvError::ProvenanceBundleInvalid)
            ),
            "verify_sigstore must fail explicitly until Sigstore integration is complete"
        );
    }
}
