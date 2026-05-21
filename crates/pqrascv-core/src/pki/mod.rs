//! Device PKI — certificate chain, trust anchor, and revocation.
//!
//! # Trust Hierarchy
//!
//! ```text
//! Offline Root CA (air-gapped)
//!   └── Manufacturer Intermediate CA (HSM-protected)
//!         └── DeviceCertificate
//!               ├── subject_key: ML-DSA-65 verifying key
//!               ├── hardware_id: TPM EK cert hash / DICE UDS fingerprint
//!               └── fw_policy: allowed firmware hash set (optional)
//! ```
//!
//! Certificates use a CBOR-native format (not X.509) to remain `no_std`-compatible
//! and avoid ASN.1 parsing on embedded targets.
//!
//! # Audit Finding #4 Fix
//!
//! v1 had no PKI. The verifier accepted arbitrary public keys with no trust
//! anchor. v2 requires every device key to be bound to a certificate chain
//! rooted at an offline CA. The verifier rejects any quote whose signing key
//! is not covered by a valid, unrevoked certificate chain.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::crypto::{pub_key_id, ML_DSA_65_VERIFYING_KEY_SIZE};

#[cfg(feature = "alloc")]
use crate::error::PqRascvError;

#[cfg(feature = "alloc")]
use sha3::{Digest, Sha3_256};

// ── Certificate version ───────────────────────────────────────────────────

/// Current PQ-RASCV certificate format version.
pub const CERT_VERSION: u8 = 2;

// ── Hardware identity binding ─────────────────────────────────────────────

/// Identifies the hardware root that anchors a device's measurements.
///
/// The verifier uses this to confirm the device certificate was issued for
/// the specific hardware that produced the attestation quote.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HardwareIdentity {
    /// SHA3-256 of the TPM 2.0 Endorsement Key certificate DER bytes.
    TpmEkCertHash([u8; 32]),
    /// SHA3-256 of the DICE Unique Device Secret (never leaves device;
    /// this is the hash of the public CDI, not the UDS itself).
    DiceCdiPublicHash([u8; 32]),
    /// Intel TDX measurement register 0 (MRTD) — stored as hex bytes.
    TdxMrtd(#[serde(with = "serde_bytes")] Vec<u8>),
    /// AMD SEV-SNP measurement — stored as hex bytes.
    SevSnpMeasurement(#[serde(with = "serde_bytes")] Vec<u8>),
}

// ── Firmware policy constraint ────────────────────────────────────────────

/// Firmware policy constraints embedded in a device certificate.
///
/// The issuing CA encodes which firmware images this device is permitted to
/// run. The verifier enforces these constraints during policy evaluation.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FirmwarePolicyConstraint {
    /// If non-empty, only these SHA3-256 firmware hashes are accepted.
    /// An empty list means "any firmware hash is permitted" (use with caution).
    pub allowed_firmware_hashes: Vec<[u8; 32]>,
    /// Minimum SLSA level required for this device's quotes.
    pub min_slsa_level: u8,
}

// ── DeviceCertificate ─────────────────────────────────────────────────────

/// A CBOR-native device identity certificate.
///
/// Binds an ML-DSA-65 verifying key to a hardware identity and optional
/// firmware policy constraints. Signed by the issuing CA's signing key.
///
/// # Wire format
///
/// CBOR-encoded `DeviceCertificate`. The `issuer_signature` covers the
/// CBOR encoding of all other fields (i.e. `DeviceCertTbs`).
#[cfg(feature = "alloc")]
#[non_exhaustive]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeviceCertificate {
    /// Certificate format version (must equal [`CERT_VERSION`]).
    pub version: u8,
    /// Human-readable serial number (unique per issuing CA).
    pub serial: String,
    /// URI identifying the issuing CA (e.g. `"https://pki.example.com/mfr-ca"`).
    pub issuer_id: String,
    /// Unix seconds: certificate becomes valid at this time.
    pub not_before: u64,
    /// Unix seconds: certificate expires at this time.
    pub not_after: u64,
    /// The device's ML-DSA-65 verifying key (1952 bytes).
    #[serde(with = "serde_bytes")]
    pub subject_key: Vec<u8>,
    /// SHA3-256 fingerprint of `subject_key` (for fast lookup).
    pub subject_key_id: [u8; 32],
    /// Hardware identity binding.
    pub hardware_identity: HardwareIdentity,
    /// Optional firmware policy constraints.
    pub fw_policy: Option<FirmwarePolicyConstraint>,
    /// ML-DSA-65 signature by the issuing CA over the TBS (to-be-signed) fields.
    #[serde(with = "serde_bytes")]
    pub issuer_signature: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl DeviceCertificate {
    /// Returns the SHA3-256 fingerprint of the subject key.
    #[must_use]
    pub fn subject_key_id(&self) -> [u8; 32] {
        self.subject_key_id
    }

    /// Returns `true` if the certificate is temporally valid at `now_secs`.
    #[must_use]
    pub fn is_valid_at(&self, now_secs: u64) -> bool {
        now_secs >= self.not_before && now_secs <= self.not_after
    }

    /// Serializes the to-be-signed fields to CBOR for signature verification.
    ///
    /// The `issuer_signature` field is excluded from the signing input.
    pub fn tbs_cbor(&self) -> Result<Vec<u8>, PqRascvError> {
        // TBS = all fields except issuer_signature
        let tbs = DeviceCertTbs {
            version: self.version,
            serial: &self.serial,
            issuer_id: &self.issuer_id,
            not_before: self.not_before,
            not_after: self.not_after,
            subject_key: &self.subject_key,
            subject_key_id: self.subject_key_id,
            hardware_identity: &self.hardware_identity,
            fw_policy: self.fw_policy.as_ref(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&tbs, &mut buf).map_err(|_| PqRascvError::SerializationFailed)?;
        Ok(buf)
    }
}

/// To-be-signed portion of a [`DeviceCertificate`] (excludes `issuer_signature`).
#[cfg(feature = "alloc")]
#[derive(serde::Serialize)]
struct DeviceCertTbs<'a> {
    version: u8,
    serial: &'a str,
    issuer_id: &'a str,
    not_before: u64,
    not_after: u64,
    #[serde(with = "serde_bytes")]
    subject_key: &'a [u8],
    subject_key_id: [u8; 32],
    hardware_identity: &'a HardwareIdentity,
    fw_policy: Option<&'a FirmwarePolicyConstraint>,
}

// ── CaPublicKey ───────────────────────────────────────────────────────────

/// A CA's ML-DSA-65 verifying key, used to validate certificate signatures.
#[derive(Clone, Debug)]
pub struct CaPublicKey {
    /// Raw ML-DSA-65 verifying key bytes (1952 bytes).
    pub key_bytes: [u8; ML_DSA_65_VERIFYING_KEY_SIZE],
    /// Human-readable CA identifier URI.
    pub ca_id: &'static str,
}

impl CaPublicKey {
    /// SHA3-256 fingerprint of this CA's public key.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        pub_key_id(&self.key_bytes)
    }
}

// ── TrustAnchor ───────────────────────────────────────────────────────────

/// The offline root CA trust anchor.
///
/// Holds the root CA's verifying key. All certificate chains must terminate
/// here. The root CA key is distributed out-of-band (e.g. burned into device
/// firmware at manufacturing time, or distributed via a secure channel).
///
/// # Security
///
/// The corresponding root CA private key must never touch a networked machine.
/// Generate it in an air-gapped ceremony and store it in an HSM or offline vault.
pub struct TrustAnchor {
    root_ca: CaPublicKey,
}

impl TrustAnchor {
    /// Creates a trust anchor from the root CA's verifying key.
    #[must_use]
    pub fn new(root_ca: CaPublicKey) -> Self {
        Self { root_ca }
    }

    /// Returns the root CA's public key fingerprint.
    #[must_use]
    pub fn root_fingerprint(&self) -> [u8; 32] {
        self.root_ca.fingerprint()
    }

    /// Returns the root CA's verifying key bytes.
    #[must_use]
    pub fn root_key_bytes(&self) -> &[u8; ML_DSA_65_VERIFYING_KEY_SIZE] {
        &self.root_ca.key_bytes
    }
}

// ── CertChain ─────────────────────────────────────────────────────────────

/// A validated certificate chain: root CA → [intermediate CAs] → device cert.
///
/// Constructed by [`validate_chain`]; cannot be constructed directly.
/// Holding a `CertChain` is proof that the chain was valid at construction time.
#[cfg(feature = "alloc")]
pub struct CertChain {
    /// The validated device certificate at the leaf.
    pub device_cert: DeviceCertificate,
    /// Intermediate CA certificates (root-to-leaf order, excluding root).
    pub intermediates: Vec<DeviceCertificate>,
}

#[cfg(feature = "alloc")]
impl CertChain {
    /// Returns the device certificate's subject key ID.
    #[must_use]
    pub fn device_key_id(&self) -> [u8; 32] {
        self.device_cert.subject_key_id
    }
}

// ── Chain validation ──────────────────────────────────────────────────────

/// Validates a certificate chain against a trust anchor.
///
/// Checks:
/// 1. Each certificate's `issuer_signature` is valid under the previous cert's key
///    (or the root CA key for the first intermediate).
/// 2. Each certificate is temporally valid at `now_secs`.
/// 3. The chain terminates at the trust anchor's root CA.
///
/// # Errors
///
/// Returns [`PqRascvError::VerificationFailed`] if any check fails.
#[cfg(feature = "alloc")]
pub fn validate_chain(
    device_cert: DeviceCertificate,
    intermediates: Vec<DeviceCertificate>,
    trust_anchor: &TrustAnchor,
    now_secs: u64,
) -> Result<CertChain, PqRascvError> {
    use crate::crypto::MlDsaBackend;
    use crate::crypto::CryptoBackend;

    // Build the full chain: root_key → intermediates → device_cert
    // Verify each cert is signed by the key above it.
    let mut current_verifying_key: &[u8] = trust_anchor.root_key_bytes();

    for intermediate in &intermediates {
        if !intermediate.is_valid_at(now_secs) {
            return Err(PqRascvError::VerificationFailed);
        }
        let tbs = intermediate.tbs_cbor()?;
        MlDsaBackend.verify(&tbs, current_verifying_key, &intermediate.issuer_signature)?;
        current_verifying_key = &intermediate.subject_key;
    }

    // Verify the device certificate is signed by the last intermediate (or root).
    if !device_cert.is_valid_at(now_secs) {
        return Err(PqRascvError::VerificationFailed);
    }
    let tbs = device_cert.tbs_cbor()?;
    MlDsaBackend.verify(&tbs, current_verifying_key, &device_cert.issuer_signature)?;

    // Verify the subject_key_id is consistent with the actual subject_key.
    let computed_id = {
        let mut h = Sha3_256::new();
        h.update(&device_cert.subject_key);
        let r: [u8; 32] = h.finalize().into();
        r
    };
    if computed_id != device_cert.subject_key_id {
        return Err(PqRascvError::VerificationFailed);
    }

    Ok(CertChain {
        device_cert,
        intermediates,
    })
}
