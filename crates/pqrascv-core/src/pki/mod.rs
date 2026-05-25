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

pub mod revocation;
#[cfg(feature = "alloc")]
pub use revocation::{RevocationEntry, RevocationList, RevocationReason, VerifiedRevocationList};

pub mod trust_store;
#[cfg(feature = "alloc")]
pub use trust_store::TrustStore;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "alloc")]
use crate::crypto::{pub_key_id, ML_DSA_65_VERIFYING_KEY_SIZE};

#[cfg(feature = "alloc")]
use crate::error::PqRascvError;

#[cfg(feature = "alloc")]
use sha3::{Digest, Sha3_256};

// ── Certificate version ───────────────────────────────────────────────────

/// Current PQ-RASCV certificate format version.
pub const CERT_VERSION: u8 = 3;

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
    /// This certificate's own subject identifier URI.
    /// Must match the `issuer_id` of any certificate this cert signs.
    #[serde(default)]
    pub self_id: String,
    /// Maximum CA depth allowed below this certificate's subject key.
    /// `Some(0)` = leaf (device cert, cannot sign further certs).
    /// `None` = no constraint.
    #[serde(default)]
    pub max_path_length: Option<u8>,
    /// ML-DSA-65 signature by the issuing CA over the TBS (to-be-signed) fields.
    #[serde(with = "serde_bytes")]
    pub issuer_signature: Vec<u8>,
}

/// Constructs a [`DeviceCertificate`] with all fields explicitly supplied.
///
/// Available under `software-rot-unsafe` to allow test code in external crates
/// to bypass the `#[non_exhaustive]` restriction.
#[cfg(all(feature = "alloc", feature = "software-rot-unsafe"))]
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_device_certificate(
    version: u8,
    serial: String,
    issuer_id: String,
    not_before: u64,
    not_after: u64,
    subject_key: Vec<u8>,
    subject_key_id: [u8; 32],
    hardware_identity: HardwareIdentity,
    fw_policy: Option<FirmwarePolicyConstraint>,
    issuer_signature: Vec<u8>,
    self_id: String,
    max_path_length: Option<u8>,
) -> DeviceCertificate {
    DeviceCertificate {
        version,
        serial,
        issuer_id,
        not_before,
        not_after,
        subject_key,
        subject_key_id,
        hardware_identity,
        fw_policy,
        self_id,
        max_path_length,
        issuer_signature,
    }
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
            self_id: &self.self_id,
            max_path_length: self.max_path_length,
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
    self_id: &'a str,
    max_path_length: Option<u8>,
}

// ── CaPublicKey ───────────────────────────────────────────────────────────

/// A CA's ML-DSA-65 verifying key with its validity window.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct CaPublicKey {
    /// Raw ML-DSA-65 verifying key bytes (1952 bytes).
    pub key_bytes: [u8; ML_DSA_65_VERIFYING_KEY_SIZE],
    /// Human-readable CA identifier URI.
    pub ca_id: String,
    /// Unix seconds: this CA key becomes valid at this time.
    pub not_before: u64,
    /// Unix seconds: this CA key expires at this time.
    pub not_after: u64,
}

#[cfg(feature = "alloc")]
impl CaPublicKey {
    /// SHA3-256 fingerprint of this CA's public key.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        pub_key_id(&self.key_bytes)
    }

    /// Returns `true` if this CA key is within its valid time window at `now_secs`.
    #[must_use]
    pub fn is_valid_at(&self, now_secs: u64) -> bool {
        now_secs >= self.not_before && now_secs <= self.not_after
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
#[cfg(feature = "alloc")]
pub struct TrustAnchor {
    root_ca: CaPublicKey,
}

#[cfg(feature = "alloc")]
impl TrustAnchor {
    /// Creates a trust anchor from the root CA's verifying key and validity window.
    ///
    /// # Panics
    ///
    /// Panics if `root_ca.ca_id` is empty or if `root_ca.not_before > root_ca.not_after`.
    #[must_use]
    pub fn new(root_ca: CaPublicKey) -> Self {
        assert!(
            !root_ca.ca_id.is_empty(),
            "TrustAnchor ca_id must not be empty"
        );
        assert!(
            root_ca.not_before <= root_ca.not_after,
            "TrustAnchor not_before must not exceed not_after"
        );
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

    /// Returns the root CA identifier URI.
    #[must_use]
    pub fn ca_id(&self) -> &str {
        &self.root_ca.ca_id
    }

    /// Returns `true` if this trust anchor is within its valid time window at `now_secs`.
    #[must_use]
    pub fn is_valid_at(&self, now_secs: u64) -> bool {
        self.root_ca.is_valid_at(now_secs)
    }

    /// Returns the Unix timestamp at which this anchor becomes valid.
    #[must_use]
    pub fn not_before(&self) -> u64 {
        self.root_ca.not_before
    }

    /// Returns the Unix timestamp after which this anchor must not be used.
    #[must_use]
    pub fn not_after(&self) -> u64 {
        self.root_ca.not_after
    }
}

// ── TrustAnchorInfo ───────────────────────────────────────────────────────

/// Metadata about the trust anchor that validated a certificate chain.
///
/// Embedded in [`CertChain`] so verification results carry full audit context.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct TrustAnchorInfo {
    /// CA identifier URI (matches `CaPublicKey::ca_id`).
    pub ca_id: String,
    /// SHA3-256 fingerprint of the root CA's public key.
    pub fingerprint: [u8; 32],
    /// Unix seconds: anchor becomes valid at this time.
    pub not_before: u64,
    /// Unix seconds: anchor expires at this time.
    pub not_after: u64,
}

// ── CertChain ─────────────────────────────────────────────────────────────

/// A validated certificate chain: root CA → [intermediate CAs] → device cert.
///
/// Constructed by [`validate_chain`]; cannot be constructed directly.
/// Holding a `CertChain` is proof that the chain was valid at construction time.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct CertChain {
    /// The validated device certificate at the leaf.
    pub device_cert: DeviceCertificate,
    /// Intermediate CA certificates (root-to-leaf order, excluding root).
    pub intermediates: Vec<DeviceCertificate>,
    /// Metadata about the trust anchor that validated this chain.
    pub trust_anchor: TrustAnchorInfo,
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
/// 1. The trust anchor is temporally valid at `now_secs`.
/// 2. Each certificate's format version equals [`CERT_VERSION`].
/// 3. Each certificate's `issuer_id` matches the identity of the cert above it.
/// 4. Each certificate's `issuer_signature` is valid under the previous cert's key
///    (or the root CA key for the first intermediate).
/// 5. Each certificate in the chain is temporally valid at `now_secs`.
/// 6. CA path-length constraints (`max_path_length`) are honoured.
/// 7. The chain terminates at the trust anchor's root CA.
///
/// # Errors
///
/// Returns [`PqRascvError::TrustAnchorExpired`] if the trust anchor is outside
/// its valid time window, [`PqRascvError::CertificateInvalid`] for structural/
/// policy failures, and [`PqRascvError::VerificationFailed`] for cryptographic
/// failures.
///
/// # Panics
///
/// Panics if the internal issuer-ID list is empty (invariant: always has at
/// least the root CA entry).
#[cfg(feature = "alloc")]
pub fn validate_chain(
    device_cert: DeviceCertificate,
    intermediates: Vec<DeviceCertificate>,
    trust_anchor: &TrustAnchor,
    now_secs: u64,
) -> Result<CertChain, PqRascvError> {
    use crate::crypto::{CryptoBackend, MlDsaBackend, SIGNING_CONTEXT_CERT};

    // Root CA temporal validation — fail-closed before any other work.
    if !trust_anchor.root_ca.is_valid_at(now_secs) {
        return Err(PqRascvError::TrustAnchorExpired);
    }

    // Build signing key sequence: [root_key, int[0].subject_key, int[1].subject_key, ...]
    let mut signing_keys: Vec<Vec<u8>> = Vec::with_capacity(intermediates.len() + 1);
    signing_keys.push(trust_anchor.root_key_bytes().to_vec());
    for int in &intermediates {
        signing_keys.push(int.subject_key.clone());
    }

    // Build expected issuer ID sequence: root_ca.ca_id, int[0].self_id, int[1].self_id, ...
    let mut issuer_ids: Vec<String> = Vec::with_capacity(intermediates.len() + 1);
    issuer_ids.push(trust_anchor.root_ca.ca_id.clone());
    for int in &intermediates {
        issuer_ids.push(int.self_id.clone());
    }

    // Validate each intermediate
    for (d, intermediate) in intermediates.iter().enumerate() {
        // Version check
        if intermediate.version != CERT_VERSION {
            return Err(PqRascvError::CertificateInvalid);
        }

        // Issuer binding: cert's issuer_id must match the identity of the cert above it
        if intermediate.issuer_id != issuer_ids[d] {
            return Err(PqRascvError::CertificateInvalid);
        }

        // Path length: the signer at level d may constrain how deep the chain goes below it.
        // Number of CA certificates below signer[d] = (intermediates.len() - d)
        if d > 0 {
            if let Some(max) = intermediates[d - 1].max_path_length {
                let ca_certs_below = intermediates.len() - d;
                if ca_certs_below > usize::from(max) {
                    return Err(PqRascvError::CertificateInvalid);
                }
            }
        }

        // Temporal validity
        if !intermediate.is_valid_at(now_secs) {
            return Err(PqRascvError::VerificationFailed);
        }

        // Signature verification
        let tbs = intermediate.tbs_cbor()?;
        MlDsaBackend.verify(
            &tbs,
            &signing_keys[d],
            &intermediate.issuer_signature,
            SIGNING_CONTEXT_CERT,
        )?;
    }

    // Validate device certificate
    if device_cert.version != CERT_VERSION {
        return Err(PqRascvError::CertificateInvalid);
    }

    let device_expected_issuer = issuer_ids.last().expect("issuer_ids always has root");
    if device_cert.issuer_id != *device_expected_issuer {
        return Err(PqRascvError::CertificateInvalid);
    }

    // Path length check from last intermediate
    if let Some(last_int) = intermediates.last() {
        if let Some(max) = last_int.max_path_length {
            if max == 0 {
                // Last intermediate is a leaf — it cannot sign the device cert
                return Err(PqRascvError::CertificateInvalid);
            }
        }
    }

    if !device_cert.is_valid_at(now_secs) {
        return Err(PqRascvError::VerificationFailed);
    }

    let device_tbs = device_cert.tbs_cbor()?;
    let device_signing_key = signing_keys.last().expect("always has root key");
    MlDsaBackend.verify(
        &device_tbs,
        device_signing_key,
        &device_cert.issuer_signature,
        SIGNING_CONTEXT_CERT,
    )?;

    // subject_key_id consistency
    let computed_id = {
        let mut h = Sha3_256::new();
        h.update(&device_cert.subject_key);
        let r: [u8; 32] = h.finalize().into();
        r
    };
    if computed_id != device_cert.subject_key_id {
        return Err(PqRascvError::VerificationFailed);
    }

    let trust_anchor_info = TrustAnchorInfo {
        ca_id: trust_anchor.root_ca.ca_id.clone(),
        fingerprint: trust_anchor.root_fingerprint(),
        not_before: trust_anchor.root_ca.not_before,
        not_after: trust_anchor.root_ca.not_after,
    };
    Ok(CertChain {
        device_cert,
        intermediates,
        trust_anchor: trust_anchor_info,
    })
}

/// Validates a certificate chain against any currently-valid anchor in a [`TrustStore`].
///
/// Anchors are tried in insertion order; the chain is accepted on the first match.
/// Returns [`PqRascvError::TrustAnchorExpired`] if no anchor is valid at `now_secs`,
/// or [`PqRascvError::CertificateInvalid`] if no valid anchor accepts the chain.
///
/// # Errors
///
/// Returns [`PqRascvError::TrustAnchorExpired`] when the store has no valid anchor,
/// [`PqRascvError::CertificateInvalid`] when every valid anchor rejects the chain,
/// or propagates errors from signature/CBOR operations.
#[cfg(feature = "alloc")]
pub fn validate_chain_with_store(
    device_cert: &DeviceCertificate,
    intermediates: &[DeviceCertificate],
    trust_store: &trust_store::TrustStore,
    now_secs: u64,
) -> Result<CertChain, PqRascvError> {
    let valid_anchors: Vec<&TrustAnchor> = trust_store.valid_anchors_at(now_secs).collect();

    if valid_anchors.is_empty() {
        return Err(PqRascvError::TrustAnchorExpired);
    }

    for anchor in valid_anchors {
        if let Ok(chain) = validate_chain(
            device_cert.clone(),
            intermediates.to_vec(),
            anchor,
            now_secs,
        ) {
            return Ok(chain);
        }
    }

    Err(PqRascvError::CertificateInvalid)
}

#[cfg(all(test, feature = "alloc", feature = "std"))]
mod chain_tests {
    use super::*;
    use crate::crypto::{
        generate_ml_dsa_keypair, CryptoBackend, MlDsaBackend, SIGNING_CONTEXT_CERT,
    };

    fn sign_cert(cert: &mut DeviceCertificate, signer_seed: &[u8]) {
        let tbs = cert.tbs_cbor().expect("tbs_cbor");
        let sig = MlDsaBackend
            .sign(&tbs, signer_seed, SIGNING_CONTEXT_CERT)
            .expect("sign");
        cert.issuer_signature = sig.as_ref().to_vec();
    }

    fn make_ca() -> (
        crate::crypto::SigningKeySeed,
        [u8; crate::crypto::ML_DSA_65_VERIFYING_KEY_SIZE],
    ) {
        generate_ml_dsa_keypair().unwrap()
    }

    fn make_device_cert(
        device_vk: &[u8],
        issuer_id: &str,
        self_id: &str,
        serial: &str,
        signer_seed: &[u8],
    ) -> DeviceCertificate {
        let subject_key_id = crate::crypto::pub_key_id(device_vk);
        let mut cert = DeviceCertificate {
            version: CERT_VERSION,
            serial: serial.to_string(),
            issuer_id: issuer_id.to_string(),
            not_before: 0,
            not_after: u64::MAX,
            subject_key: device_vk.to_vec(),
            subject_key_id,
            hardware_identity: HardwareIdentity::TpmEkCertHash([0u8; 32]),
            fw_policy: None,
            issuer_signature: vec![],
            self_id: self_id.to_string(),
            max_path_length: Some(0), // leaf cert
        };
        sign_cert(&mut cert, signer_seed);
        cert
    }

    #[test]
    fn valid_chain_no_intermediates() {
        let (ca_seed, ca_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
        let device_cert = make_device_cert(
            &dev_vk,
            "https://ca.test",
            "https://dev.test",
            "DEV-001",
            ca_seed.as_bytes(),
        );
        assert!(validate_chain(device_cert, vec![], &anchor, 1_000).is_ok());
    }

    #[test]
    fn issuer_mismatch_rejected() {
        let (ca_seed, ca_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
        // Wrong issuer_id (claims "https://evil.ca" instead of "https://ca.test")
        let device_cert = make_device_cert(
            &dev_vk,
            "https://evil.ca",
            "https://dev.test",
            "DEV-001",
            ca_seed.as_bytes(),
        );
        assert!(matches!(
            validate_chain(device_cert, vec![], &anchor, 1_000),
            Err(PqRascvError::CertificateInvalid)
        ));
    }

    #[test]
    fn path_length_exceeded_rejected() {
        let (root_seed, root_vk) = make_ca();
        let (int_seed, int_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: root_vk,
            ca_id: "https://root.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });

        // Intermediate with max_path_length = Some(0) — cannot sign the device cert
        let mut intermediate = make_device_cert(
            &int_vk,
            "https://root.test",
            "https://int.test",
            "INT-001",
            root_seed.as_bytes(),
        );
        intermediate.max_path_length = Some(0); // re-sign after field change
        sign_cert(&mut intermediate, root_seed.as_bytes());

        let device_cert = make_device_cert(
            &dev_vk,
            "https://int.test",
            "https://dev.test",
            "DEV-001",
            int_seed.as_bytes(),
        );

        assert!(matches!(
            validate_chain(device_cert, vec![intermediate], &anchor, 1_000),
            Err(PqRascvError::CertificateInvalid)
        ));
    }

    #[test]
    fn expired_trust_anchor_is_rejected() {
        let (ca_seed, ca_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: 999, // expired
        });
        let cert = make_device_cert(
            &dev_vk,
            "https://ca.test",
            "https://dev.test",
            "DEV-001",
            ca_seed.as_bytes(),
        );
        assert!(matches!(
            validate_chain(cert, vec![], &anchor, 1_000), // now=1000 > not_after=999
            Err(PqRascvError::TrustAnchorExpired)
        ));
    }

    #[test]
    fn not_yet_valid_trust_anchor_is_rejected() {
        let (ca_seed, ca_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 5_000, // not yet valid
            not_after: u64::MAX,
        });
        let cert = make_device_cert(
            &dev_vk,
            "https://ca.test",
            "https://dev.test",
            "DEV-001",
            ca_seed.as_bytes(),
        );
        assert!(matches!(
            validate_chain(cert, vec![], &anchor, 1_000), // now=1000 < not_before=5000
            Err(PqRascvError::TrustAnchorExpired)
        ));
    }

    #[test]
    fn intermediate_issuer_mismatch_rejected() {
        let (root_seed, root_vk) = make_ca();
        let (int_seed, int_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: root_vk,
            ca_id: "https://root.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });

        // Intermediate claims wrong issuer_id (should be "https://root.test" to match root CA)
        let mut intermediate = DeviceCertificate {
            version: CERT_VERSION,
            serial: "INT-001".to_string(),
            issuer_id: "https://evil.ca".to_string(), // wrong — should be "https://root.test"
            not_before: 0,
            not_after: u64::MAX,
            subject_key: int_vk.to_vec(),
            subject_key_id: crate::crypto::pub_key_id(&int_vk),
            hardware_identity: HardwareIdentity::TpmEkCertHash([0u8; 32]),
            fw_policy: None,
            issuer_signature: vec![],
            self_id: "https://int.test".to_string(),
            max_path_length: Some(0),
        };
        sign_cert(&mut intermediate, root_seed.as_bytes());

        let device_cert = make_device_cert(
            &dev_vk,
            "https://int.test",
            "https://dev.test",
            "DEV-001",
            int_seed.as_bytes(),
        );

        assert!(matches!(
            validate_chain(device_cert, vec![intermediate], &anchor, 1_000),
            Err(PqRascvError::CertificateInvalid)
        ));
    }

    #[test]
    fn trust_store_with_single_valid_anchor_validates_chain() {
        use super::trust_store::TrustStore;
        let (ca_seed, ca_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let store = TrustStore::new(TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        }));
        let cert = make_device_cert(
            &dev_vk,
            "https://ca.test",
            "https://dev.test",
            "DEV-001",
            ca_seed.as_bytes(),
        );
        let result = validate_chain_with_store(&cert, &[], &store, 1_000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().trust_anchor.ca_id, "https://ca.test");
    }

    #[test]
    fn trust_store_tries_all_valid_anchors() {
        use super::trust_store::TrustStore;
        // Two CAs; cert is signed by the second one
        let (_ca1_seed, ca1_vk) = make_ca();
        let (ca2_seed, ca2_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let store = TrustStore::new(TrustAnchor::new(CaPublicKey {
            key_bytes: ca1_vk,
            ca_id: "https://ca1.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        }))
        .with_rollover(TrustAnchor::new(CaPublicKey {
            key_bytes: ca2_vk,
            ca_id: "https://ca2.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        }));
        // Cert signed by CA2
        let cert = make_device_cert(
            &dev_vk,
            "https://ca2.test",
            "https://dev.test",
            "DEV-001",
            ca2_seed.as_bytes(),
        );
        let result = validate_chain_with_store(&cert, &[], &store, 1_000);
        assert!(
            result.is_ok(),
            "CA2-signed cert must be accepted by store containing CA2"
        );
        assert_eq!(result.unwrap().trust_anchor.ca_id, "https://ca2.test");
    }

    #[test]
    fn trust_store_no_valid_anchors_returns_expired() {
        use super::trust_store::TrustStore;
        let (ca_seed, ca_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let store = TrustStore::new(TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: 999, // already expired
        }));
        let cert = make_device_cert(
            &dev_vk,
            "https://ca.test",
            "https://dev.test",
            "DEV-001",
            ca_seed.as_bytes(),
        );
        assert!(matches!(
            validate_chain_with_store(&cert, &[], &store, 1_000),
            Err(PqRascvError::TrustAnchorExpired)
        ));
    }
}
