//! Quote assembly — [`AttestationQuote`] and the [`generate_quote`] entry point.
//!
//! # Protocol overview
//!
//! ```text
//! Verifier                           Prover
//!    |------ Challenge { nonce } ------->|
//!    |                                   | generate_quote(rot, crypto, seed, vk, nonce, provenance)
//!    |<------ AttestationQuote (CBOR) ---|
//!    | verify signature + policy         |
//! ```
//!
//! The [`AttestationQuote`] is CBOR-encoded and ML-DSA-65 signed.  The
//! signature covers the CBOR serialisation of [`QuoteBody`] (the
//! `signature` field itself is excluded from signing input).

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use crate::{
    crypto::CryptoBackend,
    error::PqRascvError,
    measurement::{Measurements, RoT},
    provenance::InTotoAttestation,
};

// ────────────────────────────────────────────────────────────────────────────
// Protocol version
// ────────────────────────────────────────────────────────────────────────────

/// Current PQ-RASCV wire protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

// ────────────────────────────────────────────────────────────────────────────
// QuoteBody — the signed payload
// ────────────────────────────────────────────────────────────────────────────

/// The portion of [`AttestationQuote`] covered by the ML-DSA-65 signature.
///
/// Serialized to CBOR bytes, then signed.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct QuoteBody {
    /// Protocol version (currently `1`).
    pub version: u16,
    /// Unix timestamp (seconds) at quote generation time; `0` if no RTC available.
    pub timestamp: u64,
    /// 32-byte verifier-supplied nonce (replay protection).
    pub nonce: [u8; 32],
    /// Platform measurements from the Root-of-Trust.
    pub measurements: Measurements,
    /// In-toto / SLSA provenance attestation.
    pub provenance: InTotoAttestation,
    /// SHA3-256 fingerprint of the signer's ML-DSA-65 verifying key.
    pub pub_key_id: [u8; 32],
}

#[cfg(feature = "alloc")]
impl QuoteBody {
    /// Serializes the body to CBOR — this is what gets signed.
    pub fn to_cbor(&self) -> Result<Vec<u8>, PqRascvError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|_| PqRascvError::SerializationFailed)?;
        Ok(buf)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// AttestationQuote
// ────────────────────────────────────────────────────────────────────────────

/// A complete, signed PQ-RASCV attestation quote.
///
/// Wire format: CBOR.  The `signature` field is an ML-DSA-65 signature
/// over the CBOR encoding of [`QuoteBody`].
///
/// # Verification procedure
///
/// 1. Deserialise: `AttestationQuote::from_cbor(bytes)`.
/// 2. Reproduce signing input: `quote.body.to_cbor()`.
/// 3. Verify: `backend.verify(&body_cbor, &verifying_key, &quote.signature)`.
/// 4. Check `body.pub_key_id == SHA3-256(verifying_key)`.
/// 5. Apply [`PolicyConfig`](crate::config::PolicyConfig).
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AttestationQuote {
    /// Signed payload.
    pub body: QuoteBody,
    /// ML-DSA-65 signature over the CBOR encoding of `body`.
    /// Serialized as a CBOR byte string.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl AttestationQuote {
    /// Serializes the complete quote to CBOR bytes, ready to send over the wire.
    pub fn to_cbor(&self) -> Result<Vec<u8>, PqRascvError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|_| PqRascvError::SerializationFailed)?;
        Ok(buf)
    }

    /// Deserializes an [`AttestationQuote`] from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, PqRascvError> {
        ciborium::from_reader(bytes).map_err(|_| PqRascvError::DeserializationFailed)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Challenge
// ────────────────────────────────────────────────────────────────────────────

/// Challenge message sent from verifier to prover.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Challenge {
    /// Cryptographically random nonce; prevents replay attacks.
    pub nonce: [u8; 32],
    /// Optional opaque policy identifier.
    pub policy_id: Option<alloc::string::String>,
}

#[cfg(feature = "alloc")]
impl Challenge {
    /// Creates a new challenge from a random nonce.
    #[must_use]
    pub fn new(nonce: [u8; 32]) -> Self {
        Self {
            nonce,
            policy_id: None,
        }
    }

    /// Attaches a policy identifier.
    #[must_use]
    pub fn with_policy(mut self, policy_id: impl Into<alloc::string::String>) -> Self {
        self.policy_id = Some(policy_id.into());
        self
    }
}

// ────────────────────────────────────────────────────────────────────────────
// generate_quote — public entry point
// ────────────────────────────────────────────────────────────────────────────

/// Generates a complete, signed [`AttestationQuote`].
///
/// This is the primary entry point for the prover.
///
/// # Arguments
///
/// - `rot`: collects platform measurements.
/// - `crypto`: ML-DSA-65 signing/verification backend.
/// - `signing_seed`: 32-byte ML-DSA-65 seed (kept secret; expanded internally).
/// - `verifying_key`: 1952-byte encoded verifying key (public).
/// - `nonce`: 32-byte verifier challenge from [`Challenge`].
/// - `provenance`: in-toto / SLSA attestation.
/// - `timestamp`: Unix seconds (`0` on platforms without a real-time clock).
///
/// # Security
///
/// `signing_seed` must be zeroized by the caller after this call returns.
/// Use [`SigningKeySeed`](crate::crypto::SigningKeySeed) for automatic zeroization.
#[cfg(feature = "alloc")]
pub fn generate_quote<R: RoT, C: CryptoBackend>(
    rot: &R,
    crypto: &C,
    signing_seed: &[u8],
    verifying_key: &[u8],
    nonce: &[u8; 32],
    provenance: InTotoAttestation,
    timestamp: u64,
) -> Result<AttestationQuote, PqRascvError> {
    let measurements = rot.measure()?;
    let pub_key_id = C::pub_key_id(verifying_key);

    let body = QuoteBody {
        version: PROTOCOL_VERSION,
        timestamp,
        nonce: *nonce,
        measurements,
        provenance,
        pub_key_id,
    };

    let body_cbor = body.to_cbor()?;
    let sig = crypto.sign(&body_cbor, signing_seed)?;

    Ok(AttestationQuote {
        body,
        signature: sig.as_ref().to_vec(),
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::{
        crypto::{generate_ml_dsa_keypair, MlDsaBackend},
        measurement::SoftwareRoT,
        provenance::SlsaPredicateBuilder,
    };

    fn test_provenance() -> InTotoAttestation {
        SlsaPredicateBuilder::new("https://ci.test")
            .add_subject("fw.bin", &[0xabu8; 32])
            .with_slsa_level(1)
            .build()
            .unwrap()
    }

    #[test]
    fn generate_quote_succeeds() {
        let (seed, vk) = generate_ml_dsa_keypair().unwrap();
        let rot = SoftwareRoT::new(b"test-firmware", None, 1);
        let nonce = [0x42u8; 32];

        let quote = generate_quote(
            &rot,
            &MlDsaBackend,
            seed.as_bytes(),
            &vk,
            &nonce,
            test_provenance(),
            1_700_000_000,
        )
        .unwrap();

        assert_eq!(quote.body.version, PROTOCOL_VERSION);
        assert_eq!(quote.body.nonce, nonce);
        assert_eq!(
            quote.signature.len(),
            crate::crypto::ML_DSA_65_SIGNATURE_SIZE
        );
    }

    #[test]
    fn quote_cbor_roundtrip() {
        let (seed, vk) = generate_ml_dsa_keypair().unwrap();
        let rot = SoftwareRoT::new(b"fw", None, 0);

        let original = generate_quote(
            &rot,
            &MlDsaBackend,
            seed.as_bytes(),
            &vk,
            &[0x01u8; 32],
            test_provenance(),
            0,
        )
        .unwrap();

        let cbor = original.to_cbor().unwrap();
        let decoded = AttestationQuote::from_cbor(&cbor).unwrap();

        assert_eq!(original.body.nonce, decoded.body.nonce);
        assert_eq!(original.signature, decoded.signature);
    }

    #[test]
    fn quote_signature_verifies() {
        let (seed, vk) = generate_ml_dsa_keypair().unwrap();
        let rot = SoftwareRoT::new(b"fw", None, 0);

        let quote = generate_quote(
            &rot,
            &MlDsaBackend,
            seed.as_bytes(),
            &vk,
            &[0x99u8; 32],
            test_provenance(),
            0,
        )
        .unwrap();

        let body_cbor = quote.body.to_cbor().unwrap();
        MlDsaBackend
            .verify(&body_cbor, &vk, &quote.signature)
            .expect("signature must verify");
    }
}
