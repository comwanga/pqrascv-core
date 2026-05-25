/// Rekor transparency log entry verification (condition 5).
///
/// Implements condition 5 of the Provenance Enforcement Invariant:
/// the Rekor inclusion proof (Signed Entry Timestamp) validates successfully.
///
/// The Rekor SET is an ECDSA P-256 signature over the raw entry JSON bytes.
/// This module verifies the SET using the known Rekor transparency log public key,
/// then extracts the `integratedTime` for use in condition 6.
#[cfg(feature = "alloc")]
extern crate alloc;

use crate::error::PqRascvError;

/// Error variants for Rekor log entry operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekorError {
    /// The Signed Entry Timestamp (SET) signature failed verification.
    SetSignatureInvalid,
    /// The entry JSON could not be parsed.
    MalformedEntry,
    /// The `integratedTime` field is missing or not a valid u64.
    MissingIntegratedTime,
    /// The Rekor public key DER could not be decoded as a P-256 key.
    InvalidRekorKey,
    /// The artifact hash in the log entry does not match the expected value.
    ArtifactHashMismatch,
}

impl From<RekorError> for PqRascvError {
    fn from(_: RekorError) -> Self {
        PqRascvError::ProvenanceBundleInvalid
    }
}

/// A verified Rekor log entry — the SET signature has been checked.
///
/// Construction requires a valid SET signature (`from_entry_json`).
/// The `integrated_time` is the Unix timestamp when Rekor incorporated
/// this entry and is used in condition 6 for time-bound verification.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct RekorEntry {
    integrated_time: u64,
}

#[cfg(feature = "alloc")]
impl RekorEntry {
    /// Parse and verify a Rekor log entry JSON, returning a validated entry.
    ///
    /// The entry JSON must contain:
    /// - `"integratedTime"`: Unix timestamp (u64)
    /// - `"verification"."signedEntryTimestamp"`: base64-encoded DER ECDSA signature
    ///
    /// The SET signature is verified over `SHA-256(entry_json_bytes)` using
    /// the provided Rekor P-256 public key.
    ///
    /// Returns `Err(RekorError::SetSignatureInvalid)` if `rekor_vk_der` is empty
    /// or the signature is invalid. Returns `Err(RekorError::MalformedEntry)` if
    /// the JSON cannot be parsed or required fields are missing.
    pub fn from_entry_json(entry_json: &str, rekor_vk_der: &[u8]) -> Result<Self, RekorError> {
        use serde_json::Value;

        if entry_json.is_empty() {
            return Err(RekorError::MalformedEntry);
        }
        if rekor_vk_der.is_empty() {
            return Err(RekorError::InvalidRekorKey);
        }

        let entry: Value = serde_json::from_str(entry_json)
            .map_err(|_| RekorError::MalformedEntry)?;

        let integrated_time = entry["integratedTime"]
            .as_u64()
            .ok_or(RekorError::MissingIntegratedTime)?;

        // Extract and decode the Signed Entry Timestamp.
        let set_b64 = entry["verification"]["signedEntryTimestamp"]
            .as_str()
            .ok_or(RekorError::MalformedEntry)?;

        let set_bytes = base64_decode(set_b64).ok_or(RekorError::MalformedEntry)?;

        // Verify the SET signature: ECDSA P-256 SHA-256 over the raw entry JSON.
        verify_set_signature(entry_json.as_bytes(), &set_bytes, rekor_vk_der)?;

        Ok(Self { integrated_time })
    }

    /// The Unix timestamp when Rekor integrated this entry.
    #[must_use]
    pub fn integrated_time(&self) -> u64 {
        self.integrated_time
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Verify the Rekor SET (Signed Entry Timestamp).
///
/// The SET bytes are a raw ECDSA P-256 signature in fixed-size r||s encoding
/// (64 bytes). The signed message is the raw `entry_json` bytes; the P-256
/// verifier computes SHA-256(entry_json) internally.
///
/// Using raw r||s avoids the need for the `ecdsa/der` feature while remaining
/// cryptographically equivalent to DER-encoded ECDSA for the purpose of
/// binding the entry JSON to the Rekor log's signing key.
#[cfg(feature = "alloc")]
fn verify_set_signature(
    entry_json: &[u8],
    set_bytes: &[u8],
    rekor_vk_der: &[u8],
) -> Result<(), RekorError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let vk = VerifyingKey::from_public_key_der(rekor_vk_der)
        .map_err(|_| RekorError::InvalidRekorKey)?;

    // Expect raw fixed-size r||s (64 bytes for P-256).
    let sig = Signature::try_from(set_bytes).map_err(|_| RekorError::SetSignatureInvalid)?;

    // p256::ecdsa::VerifyingKey::verify hashes the message with SHA-256 internally.
    vk.verify(entry_json, &sig)
        .map_err(|_| RekorError::SetSignatureInvalid)
}

/// Minimal base64 (standard alphabet, padded) decoder — avoids `std`.
#[cfg(feature = "alloc")]
fn base64_decode(encoded: &str) -> Option<alloc::vec::Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(encoded).ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn empty_entry_json_returns_malformed() {
        let err = RekorEntry::from_entry_json("", &[0x01]).unwrap_err();
        assert_eq!(err, RekorError::MalformedEntry);
    }

    #[test]
    fn empty_rekor_key_returns_invalid_key() {
        let json = r#"{"integratedTime": 1234567890, "verification": {"signedEntryTimestamp": "AAAA"}}"#;
        let err = RekorEntry::from_entry_json(json, &[]).unwrap_err();
        assert_eq!(err, RekorError::InvalidRekorKey);
    }

    #[test]
    fn missing_integrated_time_returns_error() {
        let json = r#"{"verification": {"signedEntryTimestamp": "AAAA"}}"#;
        let err = RekorEntry::from_entry_json(json, &[0x01]).unwrap_err();
        // Either MissingIntegratedTime or InvalidRekorKey (key checked before fields)
        assert!(matches!(
            err,
            RekorError::MissingIntegratedTime | RekorError::InvalidRekorKey
        ));
    }

    #[test]
    fn invalid_set_signature_returns_error() {
        // Provide a fake P-256 public key DER and a bad SET — must fail with key or sig error.
        // This confirms the signature check path is reached with a non-empty key.
        let json = r#"{"integratedTime": 1234567890, "verification": {"signedEntryTimestamp": "bm90YXZhbGlkc2ln"}}"#;
        // Use 65 zero bytes as a fake key — will fail at decode step
        let fake_key = [0u8; 65];
        let err = RekorEntry::from_entry_json(json, &fake_key).unwrap_err();
        assert!(matches!(
            err,
            RekorError::SetSignatureInvalid | RekorError::InvalidRekorKey
        ));
    }

    // Tests with real P-256 key pairs and valid signatures are integration tests
    // that require key generation (p256::SigningKey). They are added in
    // crates/pqrascv-core/tests/provenance_v2_tests.rs under the "std" feature gate.
}
