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
    /// The Rekor entry body does not bind to the expected predicate hash, signature,
    /// or signing certificate — the entry references a different artifact.
    ContentBindingMismatch,
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

        let entry: Value =
            serde_json::from_str(entry_json).map_err(|_| RekorError::MalformedEntry)?;

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
/// Real Rekor SETs are DER-encoded ECDSA P-256 signatures (the `p256/der`
/// feature enables this path). PQ-RASCV test bundles use raw fixed-size r||s
/// (64 bytes). Both are accepted: DER is tried first; raw r||s is the fallback.
///
/// The signed message is the raw `entry_json` bytes; SHA-256 is applied
/// internally by the P-256 verifier.
#[cfg(feature = "alloc")]
fn verify_set_signature(
    entry_json: &[u8],
    set_bytes: &[u8],
    rekor_vk_der: &[u8],
) -> Result<(), RekorError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let vk =
        VerifyingKey::from_public_key_der(rekor_vk_der).map_err(|_| RekorError::InvalidRekorKey)?;

    // Try DER-encoded ECDSA first (real Rekor SET wire format, starts with 0x30).
    // Fall back to raw fixed-size r||s (64 bytes) for PQ-RASCV test bundles.
    let sig: Signature = ecdsa::der::Signature::<p256::NistP256>::try_from(set_bytes)
        .ok()
        .and_then(|ds| Signature::try_from(ds).ok())
        .or_else(|| Signature::try_from(set_bytes).ok())
        .ok_or(RekorError::SetSignatureInvalid)?;

    vk.verify(entry_json, &sig)
        .map_err(|_| RekorError::SetSignatureInvalid)
}

/// Verify that the Rekor entry body binds to (`predicate_hash`, `signature`,
/// `signing_cert_der`).
///
/// The `body` field in a Rekor entry is a base64-encoded hashedrekord JSON.
/// This function decodes the body and checks three fields inside the
/// `spec` object against the values in the Sigstore bundle, ensuring an
/// attacker cannot substitute a valid Rekor entry for a different artifact.
///
/// Expected body shape:
/// ```json
/// {
///   "apiVersion": "0.0.1",
///   "kind": "hashedrekord",
///   "spec": {
///     "data": { "hash": { "algorithm": "sha3-256", "value": "<hex>" } },
///     "signature": {
///       "content": "<base64(signature)>",
///       "publicKey": { "content": "<base64(signing_cert_der)>" }
///     }
///   }
/// }
/// ```
#[cfg(feature = "alloc")]
pub(crate) fn verify_content_binding(
    entry_json: &str,
    predicate_hash: &[u8; 32],
    signature: &[u8],
    signing_cert_der: &[u8],
) -> Result<(), RekorError> {
    use base64::Engine;
    use serde_json::Value;

    let b64 = base64::engine::general_purpose::STANDARD;

    let entry: Value =
        serde_json::from_str(entry_json).map_err(|_| RekorError::MalformedEntry)?;

    // Decode the base64-encoded hashedrekord body.
    let body_b64 = entry["body"].as_str().ok_or(RekorError::MalformedEntry)?;
    let body_bytes = b64.decode(body_b64).map_err(|_| RekorError::MalformedEntry)?;
    let body: Value =
        serde_json::from_slice(&body_bytes).map_err(|_| RekorError::MalformedEntry)?;

    // ── 1. Predicate hash ──
    let body_hash = body["spec"]["data"]["hash"]["value"]
        .as_str()
        .ok_or(RekorError::ContentBindingMismatch)?;
    let expected_hash: alloc::string::String =
        predicate_hash
            .iter()
            .fold(alloc::string::String::new(), |mut s, b| {
                use core::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            });
    if body_hash != expected_hash {
        return Err(RekorError::ContentBindingMismatch);
    }

    // ── 2. CI signature ──
    let body_sig = body["spec"]["signature"]["content"]
        .as_str()
        .ok_or(RekorError::ContentBindingMismatch)?;
    if body_sig != b64.encode(signature) {
        return Err(RekorError::ContentBindingMismatch);
    }

    // ── 3. Signing certificate ──
    let body_cert = body["spec"]["signature"]["publicKey"]["content"]
        .as_str()
        .ok_or(RekorError::ContentBindingMismatch)?;
    if body_cert != b64.encode(signing_cert_der) {
        return Err(RekorError::ContentBindingMismatch);
    }

    Ok(())
}

/// Minimal base64 (standard alphabet, padded) decoder — avoids `std`.
#[cfg(feature = "alloc")]
fn base64_decode(encoded: &str) -> Option<alloc::vec::Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()
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
        let json =
            r#"{"integratedTime": 1234567890, "verification": {"signedEntryTimestamp": "AAAA"}}"#;
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

    // ── Content-binding tests ─────────────────────────────────────────────

    fn make_body_b64(hash_hex: &str, sig_b64: &str, cert_b64: &str) -> alloc::string::String {
        use base64::Engine;
        let body = alloc::format!(
            r#"{{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{{"data":{{"hash":{{"algorithm":"sha3-256","value":"{hash_hex}"}}}},"signature":{{"content":"{sig_b64}","publicKey":{{"content":"{cert_b64}"}}}}}}}}"#
        );
        base64::engine::general_purpose::STANDARD.encode(body.as_bytes())
    }

    fn make_entry(body_b64: &str) -> alloc::string::String {
        alloc::format!(
            r#"{{"body":"{body_b64}","integratedTime":1700000000,"verification":{{"signedEntryTimestamp":"AAAA"}}}}"#
        )
    }

    fn good_entry() -> (alloc::string::String, [u8; 32], alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let hash = [0x42u8; 32];
        let sig = alloc::vec![0x01u8, 0x02, 0x03];
        let cert = alloc::vec![0xAAu8, 0xBB, 0xCC];
        let hash_hex: alloc::string::String = hash.iter().fold(alloc::string::String::new(), |mut s, b| {
            use core::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        let entry = make_entry(&make_body_b64(&hash_hex, &b64.encode(&sig), &b64.encode(&cert)));
        (entry, hash, sig, cert)
    }

    #[test]
    fn content_binding_correct_fields_pass() {
        let (entry, hash, sig, cert) = good_entry();
        verify_content_binding(&entry, &hash, &sig, &cert).unwrap();
    }

    #[test]
    fn content_binding_wrong_hash_fails() {
        let (entry, _hash, sig, cert) = good_entry();
        let wrong_hash = [0xFFu8; 32];
        let err = verify_content_binding(&entry, &wrong_hash, &sig, &cert).unwrap_err();
        assert_eq!(err, RekorError::ContentBindingMismatch);
    }

    #[test]
    fn content_binding_wrong_signature_fails() {
        let (entry, hash, _sig, cert) = good_entry();
        let wrong_sig = alloc::vec![0xDEu8, 0xAD];
        let err = verify_content_binding(&entry, &hash, &wrong_sig, &cert).unwrap_err();
        assert_eq!(err, RekorError::ContentBindingMismatch);
    }

    #[test]
    fn content_binding_wrong_cert_fails() {
        let (entry, hash, sig, _cert) = good_entry();
        let wrong_cert = alloc::vec![0xFFu8; 10];
        let err = verify_content_binding(&entry, &hash, &sig, &wrong_cert).unwrap_err();
        assert_eq!(err, RekorError::ContentBindingMismatch);
    }

    #[test]
    fn content_binding_missing_body_field_fails() {
        let entry = r#"{"integratedTime":1700000000,"verification":{"signedEntryTimestamp":"AAAA"}}"#;
        let err = verify_content_binding(entry, &[0u8; 32], &[], &[]).unwrap_err();
        assert_eq!(err, RekorError::MalformedEntry);
    }

    #[test]
    fn content_binding_body_not_valid_base64_fails() {
        let entry = r#"{"body":"not-valid-base64!!!","integratedTime":1700000000}"#;
        let err = verify_content_binding(entry, &[0u8; 32], &[], &[]).unwrap_err();
        assert_eq!(err, RekorError::MalformedEntry);
    }

    #[test]
    fn content_binding_body_not_valid_json_fails() {
        use base64::Engine;
        let bad_body = base64::engine::general_purpose::STANDARD.encode(b"not json");
        let entry = alloc::format!(r#"{{"body":"{bad_body}","integratedTime":1700000000}}"#);
        let err = verify_content_binding(&entry, &[0u8; 32], &[], &[]).unwrap_err();
        assert_eq!(err, RekorError::MalformedEntry);
    }
}
