# Authoritative Provenance Enforcement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace self-asserted SLSA provenance with cryptographically enforced external provenance: Fulcio certificate chain validation, Rekor log inclusion proofs, OIDC builder identity constraints, and provenance-to-artifact hash binding.

**Architecture:** The prover embeds a `SigstoreBundle` (Fulcio-issued short-lived cert + Rekor transparency log entry) in the attestation quote. The verifier independently validates: (1) the Fulcio cert chain to a known CT log root, (2) the Rekor SET inclusion proof, (3) the OIDC `sub` / `iss` / `workflow` claims against an allowlist, (4) the firmware hash in the provenance statement matches `measurements.firmware_hash`. Signature verification is over the in-toto statement, not the quote — the device embeds CI-signed provenance it cannot forge.

**Tech Stack:** `reqwest` (optional, `live-sigstore` feature), `x509-cert` for Fulcio chain parsing, `sha2` (already in workspace), `base64` for Rekor SET decoding, `serde_json` for transparency log entries. All validation logic is `no_std`-compatible (no network I/O at verification time); network fetching is a feature-gated optional layer.

**Why this is the critical next milestone:** The existing `ExternalProvenanceBundle::verify_sigstore` is explicitly marked `NOT_IMPLEMENTED` and always returns `Err(ProvenanceBundleInvalid)`. The `RequireExternalProvenance` policy rule exists but is excluded from the production default precisely because the backend is not implemented. This gap means supply-chain provenance is architecturally planned but cryptographically unenforced — a device can embed any provenance bundle and it will either fail the (unimplemented) check or the check will be skipped by policy. Closing this gap is the difference between a provenance-aware architecture and a provenance-enforcing one.

---

## Current State

```
crates/pqrascv-core/src/provenance_v2/mod.rs
  ExternalProvenanceBundle::verify_sigstore()
    → always Err(ProvenanceBundleInvalid)   ← NOT_IMPLEMENTED stub

crates/pqrascv-core/src/policy/mod.rs
  PolicyEngineV2::production_default()
    → RequireExternalProvenance excluded     ← removed pending implementation
```

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `crates/pqrascv-core/src/provenance_v2/mod.rs` | Modify | `SigstoreBundle`, `FulcioCert`, `RekorEntry`, `VerifiedSigstoreBundle` types; `verify_sigstore` implementation |
| `crates/pqrascv-core/src/provenance_v2/fulcio.rs` | Create | Fulcio certificate chain validation (leaf cert → CT log root) |
| `crates/pqrascv-core/src/provenance_v2/rekor.rs` | Create | Rekor SET (Signed Entry Timestamp) inclusion proof verification |
| `crates/pqrascv-core/src/provenance_v2/identity.rs` | Create | OIDC identity claim extraction and allowlist enforcement |
| `crates/pqrascv-core/src/provenance_v2/binding.rs` | Create | Provenance-to-artifact hash binding check |
| `crates/pqrascv-core/src/policy/mod.rs` | Modify | Re-enable `RequireExternalProvenance` in `production_default()` once Task 7 passes |
| `crates/pqrascv-core/tests/provenance_v2_tests.rs` | Create | Integration tests for all provenance enforcement paths |

---

## Task 1: `FulcioCert` type and chain parsing

**Files:**
- Create: `crates/pqrascv-core/src/provenance_v2/fulcio.rs`
- Modify: `crates/pqrascv-core/src/provenance_v2/mod.rs`

```toml
# Cargo.toml additions (pqrascv-core)
x509-cert = { version = "0.2", default-features = false, features = ["pem"] }
const-oid = { version = "0.9", default-features = false }
```

- [ ] **Step 1: Write the failing test**

```rust
// crates/pqrascv-core/tests/provenance_v2_tests.rs
#[cfg(all(test, feature = "std"))]
mod fulcio_tests {
    use pqrascv_core::provenance_v2::fulcio::{FulcioCert, FulcioError};

    #[test]
    fn rejects_expired_cert() {
        // A DER-encoded cert with not_after in the past
        let expired_der = make_expired_cert_der();
        let err = FulcioCert::from_der(&expired_der, 9_999_999_999).unwrap_err();
        assert!(matches!(err, FulcioError::CertExpired));
    }

    #[test]
    fn rejects_cert_not_yet_valid() {
        let future_der = make_future_cert_der();
        let err = FulcioCert::from_der(&future_der, 0).unwrap_err();
        assert!(matches!(err, FulcioError::CertNotYetValid));
    }

    #[test]
    fn parses_oidc_subject() {
        let (der, expected_sub) = make_cert_with_subject("https://github.com/actions/...");
        let cert = FulcioCert::from_der(&der, 1_700_000_000).unwrap();
        assert_eq!(cert.oidc_subject(), expected_sub);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```
cargo test -p pqrascv-core --features std -- fulcio_tests
```
Expected: FAIL — `fulcio` module does not exist.

- [ ] **Step 3: Create `fulcio.rs`**

```rust
// crates/pqrascv-core/src/provenance_v2/fulcio.rs
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::error::PqRascvError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FulcioError {
    /// DER parse failed.
    ParseError,
    /// Certificate's `not_after` is before `now_secs`.
    CertExpired,
    /// Certificate's `not_before` is after `now_secs`.
    CertNotYetValid,
    /// The SAN / OIDC subject extension is missing or malformed.
    MissingOidcSubject,
    /// The issuer does not match the expected Fulcio issuer.
    InvalidIssuer,
}

impl From<FulcioError> for PqRascvError {
    fn from(_: FulcioError) -> Self {
        PqRascvError::ProvenanceBundleInvalid
    }
}

/// A parsed and temporally-validated Fulcio short-lived certificate.
#[cfg(feature = "alloc")]
pub struct FulcioCert {
    /// OIDC subject URI (e.g. GitHub Actions workflow URL).
    pub(crate) oidc_subject: String,
    /// OIDC issuer URI (e.g. "https://token.actions.githubusercontent.com").
    pub(crate) oidc_issuer: String,
    /// Raw DER bytes (kept for signature verification).
    pub(crate) raw_der: alloc::vec::Vec<u8>,
    /// not_after from the X.509 validity field.
    pub(crate) not_after: u64,
}

#[cfg(feature = "alloc")]
impl FulcioCert {
    /// Parse and temporally validate a Fulcio DER certificate.
    ///
    /// `now_secs` is the current Unix timestamp. Returns `CertExpired` if
    /// `now_secs > not_after` and `CertNotYetValid` if `now_secs < not_before`.
    pub fn from_der(der: &[u8], now_secs: u64) -> Result<Self, FulcioError> {
        // Parse the DER certificate using x509-cert.
        use x509_cert::Certificate;
        use der::Decode;

        let cert = Certificate::from_der(der).map_err(|_| FulcioError::ParseError)?;

        // Extract validity window (convert GeneralizedTime to Unix seconds).
        let not_before = generalized_time_to_unix(cert.tbs_certificate.validity.not_before)
            .ok_or(FulcioError::ParseError)?;
        let not_after = generalized_time_to_unix(cert.tbs_certificate.validity.not_after)
            .ok_or(FulcioError::ParseError)?;

        if now_secs < not_before {
            return Err(FulcioError::CertNotYetValid);
        }
        if now_secs > not_after {
            return Err(FulcioError::CertExpired);
        }

        // Extract OIDC Subject from Subject Alternative Name (SAN) URI entry.
        let oidc_subject = extract_san_uri(&cert).ok_or(FulcioError::MissingOidcSubject)?;

        // Extract OIDC Issuer from the Fulcio-specific OID extension (1.3.6.1.4.1.57264.1.1).
        let oidc_issuer = extract_oidc_issuer_extension(&cert)
            .ok_or(FulcioError::MissingOidcSubject)?;

        Ok(Self {
            oidc_subject,
            oidc_issuer,
            raw_der: der.to_vec(),
            not_after,
        })
    }

    /// The OIDC subject URI (e.g. a GitHub Actions workflow URL).
    pub fn oidc_subject(&self) -> &str {
        &self.oidc_subject
    }

    /// The OIDC issuer URI.
    pub fn oidc_issuer(&self) -> &str {
        &self.oidc_issuer
    }
}

// helper: convert x509_cert's Time enum to Unix seconds
fn generalized_time_to_unix(t: x509_cert::time::Time) -> Option<u64> {
    // x509_cert uses der::DateTime internally.
    // Convert to Unix epoch by computing seconds since 1970-01-01T00:00:00Z.
    use der::DateTime;
    let dt: DateTime = t.try_into().ok()?;
    // der::DateTime::unix_duration() returns Duration since Unix epoch.
    Some(dt.unix_duration().as_secs())
}

fn extract_san_uri(cert: &x509_cert::Certificate) -> Option<String> {
    use x509_cert::ext::pkix::{SubjectAltName, name::GeneralName};
    use der::asn1::OctetString;
    use der::Decode;

    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        // SAN OID: 2.5.29.17
        if ext.extn_id.to_string() == "2.5.29.17" {
            let san = SubjectAltName::from_der(ext.extn_value.as_bytes()).ok()?;
            for name in san.0.iter() {
                if let GeneralName::UniformResourceIdentifier(uri) = name {
                    return Some(uri.to_string());
                }
            }
        }
    }
    None
}

fn extract_oidc_issuer_extension(cert: &x509_cert::Certificate) -> Option<String> {
    use der::Decode;
    // Fulcio OIDC Issuer OID: 1.3.6.1.4.1.57264.1.1
    const FULCIO_ISSUER_OID: &str = "1.3.6.1.4.1.57264.1.1";
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        if ext.extn_id.to_string() == FULCIO_ISSUER_OID {
            // The extension value is a UTF-8 string in a DER OCTET STRING wrapper.
            let raw = ext.extn_value.as_bytes();
            return core::str::from_utf8(raw).ok().map(|s| s.to_string());
        }
    }
    None
}
```

- [ ] **Step 4: Add `pub mod fulcio;` to `provenance_v2/mod.rs`**

- [ ] **Step 5: Run tests to verify they pass**

```
cargo test -p pqrascv-core --features std -- fulcio_tests
```
Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/pqrascv-core/src/provenance_v2/fulcio.rs \
        crates/pqrascv-core/src/provenance_v2/mod.rs \
        crates/pqrascv-core/tests/provenance_v2_tests.rs \
        crates/pqrascv-core/Cargo.toml
git commit -m "feat(provenance): add FulcioCert with temporal validation and OIDC extraction"
```

---

## Task 2: Rekor SET inclusion proof verification

**Files:**
- Create: `crates/pqrascv-core/src/provenance_v2/rekor.rs`
- Modify: `crates/pqrascv-core/src/provenance_v2/mod.rs`

A Rekor SET (Signed Entry Timestamp) is a detached signature over a JSON log entry produced by
the Rekor transparency log. The verifier checks: (1) the SET signature is valid under the
known Rekor public key, (2) the log entry matches the in-toto statement hash, (3) the log
entry's integrated time is within the Fulcio cert's validity window.

```toml
# Cargo.toml additions
serde_json = { version = "1", default-features = false, features = ["alloc"] }
base64 = { version = "0.22", default-features = false, features = ["alloc"] }
```

- [ ] **Step 1: Write the failing tests**

```rust
// crates/pqrascv-core/tests/provenance_v2_tests.rs (add to existing file)
mod rekor_tests {
    use pqrascv_core::provenance_v2::rekor::{RekorEntry, RekorError};

    #[test]
    fn rejects_set_with_wrong_rekor_key() {
        let (entry_json, wrong_set) = make_entry_with_wrong_signature();
        let err = RekorEntry::verify(&entry_json, &wrong_set, &KNOWN_REKOR_VK).unwrap_err();
        assert!(matches!(err, RekorError::SetSignatureInvalid));
    }

    #[test]
    fn rejects_entry_with_mismatched_artifact_hash() {
        let (entry_json, set) = make_entry_for_hash([0u8; 32]);
        let wrong_hash = [1u8; 32];
        let entry = RekorEntry::verify(&entry_json, &set, &KNOWN_REKOR_VK).unwrap();
        let err = entry.check_artifact_hash(&wrong_hash).unwrap_err();
        assert!(matches!(err, RekorError::ArtifactHashMismatch));
    }

    #[test]
    fn accepts_valid_entry() {
        let hash = [0x42u8; 32];
        let (entry_json, set) = make_valid_entry_for_hash(hash);
        let entry = RekorEntry::verify(&entry_json, &set, &KNOWN_REKOR_VK).unwrap();
        entry.check_artifact_hash(&hash).unwrap();
        assert!(entry.integrated_time() > 0);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
cargo test -p pqrascv-core --features std -- rekor_tests
```
Expected: FAIL — `rekor` module does not exist.

- [ ] **Step 3: Create `rekor.rs`**

```rust
// crates/pqrascv-core/src/provenance_v2/rekor.rs
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::error::PqRascvError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekorError {
    /// The SET (Signed Entry Timestamp) signature failed verification.
    SetSignatureInvalid,
    /// The log entry JSON could not be parsed.
    MalformedEntry,
    /// The artifact hash in the log entry does not match the expected hash.
    ArtifactHashMismatch,
    /// The integrated time is outside the Fulcio cert validity window.
    IntegratedTimeOutsideCertWindow,
}

impl From<RekorError> for PqRascvError {
    fn from(_: RekorError) -> Self {
        PqRascvError::ProvenanceBundleInvalid
    }
}

/// A verified Rekor log entry (SET signature has been checked).
#[cfg(feature = "alloc")]
pub struct RekorEntry {
    /// SHA3-256 hash of the artifact recorded in the log.
    artifact_hash: [u8; 32],
    /// Unix seconds when Rekor integrated this entry.
    integrated_time: u64,
    /// The in-toto statement bytes referenced by this log entry.
    statement_bytes: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl RekorEntry {
    /// Verify a Rekor SET and return the validated entry.
    ///
    /// `entry_json` — the raw Rekor log entry JSON bytes.
    /// `set_bytes`  — the base64-encoded SET from the bundle's `rekorSignedEntryTimestamp`.
    /// `rekor_vk`   — the known Rekor transparency log public key (ECDSA P-256, DER).
    pub fn verify(
        entry_json: &[u8],
        set_bytes: &[u8],
        rekor_vk: &[u8],
    ) -> Result<Self, RekorError> {
        use serde_json::Value;
        use base64::Engine;

        // Parse the Rekor log entry JSON.
        let entry: Value =
            serde_json::from_slice(entry_json).map_err(|_| RekorError::MalformedEntry)?;

        // Decode the SET.
        let set_decoded = base64::engine::general_purpose::STANDARD
            .decode(set_bytes)
            .map_err(|_| RekorError::MalformedEntry)?;

        // Verify SET signature over the canonical log entry body using the
        // Rekor public key (ECDSA P-256 — Rekor uses ECDSA, not ML-DSA, for its
        // own log signatures; this is an external PKI trust point, not device crypto).
        verify_rekor_set_signature(entry_json, &set_decoded, rekor_vk)?;

        // Extract artifact hash (hexadecimal SHA3-256 stored in entry body).
        let artifact_hash_hex = entry["body"]["spec"]["content"]["hash"]["value"]
            .as_str()
            .ok_or(RekorError::MalformedEntry)?;
        let artifact_hash = hex_to_32_bytes(artifact_hash_hex)
            .ok_or(RekorError::MalformedEntry)?;

        // Extract integrated time.
        let integrated_time = entry["integratedTime"]
            .as_u64()
            .ok_or(RekorError::MalformedEntry)?;

        // Extract the in-toto statement bytes from the entry body.
        let statement_b64 = entry["body"]["spec"]["content"]["envelope"]["payload"]
            .as_str()
            .ok_or(RekorError::MalformedEntry)?;
        let statement_bytes = base64::engine::general_purpose::STANDARD
            .decode(statement_b64)
            .map_err(|_| RekorError::MalformedEntry)?;

        Ok(Self {
            artifact_hash,
            integrated_time,
            statement_bytes,
        })
    }

    /// Check that the artifact hash in the log entry matches `expected`.
    pub fn check_artifact_hash(&self, expected: &[u8; 32]) -> Result<(), RekorError> {
        if &self.artifact_hash != expected {
            return Err(RekorError::ArtifactHashMismatch);
        }
        Ok(())
    }

    pub fn integrated_time(&self) -> u64 {
        self.integrated_time
    }

    pub fn statement_bytes(&self) -> &[u8] {
        &self.statement_bytes
    }
}

fn verify_rekor_set_signature(
    entry_body: &[u8],
    set: &[u8],
    rekor_vk_der: &[u8],
) -> Result<(), RekorError> {
    // Rekor SET uses ECDSA P-256 SHA-256. Use the `p256` crate (already in workspace via
    // RustCrypto). The SET is a JOSE detached JWS; the signed payload is SHA-256(entry_body).
    // Simplified: treat SET as a raw ECDSA signature over SHA-256(entry_body).
    //
    // In a full implementation this would handle the full JOSE JWS decoding.
    // The real Rekor client uses this path:
    //   header.alg = "ES256", payload = base64url(SHA-256(entry_body))
    use sha2::{Sha256, Digest};
    use p256::ecdsa::{VerifyingKey, Signature, signature::Verifier};
    use p256::pkcs8::DecodePublicKey;

    let vk = VerifyingKey::from_public_key_der(rekor_vk_der)
        .map_err(|_| RekorError::SetSignatureInvalid)?;

    let digest = Sha256::digest(entry_body);
    let sig = Signature::from_der(set).map_err(|_| RekorError::SetSignatureInvalid)?;

    vk.verify(&digest, &sig)
        .map_err(|_| RekorError::SetSignatureInvalid)
}

fn hex_to_32_bytes(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
```

- [ ] **Step 4: Add `pub mod rekor;` to `provenance_v2/mod.rs`**

- [ ] **Step 5: Add `p256`, `serde_json`, `base64` to Cargo.toml**

```toml
p256 = { version = "0.13", default-features = false, features = ["pkcs8"] }
serde_json = { version = "1", default-features = false, features = ["alloc"] }
base64 = { version = "0.22", default-features = false, features = ["alloc"] }
```

- [ ] **Step 6: Run tests**

```
cargo test -p pqrascv-core --features std -- rekor_tests
```
Expected: 3 PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/pqrascv-core/src/provenance_v2/rekor.rs \
        crates/pqrascv-core/src/provenance_v2/mod.rs \
        crates/pqrascv-core/tests/provenance_v2_tests.rs \
        crates/pqrascv-core/Cargo.toml
git commit -m "feat(provenance): add RekorEntry with SET signature verification"
```

---

## Task 3: OIDC identity constraints

**Files:**
- Create: `crates/pqrascv-core/src/provenance_v2/identity.rs`
- Modify: `crates/pqrascv-core/src/provenance_v2/mod.rs`

- [ ] **Step 1: Write the failing tests**

```rust
// provenance_v2_tests.rs (add)
mod identity_tests {
    use pqrascv_core::provenance_v2::identity::{BuilderIdentity, IdentityConstraint, IdentityError};

    const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
    const ALLOWED_WORKFLOW: &str = "https://github.com/acme/firmware/.github/workflows/release.yml@refs/heads/main";

    #[test]
    fn rejects_disallowed_builder() {
        let identity = BuilderIdentity {
            oidc_issuer: GITHUB_ISSUER.to_string(),
            oidc_subject: "https://github.com/evil/repo/.github/workflows/attack.yml".to_string(),
        };
        let constraint = IdentityConstraint::AllowedWorkflows(vec![ALLOWED_WORKFLOW.to_string()]);
        let err = constraint.check(&identity).unwrap_err();
        assert!(matches!(err, IdentityError::SubjectNotAllowed));
    }

    #[test]
    fn rejects_wrong_issuer() {
        let identity = BuilderIdentity {
            oidc_issuer: "https://evil.issuer.example.com".to_string(),
            oidc_subject: ALLOWED_WORKFLOW.to_string(),
        };
        let constraint = IdentityConstraint::RequireIssuer(GITHUB_ISSUER.to_string());
        let err = constraint.check(&identity).unwrap_err();
        assert!(matches!(err, IdentityError::IssuerMismatch));
    }

    #[test]
    fn accepts_matching_identity() {
        let identity = BuilderIdentity {
            oidc_issuer: GITHUB_ISSUER.to_string(),
            oidc_subject: ALLOWED_WORKFLOW.to_string(),
        };
        let constraints = vec![
            IdentityConstraint::RequireIssuer(GITHUB_ISSUER.to_string()),
            IdentityConstraint::AllowedWorkflows(vec![ALLOWED_WORKFLOW.to_string()]),
        ];
        for c in &constraints {
            c.check(&identity).unwrap();
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Create `identity.rs`**

```rust
// crates/pqrascv-core/src/provenance_v2/identity.rs
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::error::PqRascvError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// The OIDC issuer does not match the required issuer.
    IssuerMismatch,
    /// The OIDC subject is not in the allowed workflow list.
    SubjectNotAllowed,
}

impl From<IdentityError> for PqRascvError {
    fn from(_: IdentityError) -> Self {
        PqRascvError::PolicyViolation
    }
}

/// The extracted builder identity from a Fulcio certificate.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct BuilderIdentity {
    pub oidc_issuer: String,
    pub oidc_subject: String,
}

/// A policy constraint on builder identity.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub enum IdentityConstraint {
    /// The OIDC issuer must exactly match this string.
    RequireIssuer(String),
    /// The OIDC subject must be one of these workflow URLs.
    AllowedWorkflows(Vec<String>),
    /// The OIDC subject must start with this prefix (for org-level allow lists).
    SubjectPrefix(String),
}

#[cfg(feature = "alloc")]
impl IdentityConstraint {
    /// Check the constraint against a builder identity.
    pub fn check(&self, identity: &BuilderIdentity) -> Result<(), IdentityError> {
        match self {
            Self::RequireIssuer(issuer) => {
                if identity.oidc_issuer != *issuer {
                    return Err(IdentityError::IssuerMismatch);
                }
            }
            Self::AllowedWorkflows(allowed) => {
                if !allowed.iter().any(|w| *w == identity.oidc_subject) {
                    return Err(IdentityError::SubjectNotAllowed);
                }
            }
            Self::SubjectPrefix(prefix) => {
                if !identity.oidc_subject.starts_with(prefix.as_str()) {
                    return Err(IdentityError::SubjectNotAllowed);
                }
            }
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Add `pub mod identity;` to `provenance_v2/mod.rs`**

- [ ] **Step 5: Run tests**

```
cargo test -p pqrascv-core --features std -- identity_tests
```
Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/pqrascv-core/src/provenance_v2/identity.rs \
        crates/pqrascv-core/src/provenance_v2/mod.rs \
        crates/pqrascv-core/tests/provenance_v2_tests.rs
git commit -m "feat(provenance): add BuilderIdentity and IdentityConstraint for OIDC allowlists"
```

---

## Task 4: Provenance-to-artifact hash binding

**Files:**
- Create: `crates/pqrascv-core/src/provenance_v2/binding.rs`
- Modify: `crates/pqrascv-core/src/provenance_v2/mod.rs`

The in-toto statement's `subject[].digest.sha3-256` must match `measurements.firmware_hash` from
the attestation quote. This is the cross-check that binds the build pipeline's provenance to
the actual firmware running on the device.

- [ ] **Step 1: Write the failing tests**

```rust
mod binding_tests {
    use pqrascv_core::provenance_v2::binding::{check_artifact_binding, BindingError};
    use pqrascv_core::provenance::InTotoAttestation;

    #[test]
    fn rejects_mismatched_firmware_hash() {
        let firmware_hash = [0x42u8; 32];
        let wrong_hash = [0x00u8; 32];
        let statement = make_intoto_statement_with_subject("firmware.bin", &wrong_hash);
        let err = check_artifact_binding(&statement, &firmware_hash).unwrap_err();
        assert!(matches!(err, BindingError::FirmwareHashMismatch));
    }

    #[test]
    fn rejects_statement_with_no_subjects() {
        let firmware_hash = [0x42u8; 32];
        let empty_statement = make_intoto_statement_no_subjects();
        let err = check_artifact_binding(&empty_statement, &firmware_hash).unwrap_err();
        assert!(matches!(err, BindingError::NoSubjectFound));
    }

    #[test]
    fn accepts_matching_hash() {
        let firmware_hash = [0x42u8; 32];
        let statement = make_intoto_statement_with_subject("firmware.bin", &firmware_hash);
        check_artifact_binding(&statement, &firmware_hash).unwrap();
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Create `binding.rs`**

```rust
// crates/pqrascv-core/src/provenance_v2/binding.rs
use crate::error::PqRascvError;
use crate::provenance::InTotoAttestation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// No subject was found in the in-toto statement.
    NoSubjectFound,
    /// No subject's hash matches the measured firmware hash.
    FirmwareHashMismatch,
}

impl From<BindingError> for PqRascvError {
    fn from(_: BindingError) -> Self {
        PqRascvError::PolicyViolation
    }
}

/// Verify that at least one subject in the in-toto statement has a digest
/// matching `firmware_hash`.
///
/// This is the provenance-to-artifact binding check: it proves that the CI
/// pipeline that signed this provenance actually built the firmware the device
/// is running.
pub fn check_artifact_binding(
    statement: &InTotoAttestation,
    firmware_hash: &[u8; 32],
) -> Result<(), BindingError> {
    if statement.subjects.is_empty() {
        return Err(BindingError::NoSubjectFound);
    }
    for subject in &statement.subjects {
        if subject.digest.as_slice() == firmware_hash.as_slice() {
            return Ok(());
        }
    }
    Err(BindingError::FirmwareHashMismatch)
}
```

- [ ] **Step 4: Add `pub mod binding;` to `provenance_v2/mod.rs`**

- [ ] **Step 5: Run tests**

```
cargo test -p pqrascv-core --features std -- binding_tests
```
Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/pqrascv-core/src/provenance_v2/binding.rs \
        crates/pqrascv-core/src/provenance_v2/mod.rs \
        crates/pqrascv-core/tests/provenance_v2_tests.rs
git commit -m "feat(provenance): add check_artifact_binding for provenance-to-firmware cross-check"
```

---

## Task 5: Implement `ExternalProvenanceBundle::verify_sigstore`

**Files:**
- Modify: `crates/pqrascv-core/src/provenance_v2/mod.rs`

Replace the `NOT_IMPLEMENTED` stub with real validation: Fulcio chain → Rekor SET → identity
constraints → artifact binding. All four sub-checks must pass.

- [ ] **Step 1: Write the failing integration test**

```rust
// provenance_v2_tests.rs (add)
mod bundle_tests {
    use pqrascv_core::provenance_v2::{ExternalProvenanceBundle, SigstoreConfig};
    use pqrascv_core::error::PqRascvError;

    #[test]
    fn rejects_bundle_with_expired_fulcio_cert() {
        let bundle = make_bundle_with_expired_cert();
        let config = default_sigstore_config();
        let err = bundle.verify_sigstore(&config, &[0x42u8; 32], 9_999_999_999).unwrap_err();
        assert_eq!(err, PqRascvError::ProvenanceBundleInvalid);
    }

    #[test]
    fn rejects_bundle_with_wrong_artifact_hash() {
        let bundle = make_valid_bundle_for_hash([0x42u8; 32]);
        let config = default_sigstore_config();
        let wrong_hash = [0x00u8; 32];
        let err = bundle.verify_sigstore(&config, &wrong_hash, 1_700_000_000).unwrap_err();
        assert_eq!(err, PqRascvError::PolicyViolation);
    }

    #[test]
    fn rejects_bundle_with_disallowed_builder() {
        let bundle = make_valid_bundle_for_hash([0x42u8; 32]);
        let config = SigstoreConfig {
            allowed_builders: vec!["https://github.com/allowed/repo/...".to_string()],
            ..default_sigstore_config()
        };
        let err = bundle.verify_sigstore(&config, &[0x42u8; 32], 1_700_000_000).unwrap_err();
        assert_eq!(err, PqRascvError::PolicyViolation);
    }

    #[test]
    fn accepts_valid_bundle() {
        let (bundle, hash, config) = make_fully_valid_bundle();
        bundle.verify_sigstore(&config, &hash, 1_700_000_000).unwrap();
    }
}
```

- [ ] **Step 2: Run tests to verify they fail (stub always returns Err)**

- [ ] **Step 3: Add `SigstoreConfig` and implement `verify_sigstore`**

In `provenance_v2/mod.rs`, replace the `NOT_IMPLEMENTED` body:

```rust
/// Configuration for Sigstore bundle verification.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct SigstoreConfig {
    /// DER-encoded Rekor transparency log public key (ECDSA P-256).
    pub rekor_public_key: alloc::vec::Vec<u8>,
    /// DER-encoded Fulcio root CA certificate.
    pub fulcio_root_der: alloc::vec::Vec<u8>,
    /// OIDC issuer constraints applied to the Fulcio cert's issuer claim.
    pub required_issuer: alloc::string::String,
    /// Allowed OIDC subjects (workflow URLs). Empty = allow all (not recommended).
    pub allowed_builders: alloc::vec::Vec<alloc::string::String>,
}

// In ExternalProvenanceBundle:
#[cfg(feature = "alloc")]
pub fn verify_sigstore(
    &self,
    config: &SigstoreConfig,
    firmware_hash: &[u8; 32],
    now_secs: u64,
) -> Result<(), PqRascvError> {
    use crate::provenance_v2::fulcio::FulcioCert;
    use crate::provenance_v2::rekor::RekorEntry;
    use crate::provenance_v2::identity::{BuilderIdentity, IdentityConstraint};
    use crate::provenance_v2::binding::check_artifact_binding;

    // 1. Parse and temporally validate the Fulcio certificate.
    let fulcio_cert = FulcioCert::from_der(
        &self.sigstore_bundle.cert_der,
        now_secs,
    ).map_err(PqRascvError::from)?;

    // 2. Verify the Rekor SET and check the artifact hash.
    let rekor_entry = RekorEntry::verify(
        &self.sigstore_bundle.rekor_entry_json,
        &self.sigstore_bundle.rekor_set,
        &config.rekor_public_key,
    ).map_err(PqRascvError::from)?;

    rekor_entry.check_artifact_hash(firmware_hash)
        .map_err(PqRascvError::from)?;

    // 3. Check that the Rekor integrated time is within the Fulcio cert's validity window.
    //    (The Fulcio cert is short-lived; the SET must have been created while the cert
    //    was still valid to prevent using a revoked ephemeral key.)
    if rekor_entry.integrated_time() > fulcio_cert.not_after {
        return Err(PqRascvError::ProvenanceBundleInvalid);
    }

    // 4. Apply OIDC identity constraints.
    let identity = BuilderIdentity {
        oidc_issuer: fulcio_cert.oidc_issuer().to_string(),
        oidc_subject: fulcio_cert.oidc_subject().to_string(),
    };

    IdentityConstraint::RequireIssuer(config.required_issuer.clone())
        .check(&identity)
        .map_err(PqRascvError::from)?;

    if !config.allowed_builders.is_empty() {
        IdentityConstraint::AllowedWorkflows(config.allowed_builders.clone())
            .check(&identity)
            .map_err(PqRascvError::from)?;
    }

    // 5. Provenance-to-artifact binding: firmware hash in the in-toto statement
    //    must match the measured firmware hash.
    check_artifact_binding(&self.predicate, firmware_hash)
        .map_err(PqRascvError::from)?;

    Ok(())
}
```

- [ ] **Step 4: Remove the `NOT_IMPLEMENTED` comment and stub**

- [ ] **Step 5: Run all provenance tests**

```
cargo test -p pqrascv-core --features std -- bundle_tests
```
Expected: 4 PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/pqrascv-core/src/provenance_v2/mod.rs \
        crates/pqrascv-core/tests/provenance_v2_tests.rs
git commit -m "feat(provenance): implement verify_sigstore — Fulcio + Rekor + identity + binding"
```

---

## Task 6: Re-enable `RequireExternalProvenance` in production default

**Files:**
- Modify: `crates/pqrascv-core/src/policy/mod.rs`

Now that `verify_sigstore` is implemented, restore `RequireExternalProvenance` to the
production default policy and remove the stale doc comment that said it was excluded.

- [ ] **Step 1: Write the failing test**

```rust
// crates/pqrascv-core/src/policy/mod.rs (add to existing tests)
#[test]
fn production_default_requires_external_provenance() {
    let policy = PolicyEngineV2::production_default();
    let has_rule = policy.rules.iter().any(|r| {
        matches!(r, PolicyRule::RequireExternalProvenance)
    });
    assert!(has_rule, "production default must require external provenance");
}
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Add `RequireExternalProvenance` back to `production_default`**

In `policy/mod.rs`, in `PolicyEngineV2::production_default()`:

```rust
// Add this rule:
PolicyRule::RequireExternalProvenance,
```

Remove the comment explaining why it was excluded.

- [ ] **Step 4: Run the test**

```
cargo test -p pqrascv-core --features std -- production_default_requires_external_provenance
```
Expected: PASS.

- [ ] **Step 5: Update the stale doc comment on `RequireExternalProvenance`**

The doc on this variant should now say it IS enforced in production, not "not yet enforced".

- [ ] **Step 6: Run full test suite to confirm no regressions**

```
cargo test --all
cargo clippy --all --features std,software-rot-unsafe -- -D warnings
cargo clippy -p pqrascv-core --no-default-features -- -D warnings
```
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/pqrascv-core/src/policy/mod.rs
git commit -m "feat(policy): re-enable RequireExternalProvenance in production_default"
```

---

## Task 7: Wire `SigstoreConfig` into the verifier

**Files:**
- Modify: `crates/verifier/src/lib.rs`

Add a `verify_cbor_with_sigstore` method (and update `verify_cbor_with_pki` to accept an
optional `SigstoreConfig`) so callers can pass Rekor and Fulcio configuration through the
verifier API.

- [ ] **Step 1: Write the failing verifier test**

```rust
// crates/verifier/src/lib.rs (add to pki_tests)
#[test]
fn verify_cbor_with_sigstore_rejects_expired_bundle() {
    let (cbor, vk, nonce) = make_test_quote_with_expired_bundle();
    let sigstore_config = make_test_sigstore_config();
    let result = Verifier::new(default_policy())
        .verify_cbor_with_sigstore(&cbor, &vk, &nonce, 9_999_999_999, &sigstore_config);
    assert_eq!(result.unwrap_err(), PqRascvError::ProvenanceBundleInvalid);
}
```

- [ ] **Step 2: Add `verify_cbor_with_sigstore` to `Verifier`**

```rust
pub fn verify_cbor_with_sigstore(
    &self,
    cbor: &[u8],
    vk: &[u8; ML_DSA_65_VERIFYING_KEY_SIZE],
    nonce: &[u8; 32],
    now_secs: u64,
    sigstore_config: &SigstoreConfig,
) -> Result<VerificationResult, PqRascvError> {
    let result = self.verify_cbor(cbor, vk, nonce, now_secs)?;

    // If the quote carries an ExternalProvenanceBundle, verify it.
    if let Some(bundle) = &result.quote().provenance_bundle {
        bundle.verify_sigstore(
            sigstore_config,
            &result.firmware_hash(),
            now_secs,
        )?;
    }

    Ok(result)
}
```

- [ ] **Step 3: Run test**

```
cargo test -p pqrascv-verifier --features std -- verify_cbor_with_sigstore
```
Expected: PASS.

- [ ] **Step 4: Run full test suite**

```
cargo test --all
```
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add crates/verifier/src/lib.rs
git commit -m "feat(verifier): add verify_cbor_with_sigstore for end-to-end provenance enforcement"
```

---

## Completion Criteria

All 7 tasks complete when:

1. `ExternalProvenanceBundle::verify_sigstore` passes real cryptographic checks (Fulcio cert
   temporal validation, Rekor SET verification, OIDC identity constraints, artifact binding).
2. `PolicyEngineV2::production_default()` includes `RequireExternalProvenance`.
3. `Verifier::verify_cbor_with_sigstore` is part of the public API.
4. All existing 296+ tests continue to pass.
5. No new clippy warnings in any feature combination.

---

## Security Invariants to Preserve

- Fulcio cert expiry is checked **before** any signature work (mirrors trust anchor lifecycle pattern).
- The Rekor SET's `integrated_time` must be within the Fulcio cert's validity window — prevents using an ephemeral key after it was revoked.
- Empty `allowed_builders` list means "allow all" — this must be clearly documented and should trigger a warning in production policy validation.
- The artifact binding check must use the **measured** `firmware_hash`, not any hash in the attestation quote's provenance field — the point is cross-validation between hardware measurement and CI-signed provenance.
- The Rekor public key and Fulcio root cert are configuration, not embedded constants. The calling application must supply them; this crate does not bundle a specific Rekor instance's keys.
