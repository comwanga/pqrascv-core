//! External provenance bundles — CI-signed, independently verifiable.
//!
//! # Provenance Enforcement Invariant
//!
//! A firmware image satisfies provenance policy only when ALL of the following
//! hold simultaneously (see [`ExternalProvenanceBundle::verify_all`]):
//!
//! 1. The provenance statement is cryptographically signed.
//! 2. The signing certificate chains to a trusted Fulcio root.
//! 3. The Fulcio certificate is temporally valid at verification time.
//! 4. The OIDC identity matches an explicitly authorized identity policy.
//! 5. The Rekor entry inclusion proof validates successfully.
//! 6. The Rekor integrated time falls within acceptable trust bounds.
//! 7. The provenance artifact digest exactly matches the measured firmware hash.
//! 8. The provenance statement binds to the attested artifact without ambiguity.
//! 9. No verification step was degraded, downgraded, or soft-failed.
//! 10. All provenance checks executed in the authoritative verifier path.
//!
//! If any condition fails — provenance fails, policy fails, attestation fails.
//! No partial provenance trust states are permitted.
//!
//! The `VerifiedProvenance` type is the proof token encoding conditions 9 and 10:
//! it is only constructible inside this module, after all prior conditions have
//! passed. `PolicyContext` holds `Option<&VerifiedProvenance>` — the policy
//! engine cannot be told "provenance is fine" without the cryptographic proof.
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
//!   ├── calls bundle.verify_all(&config, &firmware_hash, now_secs)
//!   │     ├── [1] predicate hash integrity
//!   │     ├── [2] Fulcio cert chain to trusted root
//!   │     ├── [3] Fulcio cert temporal validity
//!   │     ├── [4] OIDC identity against allowlist
//!   │     ├── [5] Rekor inclusion proof
//!   │     ├── [6] Rekor integrated time bounds
//!   │     ├── [7] artifact digest == firmware_hash
//!   │     └── [8] unambiguous artifact binding
//!   └── receives VerifiedProvenance token (or Err — no partial states)
//! ```

pub mod fulcio;
pub mod identity;
pub mod rekor;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "alloc")]
use crate::error::PqRascvError;

/// Configuration required to verify a Sigstore provenance bundle.
///
/// All fields are mandatory. The verifier must supply explicit values —
/// there are no insecure defaults.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct SigstoreConfig {
    /// DER-encoded Rekor transparency log public key (ECDSA P-256).
    ///
    /// Used to verify the Signed Entry Timestamp (SET) in the Rekor bundle.
    pub rekor_public_key_der: Vec<u8>,

    /// DER-encoded Fulcio root CA certificate.
    ///
    /// The Fulcio short-lived signing certificate must chain to this root.
    pub fulcio_root_der: Vec<u8>,

    /// Required OIDC issuer URI.
    ///
    /// Example: `"https://token.actions.githubusercontent.com"`.
    /// The Fulcio certificate's issuer extension must exactly match.
    pub required_issuer: String,

    /// Explicitly authorized OIDC subject URIs (workflow URLs).
    ///
    /// An empty list means **deny all** — you must enumerate permitted
    /// builders. There is intentionally no "allow all" mode.
    pub allowed_builders: Vec<String>,

    /// Maximum allowed forward clock skew between `now_secs` and the Rekor
    /// integrated time (seconds).
    ///
    /// Rekor's integrated time must not exceed `now_secs + max_clock_skew_secs`.
    /// Set to 0 to require the entry to be in the past.
    pub max_clock_skew_secs: u64,
}

/// Proof that all 10 provenance invariant conditions have been satisfied.
///
/// This type can only be constructed by [`ExternalProvenanceBundle::verify_all`].
/// Possession of a `VerifiedProvenance` value is the authoritative proof that
/// the provenance verification was complete — no condition was skipped,
/// degraded, or soft-failed.
///
/// `PolicyContext` holds `Option<&VerifiedProvenance>`. The only way to set
/// it to `Some` is to have called `verify_all` successfully.
///
/// # Why a sealed type?
///
/// A `bool` flag for "provenance verified" is a partial trust state: it can be
/// set to `true` without any cryptographic evidence. The sealed `VerifiedProvenance`
/// type makes the partial trust state unrepresentable — the compiler rejects any
/// code that claims provenance is verified without the proof.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct VerifiedProvenance {
    /// OIDC subject URI of the CI builder that signed the provenance.
    builder_identity: String,
    /// The firmware hash that was verified against the provenance statement.
    firmware_hash: [u8; 32],
    /// Unix seconds when Rekor integrated the transparency log entry.
    rekor_integrated_time: u64,
}

#[cfg(feature = "alloc")]
impl VerifiedProvenance {
    /// Private constructor — only callable within this module.
    /// External code cannot construct a `VerifiedProvenance` directly.
    fn new(builder_identity: String, firmware_hash: [u8; 32], rekor_integrated_time: u64) -> Self {
        Self {
            builder_identity,
            firmware_hash,
            rekor_integrated_time,
        }
    }

    /// The OIDC subject URI of the CI builder that signed the provenance.
    #[must_use]
    pub fn builder_identity(&self) -> &str {
        &self.builder_identity
    }

    /// The firmware hash that was bound to this provenance statement.
    #[must_use]
    pub fn firmware_hash(&self) -> &[u8; 32] {
        &self.firmware_hash
    }

    /// Unix seconds when Rekor integrated the transparency log entry.
    #[must_use]
    pub fn rekor_integrated_time(&self) -> u64 {
        self.rekor_integrated_time
    }
}

/// A Sigstore bundle: CI signature + Rekor transparency log proof.
#[cfg(feature = "alloc")]
#[non_exhaustive]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SigstoreBundle {
    /// The CI provider's signature over the provenance statement bytes.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,

    /// Fulcio-issued short-lived certificate (DER-encoded X.509).
    ///
    /// Binds the signing key to an OIDC identity (e.g. a GitHub Actions workflow).
    #[serde(with = "serde_bytes")]
    pub signing_cert_der: Vec<u8>,

    /// Rekor transparency log entry (JSON-encoded).
    ///
    /// Contains the log index, inclusion proof, and Signed Entry Timestamp.
    pub rekor_entry_json: String,

    /// SHA3-256 of the provenance statement that was signed.
    ///
    /// Checked first (condition 1) before trusting any other bundle field.
    pub predicate_hash: [u8; 32],
}

/// A CI-signed provenance bundle embedded in an attestation quote.
///
/// The device embeds this bundle verbatim — it does NOT re-sign the provenance.
/// The verifier validates the Sigstore bundle independently via [`verify_all`].
///
/// [`verify_all`]: ExternalProvenanceBundle::verify_all
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
impl SigstoreBundle {
    /// Construct a [`SigstoreBundle`] from its constituent fields.
    #[must_use]
    pub fn new(
        signature: Vec<u8>,
        signing_cert_der: Vec<u8>,
        rekor_entry_json: String,
        predicate_hash: [u8; 32],
    ) -> Self {
        Self {
            signature,
            signing_cert_der,
            rekor_entry_json,
            predicate_hash,
        }
    }
}

#[cfg(feature = "alloc")]
impl ExternalProvenanceBundle {
    /// Construct an [`ExternalProvenanceBundle`] from a predicate and its Sigstore proof.
    #[must_use]
    pub fn new(predicate: ProvenancePredicate, sigstore_bundle: SigstoreBundle) -> Self {
        Self {
            predicate,
            sigstore_bundle,
        }
    }

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

    /// Condition 1 — The provenance statement is cryptographically signed.
    ///
    /// Verifies that the `predicate_hash` field in the Sigstore bundle is the
    /// SHA3-256 of the actual `predicate`. This must be checked first so that
    /// the signature in subsequent checks covers the genuine predicate.
    fn check_predicate_integrity(&self) -> Result<(), PqRascvError> {
        use sha3::{Digest, Sha3_256};
        let mut buf = Vec::new();
        ciborium::into_writer(&self.predicate, &mut buf)
            .map_err(|_| PqRascvError::SerializationFailed)?;
        let computed: [u8; 32] = Sha3_256::digest(&buf).into();
        if computed != self.sigstore_bundle.predicate_hash {
            return Err(PqRascvError::InvalidProvenance);
        }
        // Conditions 2–5 will verify the actual signature over this hash.
        Ok(())
    }

    /// Condition 2 — The signing certificate chains to a trusted Fulcio root.
    ///
    /// Performs two checks via [`fulcio::verify_chain`]:
    /// 1. **Structural**: the leaf cert's `issuer` DN equals the root's `subject` DN.
    /// 2. **Cryptographic**: the root CA's P-256 key produced the DER-encoded ECDSA
    ///    signature over the leaf's `TBSCertificate` bytes.
    ///
    /// Both checks must pass. A cert with the right issuer DN but an invalid CA
    /// signature is rejected.
    fn check_fulcio_chain(&self, fulcio_root_der: &[u8]) -> Result<(), PqRascvError> {
        fulcio::verify_chain(&self.sigstore_bundle.signing_cert_der, fulcio_root_der)
            .map_err(PqRascvError::from)
    }

    /// Condition 3 — The Fulcio certificate is temporally valid.
    ///
    /// Parses the Fulcio cert and verifies its validity window against `now_secs`.
    /// Also extracts the `integratedTime` from the Rekor entry JSON so that
    /// condition 6 can check the Rekor timestamp against the cert window.
    ///
    /// Returns the `integratedTime` for use in condition 6.
    fn check_fulcio_temporal(&self, now_secs: u64) -> Result<u64, PqRascvError> {
        use serde_json::Value;

        // Parse and temporally validate the Fulcio cert (this also parses the cert
        // once; condition 4 will re-parse only for OIDC claim extraction).
        let cert = fulcio::FulcioCert::from_der(&self.sigstore_bundle.signing_cert_der, now_secs)
            .map_err(PqRascvError::from)?;

        // Extract the integratedTime from the Rekor log entry JSON.
        let entry: Value = serde_json::from_str(&self.sigstore_bundle.rekor_entry_json)
            .map_err(|_| PqRascvError::ProvenanceBundleInvalid)?;
        let integrated_time = entry["integratedTime"]
            .as_u64()
            .ok_or(PqRascvError::ProvenanceBundleInvalid)?;

        // The Rekor entry must have been created while the Fulcio cert was still valid.
        if integrated_time < cert.not_before || integrated_time > cert.not_after() {
            return Err(PqRascvError::ProvenanceBundleInvalid);
        }

        Ok(integrated_time)
    }

    /// Condition 4 — The OIDC identity matches an explicitly authorized policy.
    ///
    /// Extracts the OIDC subject and issuer from the Fulcio cert (skipping
    /// temporal re-validation since condition 3 already confirmed validity).
    /// Applies `config.required_issuer` and `config.allowed_builders` checks.
    ///
    /// Returns the OIDC subject URI for embedding in [`VerifiedProvenance`].
    fn check_oidc_identity(&self, config: &SigstoreConfig) -> Result<String, PqRascvError> {
        use identity::{BuilderIdentity, IdentityConstraint};

        let (oidc_subject, oidc_issuer) =
            fulcio::FulcioCert::parse_oidc_claims(&self.sigstore_bundle.signing_cert_der)
                .map_err(PqRascvError::from)?;

        let identity = BuilderIdentity {
            oidc_issuer,
            oidc_subject,
        };

        IdentityConstraint::RequireIssuer(config.required_issuer.clone())
            .check(&identity)
            .map_err(PqRascvError::from)?;

        // Empty allowed_builders = deny all (enforced by AllowedWorkflows).
        IdentityConstraint::AllowedWorkflows(config.allowed_builders.clone())
            .check(&identity)
            .map_err(PqRascvError::from)?;

        Ok(identity.oidc_subject)
    }

    /// Condition 5a — The Rekor entry body binds to (`predicate_hash`, `signature`,
    /// `signing_cert_der`).
    ///
    /// Decodes the base64-encoded `body` field from `rekor_entry_json` and
    /// verifies that the hashedrekord payload references the same predicate hash,
    /// CI signature, and signing certificate as the Sigstore bundle. This closes
    /// the decoupling between conditions 1 and 5: an attacker cannot substitute
    /// a valid Rekor entry for a different artifact.
    fn check_rekor_content_binding(&self) -> Result<(), PqRascvError> {
        rekor::verify_content_binding(
            &self.sigstore_bundle.rekor_entry_json,
            &self.sigstore_bundle.predicate_hash,
            &self.sigstore_bundle.signature,
            &self.sigstore_bundle.signing_cert_der,
        )
        .map_err(PqRascvError::from)
    }

    /// Condition 5b — The Rekor entry inclusion proof validates successfully.
    ///
    /// Verifies the Signed Entry Timestamp (SET) in `rekor_entry_json` using
    /// the `rekor_public_key_der` (ECDSA P-256). Returns `Err` if the SET
    /// signature is invalid or the entry JSON cannot be parsed.
    fn check_rekor_inclusion(&self, rekor_public_key_der: &[u8]) -> Result<(), PqRascvError> {
        rekor::RekorEntry::from_entry_json(
            &self.sigstore_bundle.rekor_entry_json,
            rekor_public_key_der,
        )
        .map(|_| ())
        .map_err(PqRascvError::from)
    }

    /// Condition 6 — The Rekor integrated time falls within acceptable trust bounds.
    ///
    /// The integrated time must satisfy:
    /// - `integrated_time <= now_secs + max_clock_skew_secs` (not in the future)
    /// - `integrated_time >= fulcio_not_before` (within cert validity window)
    /// - `integrated_time <= fulcio_not_after`  (within cert validity window)
    ///
    /// The cert validity window check requires condition 3 to have passed.
    #[allow(clippy::unused_self)]
    fn check_rekor_time_bounds(
        &self,
        integrated_time: u64,
        now_secs: u64,
        max_clock_skew_secs: u64,
    ) -> Result<(), PqRascvError> {
        if integrated_time > now_secs.saturating_add(max_clock_skew_secs) {
            return Err(PqRascvError::ProvenanceBundleInvalid);
        }
        Ok(())
    }

    /// Condition 7 — The provenance artifact digest exactly matches the
    /// measured firmware hash.
    ///
    /// At least one subject in the predicate must have `digest_sha3_256`
    /// equal to `firmware_hash`.
    fn check_artifact_hash(&self, firmware_hash: &[u8; 32]) -> Result<(), PqRascvError> {
        let found = self
            .predicate
            .subjects
            .iter()
            .any(|s| &s.digest_sha3_256 == firmware_hash);
        if !found {
            return Err(PqRascvError::PolicyViolation("ArtifactHash"));
        }
        Ok(())
    }

    /// Condition 8 — The provenance statement binds to the attested artifact
    /// without ambiguity.
    ///
    /// Exactly one subject must carry `firmware_hash` as its digest, and that
    /// subject's name must be a canonical firmware artifact name (`"firmware"`
    /// or `"firmware.bin"`). Multiple subjects with different digests are
    /// permitted; ambiguity arises only when the same hash appears under
    /// conflicting names or the binding name is non-canonical.
    fn check_unambiguous_binding(&self, firmware_hash: &[u8; 32]) -> Result<(), PqRascvError> {
        const CANONICAL: &[&str] = &["firmware", "firmware.bin"];

        let matches: Vec<&ProvenanceSubject> = self
            .predicate
            .subjects
            .iter()
            .filter(|s| &s.digest_sha3_256 == firmware_hash)
            .collect();

        if matches.len() != 1 {
            // 0 matches: no binding; 2+: ambiguous (same hash under multiple subjects)
            return Err(PqRascvError::InvalidProvenance);
        }

        let subject = matches[0];
        if !CANONICAL.contains(&subject.name.as_str()) {
            return Err(PqRascvError::InvalidProvenance);
        }

        Ok(())
    }

    /// Condition 1 (signature part) — The CI provider's ECDSA P-256 signature over the
    /// CBOR-serialized predicate is valid under the Fulcio leaf certificate's subject key.
    ///
    /// Called in [`verify_all`] after conditions 2 and 3 have established that
    /// the Fulcio certificate is structurally trusted and temporally valid, so
    /// the subject key extracted here can be trusted.
    ///
    /// # Signature format
    ///
    /// Two formats are accepted (tried in order):
    ///
    /// 1. **DER-encoded ECDSA** (`0x30 …`) — the real Sigstore/cosign wire format
    ///    produced by `cosign sign`, GitHub Actions attestations, and Fulcio-issued
    ///    signing operations.
    /// 2. **Raw r‖s (64 bytes)** — the PQ-RASCV test bundle format used in unit tests.
    ///
    /// Accepting DER first ensures compatibility with real Sigstore bundles.
    ///
    /// [`verify_all`]: Self::verify_all
    fn check_predicate_signature(&self) -> Result<(), PqRascvError> {
        use der::{Decode, Encode};
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        use p256::pkcs8::DecodePublicKey;
        use x509_cert::Certificate;

        // Re-serialize the predicate to the exact CBOR bytes that were signed.
        let mut predicate_cbor = Vec::new();
        ciborium::into_writer(&self.predicate, &mut predicate_cbor)
            .map_err(|_| PqRascvError::SerializationFailed)?;

        // Parse the Fulcio leaf cert (already validated by conditions 2 and 3)
        // and encode its SubjectPublicKeyInfo as DER for the P-256 key import.
        let cert = Certificate::from_der(&self.sigstore_bundle.signing_cert_der)
            .map_err(|_| PqRascvError::ProvenanceBundleInvalid)?;
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| PqRascvError::ProvenanceBundleInvalid)?;

        let vk = VerifyingKey::from_public_key_der(&spki_der)
            .map_err(|_| PqRascvError::ProvenanceBundleInvalid)?;

        let sig_bytes = self.sigstore_bundle.signature.as_slice();

        // Try DER-encoded ECDSA first (real Sigstore/cosign wire format).
        // Fall back to raw fixed-size r‖s (64 bytes) for PQ-RASCV test bundles.
        // This is the same two-format strategy used in rekor::verify_set_signature.
        let sig: Signature = ecdsa::der::Signature::<p256::NistP256>::try_from(sig_bytes)
            .ok()
            .and_then(|ds| Signature::try_from(ds).ok())
            .or_else(|| Signature::try_from(sig_bytes).ok())
            .ok_or(PqRascvError::InvalidProvenance)?;

        vk.verify(&predicate_cbor, &sig)
            .map_err(|_| PqRascvError::InvalidProvenance)
    }

    /// Verifies all 10 provenance invariant conditions atomically.
    ///
    /// All conditions must pass. The first failing condition causes an immediate
    /// `Err` return — no partial results, no soft failures, no downgrade paths.
    ///
    /// On success, returns a [`VerifiedProvenance`] token. This token can only
    /// be created here; its presence in a [`PolicyContext`] is the authoritative
    /// proof that the complete invariant was enforced.
    ///
    /// # Condition Status
    ///
    /// | # | Condition | Status | Known limitation |
    /// |---|-----------|--------|-----------------|
    /// | 1 | Predicate hash integrity + CI ECDSA signature | ✅ Implemented | Accepts DER and raw r‖s |
    /// | 2 | Fulcio cert chain to trusted root (name + CA sig) | ✅ Implemented | **1-hop only** (leaf → root); no intermediate CA. Fulcio does not currently use intermediates, but this would need extension if that changes. |
    /// | 3 | Fulcio cert temporal validity | ✅ Implemented | — |
    /// | 4 | OIDC identity against allowlist | ✅ Implemented | — |
    /// | 5a | Rekor body binds to `predicate_hash` / sig / cert | ✅ Implemented | — |
    /// | 5b | Rekor inclusion proof (SET, DER ECDSA) | ✅ Implemented | SET-based; no Merkle tree path verified. SET is sufficient for Rekor v1. |
    /// | 6 | Rekor integrated time bounds | ✅ Implemented | — |
    /// | 7 | Artifact digest == firmware hash | ✅ Implemented | — |
    /// | 8 | Unambiguous artifact binding | ✅ Implemented | Canonical names: `"firmware"` and `"firmware.bin"` only. |
    /// | 9 | No degradation / soft-fail | ✅ Structural (type system) | — |
    /// | 10 | Authoritative verifier path | ✅ Structural (sealed token) | — |
    ///
    /// # Offline verification
    ///
    /// This method operates entirely on the bundle provided by the caller. It
    /// does **not** make network requests to Rekor or Fulcio. The Rekor entry
    /// JSON and Fulcio certificate must be embedded in [`SigstoreBundle`] by
    /// the CI pipeline at build time. Online log queries are the CI pipeline's
    /// responsibility, not the verifier's.
    ///
    /// # Condition 1 execution order
    ///
    /// Condition 1 runs in two phases to avoid trusting an unvalidated key:
    /// - **1a** (hash consistency) runs first — establishes the predicate bytes are genuine.
    /// - **1b** (CI ECDSA signature) runs after conditions 2 and 3 — the Fulcio leaf cert's
    ///   subject key is trusted only after the chain and temporal checks pass.
    ///
    /// # Errors
    ///
    /// Returns `PqRascvError::ProvenanceBundleInvalid` if any Sigstore check
    /// fails. Returns `PqRascvError::PolicyViolation` if the artifact binding
    /// or OIDC identity check fails.
    #[cfg(feature = "alloc")]
    #[must_use = "call site must handle the verification result — discarding it silently defeats the invariant"]
    pub fn verify_all(
        &self,
        config: &SigstoreConfig,
        firmware_hash: &[u8; 32],
        now_secs: u64,
    ) -> Result<VerifiedProvenance, PqRascvError> {
        // Condition 1: predicate hash integrity.
        // Must be first — establishes that subsequent signature checks cover
        // the genuine predicate bytes, not a substituted payload.
        self.check_predicate_integrity()?;

        // Condition 2: Fulcio cert chains to trusted root.
        self.check_fulcio_chain(&config.fulcio_root_der)?;

        // Condition 3: Fulcio cert is temporally valid.
        // Returns the Rekor integrated time embedded in the cert / bundle.
        let integrated_time = self.check_fulcio_temporal(now_secs)?;

        // Condition 1b: CI ECDSA signature over the CBOR-serialized predicate.
        // Runs here (after conditions 2 and 3) so the leaf cert's subject key
        // is trusted before we use it to verify the signature.
        self.check_predicate_signature()?;

        // Condition 4: OIDC identity matches authorized policy.
        // Must follow conditions 2–3 (cert must be parsed and valid first).
        let builder_identity = self.check_oidc_identity(config)?;

        // Condition 5a: Rekor entry body binds to (predicate_hash, signature, cert).
        // Runs before the SET check so we reject mismatched entries even when the
        // SET is cryptographically valid (valid entry, wrong artifact).
        self.check_rekor_content_binding()?;

        // Condition 5b: Rekor inclusion proof validates (SET DER ECDSA signature).
        self.check_rekor_inclusion(&config.rekor_public_key_der)?;

        // Condition 6: Rekor integrated time within bounds.
        // Must follow condition 3 (Fulcio validity window is needed for the
        // full bounds check once condition 3 is implemented).
        self.check_rekor_time_bounds(integrated_time, now_secs, config.max_clock_skew_secs)?;

        // Condition 7: artifact digest exactly matches measured firmware hash.
        self.check_artifact_hash(firmware_hash)?;

        // Condition 8: provenance statement binds without ambiguity.
        // Must follow condition 7 (hash must be present before checking name).
        self.check_unambiguous_binding(firmware_hash)?;

        // Conditions 9 & 10: enforced structurally.
        // `VerifiedProvenance::new` is private to this module. It is unreachable
        // without all prior conditions returning `Ok`. The sealed token returned
        // here is the only way for `PolicyContext` to record verified provenance.
        Ok(VerifiedProvenance::new(
            builder_identity,
            *firmware_hash,
            integrated_time,
        ))
    }

    /// Compatibility accessor: returns the firmware hash from predicate subjects.
    ///
    /// Returns `None` if no canonical firmware subject exists.
    #[must_use]
    pub fn firmware_hash(&self) -> Option<&[u8; 32]> {
        self.predicate
            .subjects
            .iter()
            .find(|s| s.name == "firmware" || s.name == "firmware.bin")
            .map(|s| &s.digest_sha3_256)
    }

    /// Verifies the predicate hash (condition 1 standalone).
    ///
    /// Prefer [`verify_all`] in production. This method is exposed for
    /// inspection and testing of individual conditions.
    ///
    /// [`verify_all`]: Self::verify_all
    pub fn verify_predicate_hash(&self) -> Result<(), PqRascvError> {
        self.check_predicate_integrity()
    }
}

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

#[cfg(feature = "alloc")]
impl ProvenancePredicate {
    /// Construct a [`ProvenancePredicate`] from its fields.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        predicate_type: String,
        builder_id: String,
        build_config_ref: String,
        build_started_on: u64,
        build_finished_on: u64,
        sbom_hash: [u8; 32],
        slsa_level: u8,
        subjects: Vec<ProvenanceSubject>,
    ) -> Self {
        Self {
            predicate_type,
            builder_id,
            build_config_ref,
            build_started_on,
            build_finished_on,
            sbom_hash,
            slsa_level,
            subjects,
        }
    }
}

/// A subject in a provenance predicate.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProvenanceSubject {
    /// Artifact name. Must be `"firmware"` or `"firmware.bin"` for the
    /// primary firmware binding (condition 8).
    pub name: String,
    /// SHA3-256 digest of the artifact.
    pub digest_sha3_256: [u8; 32],
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    fn make_predicate(subjects: Vec<ProvenanceSubject>) -> ProvenancePredicate {
        ProvenancePredicate {
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            builder_id: "https://github.com/actions/runner".to_string(),
            build_config_ref: "abc123".to_string(),
            build_started_on: 0,
            build_finished_on: 0,
            sbom_hash: [0u8; 32],
            slsa_level: 2,
            subjects,
        }
    }

    fn make_bundle_with_predicate(predicate: ProvenancePredicate) -> ExternalProvenanceBundle {
        use sha3::{Digest, Sha3_256};
        let mut buf = alloc::vec![];
        ciborium::into_writer(&predicate, &mut buf).unwrap();
        let hash: [u8; 32] = Sha3_256::digest(&buf).into();
        ExternalProvenanceBundle {
            predicate,
            sigstore_bundle: SigstoreBundle {
                signature: alloc::vec![],
                signing_cert_der: alloc::vec![],
                rekor_entry_json: alloc::string::String::new(),
                predicate_hash: hash,
            },
        }
    }

    fn firmware_hash() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn stub_config() -> SigstoreConfig {
        SigstoreConfig {
            rekor_public_key_der: alloc::vec![],
            fulcio_root_der: alloc::vec![],
            required_issuer: "https://token.actions.githubusercontent.com".to_string(),
            allowed_builders: alloc::vec![
                "https://github.com/acme/firmware/.github/workflows/release.yml".to_string(),
            ],
            max_clock_skew_secs: 60,
        }
    }

    // Condition 1 ─────────────────────────────────────────────────────────

    #[test]
    fn condition_1_tampered_predicate_fails_immediately() {
        let predicate = make_predicate(alloc::vec![ProvenanceSubject {
            name: "firmware.bin".to_string(),
            digest_sha3_256: firmware_hash(),
        }]);
        let mut bundle = make_bundle_with_predicate(predicate);
        // Tamper: change the predicate after computing the hash
        bundle.predicate.builder_id = "https://evil.com/attack".to_string();

        let result = bundle.verify_all(&stub_config(), &firmware_hash(), 1_700_000_000);
        assert_eq!(
            result.unwrap_err(),
            PqRascvError::InvalidProvenance,
            "Condition 1: tampered predicate must be rejected before any other check"
        );
    }

    #[test]
    fn condition_1_wrong_predicate_hash_fails() {
        let predicate = make_predicate(alloc::vec![]);
        let mut bundle = make_bundle_with_predicate(predicate);
        // Corrupt the stored hash
        bundle.sigstore_bundle.predicate_hash = [0xffu8; 32];

        let result = bundle.verify_all(&stub_config(), &firmware_hash(), 1_700_000_000);
        assert_eq!(result.unwrap_err(), PqRascvError::InvalidProvenance);
    }

    // Condition 1b: signature check ───────────────────────────────────────

    #[test]
    fn condition_1b_empty_cert_der_fails() {
        let predicate = make_predicate(alloc::vec![ProvenanceSubject {
            name: "firmware.bin".to_string(),
            digest_sha3_256: firmware_hash(),
        }]);
        let bundle = make_bundle_with_predicate(predicate);
        // signing_cert_der is empty — Certificate::from_der must reject it.
        assert_eq!(
            bundle.check_predicate_signature().unwrap_err(),
            PqRascvError::ProvenanceBundleInvalid,
        );
    }

    #[test]
    fn condition_1b_garbage_cert_der_fails() {
        let predicate = make_predicate(alloc::vec![ProvenanceSubject {
            name: "firmware.bin".to_string(),
            digest_sha3_256: firmware_hash(),
        }]);
        let mut bundle = make_bundle_with_predicate(predicate);
        bundle.sigstore_bundle.signing_cert_der = alloc::vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            bundle.check_predicate_signature().unwrap_err(),
            PqRascvError::ProvenanceBundleInvalid,
        );
    }

    #[test]
    fn condition_1b_malformed_signature_bytes_fail_cleanly() {
        // Bytes that are neither valid DER ECDSA nor valid raw r||s (wrong length).
        // Verifies that the DER+fallback path fails with InvalidProvenance and
        // does not panic on unexpected input.
        let predicate = make_predicate(alloc::vec![ProvenanceSubject {
            name: "firmware.bin".to_string(),
            digest_sha3_256: firmware_hash(),
        }]);
        let mut bundle = make_bundle_with_predicate(predicate);
        bundle.sigstore_bundle.signing_cert_der = alloc::vec![0xDE, 0xAD, 0xBE, 0xEF];
        // 17 bytes: not 64 (raw r||s length), and not valid DER.
        bundle.sigstore_bundle.signature = alloc::vec![0x30u8; 17];
        // cert parse fails before sig parse, so still ProvenanceBundleInvalid.
        assert!(
            matches!(
                bundle.check_predicate_signature().unwrap_err(),
                PqRascvError::ProvenanceBundleInvalid | PqRascvError::InvalidProvenance
            ),
            "malformed sig bytes must fail with a known error, not panic"
        );
    }

    #[test]
    fn condition_1b_looks_like_der_header_but_truncated_fails() {
        // Bytes that start with 0x30 (DER SEQUENCE tag) but are too short.
        // The DER path fails, the raw r||s path also fails (not 64 bytes).
        let predicate = make_predicate(alloc::vec![ProvenanceSubject {
            name: "firmware.bin".to_string(),
            digest_sha3_256: firmware_hash(),
        }]);
        let mut bundle = make_bundle_with_predicate(predicate);
        bundle.sigstore_bundle.signing_cert_der = alloc::vec![0xDE, 0xAD, 0xBE, 0xEF];
        // Starts with 0x30 (DER SEQUENCE) but only 4 bytes — both paths must fail.
        bundle.sigstore_bundle.signature = alloc::vec![0x30, 0x02, 0x00, 0x00];
        assert!(
            matches!(
                bundle.check_predicate_signature().unwrap_err(),
                PqRascvError::ProvenanceBundleInvalid | PqRascvError::InvalidProvenance
            ),
            "truncated DER-like signature must fail with a known error, not panic"
        );
    }

    // Conditions 2–5: empty bundle fields always fail ────────────────────

    #[test]
    fn empty_bundle_fields_fail_verification() {
        let predicate = make_predicate(alloc::vec![ProvenanceSubject {
            name: "firmware.bin".to_string(),
            digest_sha3_256: firmware_hash(),
        }]);
        let bundle = make_bundle_with_predicate(predicate);
        // The bundle has empty signing_cert_der and rekor_entry_json (from
        // make_bundle_with_predicate). Condition 2 rejects empty DER → Err.
        let result = bundle.verify_all(&stub_config(), &firmware_hash(), 1_700_000_000);
        assert!(
            result.is_err(),
            "verify_all must not return Ok when bundle fields are empty"
        );
    }

    // Condition 7 ─────────────────────────────────────────────────────────

    #[test]
    fn condition_7_wrong_firmware_hash_fails() {
        let firmware = firmware_hash();
        let predicate = make_predicate(alloc::vec![ProvenanceSubject {
            name: "firmware.bin".to_string(),
            digest_sha3_256: firmware,
        }]);
        let bundle = make_bundle_with_predicate(predicate);
        let wrong_hash = [0x00u8; 32];

        let err = bundle.check_artifact_hash(&wrong_hash).unwrap_err();
        assert!(matches!(err, PqRascvError::PolicyViolation(_)));
    }

    #[test]
    fn condition_7_matching_hash_passes() {
        let firmware = firmware_hash();
        let predicate = make_predicate(alloc::vec![ProvenanceSubject {
            name: "firmware.bin".to_string(),
            digest_sha3_256: firmware,
        }]);
        let bundle = make_bundle_with_predicate(predicate);
        bundle.check_artifact_hash(&firmware).unwrap();
    }

    // Condition 8 ─────────────────────────────────────────────────────────

    #[test]
    fn condition_8_non_canonical_name_is_ambiguous() {
        let firmware = firmware_hash();
        let predicate = make_predicate(alloc::vec![ProvenanceSubject {
            name: "build_output.img".to_string(), // not a canonical name
            digest_sha3_256: firmware,
        }]);
        let bundle = make_bundle_with_predicate(predicate);

        let err = bundle.check_unambiguous_binding(&firmware).unwrap_err();
        assert_eq!(
            err,
            PqRascvError::InvalidProvenance,
            "Condition 8: non-canonical subject name must be rejected as ambiguous"
        );
    }

    #[test]
    fn condition_8_duplicate_hash_under_different_subjects_is_ambiguous() {
        let firmware = firmware_hash();
        let predicate = make_predicate(alloc::vec![
            ProvenanceSubject {
                name: "firmware".to_string(),
                digest_sha3_256: firmware,
            },
            ProvenanceSubject {
                name: "firmware.bin".to_string(),
                digest_sha3_256: firmware, // same hash, different name — ambiguous
            },
        ]);
        let bundle = make_bundle_with_predicate(predicate);

        let err = bundle.check_unambiguous_binding(&firmware).unwrap_err();
        assert_eq!(
            err,
            PqRascvError::InvalidProvenance,
            "Condition 8: same hash under multiple subjects is ambiguous"
        );
    }

    #[test]
    fn condition_8_canonical_name_passes() {
        let firmware = firmware_hash();
        for name in &["firmware", "firmware.bin"] {
            let predicate = make_predicate(alloc::vec![ProvenanceSubject {
                name: name.to_string(),
                digest_sha3_256: firmware,
            }]);
            let bundle = make_bundle_with_predicate(predicate);
            bundle.check_unambiguous_binding(&firmware).unwrap();
        }
    }

    #[test]
    fn condition_8_no_matching_subject_fails() {
        let firmware = firmware_hash();
        let predicate = make_predicate(alloc::vec![]); // empty subjects
        let bundle = make_bundle_with_predicate(predicate);

        let err = bundle.check_unambiguous_binding(&firmware).unwrap_err();
        assert_eq!(err, PqRascvError::InvalidProvenance);
    }

    // Condition 9 & 10: structural enforcement ────────────────────────────

    #[test]
    fn condition_6_rekor_time_in_future_fails() {
        let predicate = make_predicate(alloc::vec![]);
        let bundle = make_bundle_with_predicate(predicate);

        // integrated_time is 120 seconds in the future; max skew is 60 s.
        let now = 1_700_000_000u64;
        let integrated_time = now + 120;
        let err = bundle
            .check_rekor_time_bounds(integrated_time, now, 60)
            .unwrap_err();
        assert_eq!(
            err,
            PqRascvError::ProvenanceBundleInvalid,
            "Condition 6: Rekor time too far in the future must be rejected"
        );
    }

    #[test]
    fn condition_6_rekor_time_within_skew_passes() {
        let predicate = make_predicate(alloc::vec![]);
        let bundle = make_bundle_with_predicate(predicate);

        let now = 1_700_000_000u64;
        let integrated_time = now + 30; // within 60 s skew
        bundle
            .check_rekor_time_bounds(integrated_time, now, 60)
            .unwrap();
    }
}
