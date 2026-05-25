//! # pqrascv-verifier
//!
//! Reference verifier for the PQ-RASCV protocol.
//!
//! ## Verification procedure
//!
//! 1. Deserialize the CBOR-encoded [`AttestationQuote`] from the prover.
//! 2. Re-serialize the [`QuoteBody`] to reproduce the exact bytes that were signed.
//! 3. Verify the ML-DSA-65 signature using the prover's known verifying key.
//! 4. Check `body.pub_key_id` matches the expected key fingerprint.
//! 5. Apply [`PolicyConfig`] (SLSA level, age, firmware hash presence, etc.).
//!
//! This crate is `std`-only and intended for server-side or CI use.

use pqrascv_core::{
    config::PolicyConfig,
    crypto::{pub_key_id, CryptoBackend, MlDsaBackend, SIGNING_CONTEXT_QUOTE},
    error::PqRascvError,
    pki::{validate_chain, validate_chain_with_store, CertChain, DeviceCertificate, TrustAnchor, TrustStore},
    pki::revocation::VerifiedRevocationList,
    quote::{AttestationQuote, Challenge, PROTOCOL_VERSION},
};

// ────────────────────────────────────────────────────────────────────────────
// VerificationResult
// ────────────────────────────────────────────────────────────────────────────

/// Outcome of a successful attestation verification.
///
/// Only returned when ALL checks pass — errors surface as `Err(PqRascvError)`.
#[derive(Debug)]
pub struct VerificationResult {
    /// The verified quote, available for further inspection.
    pub quote: AttestationQuote,
}

impl VerificationResult {
    /// SLSA level claimed by the prover's provenance predicate.
    #[must_use]
    pub fn slsa_level(&self) -> u8 {
        self.quote.body.provenance.slsa_level()
    }

    /// SHA3-256 digest of the firmware image that was measured.
    #[must_use]
    pub fn firmware_hash(&self) -> &[u8; 32] {
        &self.quote.body.measurements.firmware_hash
    }

    /// The nonce that was bound into this quote.
    #[must_use]
    pub fn nonce(&self) -> &[u8; 32] {
        &self.quote.body.nonce
    }
}

// ────────────────────────────────────────────────────────────────────────────
// PkiVerificationResult
// ────────────────────────────────────────────────────────────────────────────

/// Outcome of a successful PKI-backed attestation verification.
///
/// Both the ML-DSA-65 signature and the certificate chain are verified.
/// The signing key is derived exclusively from the validated certificate.
#[derive(Debug)]
pub struct PkiVerificationResult {
    pub quote: AttestationQuote,
    pub cert_chain: CertChain,
}

impl PkiVerificationResult {
    #[must_use]
    pub fn slsa_level(&self) -> u8 { self.quote.body.provenance.slsa_level() }
    #[must_use]
    pub fn firmware_hash(&self) -> &[u8; 32] { &self.quote.body.measurements.firmware_hash }
    #[must_use]
    pub fn nonce(&self) -> &[u8; 32] { &self.quote.body.nonce }
    #[must_use]
    pub fn device_serial(&self) -> &str { &self.cert_chain.device_cert.serial }

    /// The CA identifier URI of the trust anchor that validated this chain.
    #[must_use]
    pub fn trust_anchor_id(&self) -> &str {
        &self.cert_chain.trust_anchor.ca_id
    }

    /// SHA3-256 fingerprint of the trust anchor's public key.
    #[must_use]
    pub fn trust_anchor_fingerprint(&self) -> &[u8; 32] {
        &self.cert_chain.trust_anchor.fingerprint
    }

    /// Unix timestamp after which the trust anchor must not be used.
    #[must_use]
    pub fn trust_anchor_valid_until(&self) -> u64 {
        self.cert_chain.trust_anchor.not_after
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Verifier
// ────────────────────────────────────────────────────────────────────────────

/// Stateless PQ-RASCV quote verifier.
///
/// # Example
///
/// ```rust,no_run
/// use pqrascv_verifier::Verifier;
/// use pqrascv_core::config::PolicyConfig;
///
/// // cbor, vk, nonce, and timestamp come from your protocol layer.
/// let verifier = Verifier::new(PolicyConfig::default());
/// // let result = verifier.verify_cbor(&cbor, &vk, &nonce, now_secs);
/// ```
pub struct Verifier {
    policy: PolicyConfig,
}

impl Verifier {
    /// Creates a new [`Verifier`] with the given policy.
    #[must_use]
    pub fn new(policy: PolicyConfig) -> Self {
        Self { policy }
    }

    /// Verifies a CBOR-encoded [`AttestationQuote`].
    ///
    /// # Arguments
    ///
    /// - `cbor`: raw CBOR bytes received from the prover.
    /// - `verifying_key`: the prover's trusted ML-DSA-65 verifying key bytes.
    /// - `expected_nonce`: the nonce sent in the [`Challenge`]; must match `body.nonce`.
    /// - `now_secs`: current Unix time for age-check policy evaluation.
    ///
    /// # Errors
    ///
    /// Returns the first [`PqRascvError`] encountered.
    pub fn verify_cbor(
        &self,
        cbor: &[u8],
        verifying_key: &[u8],
        expected_nonce: &[u8; 32],
        now_secs: u64,
    ) -> Result<VerificationResult, PqRascvError> {
        let quote = AttestationQuote::from_cbor(cbor)?;

        self.verify_quote(&quote, verifying_key, expected_nonce, now_secs)?;

        Ok(VerificationResult { quote })
    }

    /// Convenience wrapper that takes a [`Challenge`] directly instead of a raw nonce.
    ///
    /// Use this when you generated the challenge with [`Challenge::new`] and want
    /// to pair it with the quote the prover returned.
    pub fn verify_with_challenge(
        &self,
        cbor: &[u8],
        verifying_key: &[u8],
        challenge: &Challenge,
        now_secs: u64,
    ) -> Result<VerificationResult, PqRascvError> {
        self.verify_cbor(cbor, verifying_key, &challenge.nonce, now_secs)
    }

    /// Verifies a CBOR quote using a cryptographically-validated certificate chain.
    ///
    /// The signing key is extracted exclusively from the validated certificate.
    /// No caller-supplied verifying key is accepted — the chain IS the source of trust.
    ///
    /// # Arguments
    ///
    /// - `device_cert`: leaf certificate for the attesting device.
    /// - `intermediates`: ordered CA chain from root-adjacent to device-adjacent (may be empty).
    /// - `trust_anchor`: root CA trust anchor.
    /// - `crl`: optional verified CRL; if `Some`, the device serial is checked for revocation.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_cbor_with_pki(
        &self,
        cbor: &[u8],
        device_cert: DeviceCertificate,
        intermediates: Vec<DeviceCertificate>,
        trust_anchor: &TrustAnchor,
        crl: Option<&VerifiedRevocationList<'_>>,
        expected_nonce: &[u8; 32],
        now_secs: u64,
    ) -> Result<PkiVerificationResult, PqRascvError> {
        // Step 1: Validate certificate chain — sole source of the trusted signing key
        let chain = validate_chain(device_cert, intermediates, trust_anchor, now_secs)?;

        // Step 2: Revocation check before any signature work
        if let Some(crl) = crl {
            if crl.is_revoked(&chain.device_cert.serial) {
                return Err(PqRascvError::CertificateRevoked);
            }
        }

        // Step 3: Verify the quote against the key from the validated certificate
        let verifying_key = &chain.device_cert.subject_key;
        let result = self.verify_cbor(cbor, verifying_key, expected_nonce, now_secs)?;

        Ok(PkiVerificationResult { quote: result.quote, cert_chain: chain })
    }

    /// Verifies a CBOR quote using any currently-valid anchor in a [`TrustStore`].
    ///
    /// Tries each valid (temporally active) anchor in insertion order. Returns
    /// [`PqRascvError::TrustAnchorExpired`] if the store has no valid anchor,
    /// or [`PqRascvError::CertificateInvalid`] if no valid anchor accepts the chain.
    ///
    /// # Arguments
    ///
    /// - `trust_store`: holds primary and rollover root CA anchors.
    /// - `crl`: optional verified CRL; if `Some`, the device serial is checked for revocation.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_cbor_with_trust_store(
        &self,
        cbor: &[u8],
        device_cert: DeviceCertificate,
        intermediates: Vec<DeviceCertificate>,
        trust_store: &TrustStore,
        crl: Option<&VerifiedRevocationList<'_>>,
        expected_nonce: &[u8; 32],
        now_secs: u64,
    ) -> Result<PkiVerificationResult, PqRascvError> {
        let chain =
            validate_chain_with_store(&device_cert, &intermediates, trust_store, now_secs)?;

        if let Some(crl) = crl {
            if crl.is_revoked(&chain.device_cert.serial) {
                return Err(PqRascvError::CertificateRevoked);
            }
        }

        let verifying_key = &chain.device_cert.subject_key;
        let result = self.verify_cbor(cbor, verifying_key, expected_nonce, now_secs)?;

        Ok(PkiVerificationResult { quote: result.quote, cert_chain: chain })
    }

    /// Verifies an already-parsed [`AttestationQuote`]. Useful if you've already
    /// deserialized the CBOR yourself and don't want to do it twice.
    pub fn verify_quote(
        &self,
        quote: &AttestationQuote,
        verifying_key: &[u8],
        expected_nonce: &[u8; 32],
        now_secs: u64,
    ) -> Result<(), PqRascvError> {
        // Reject unknown protocol versions before doing any other work.
        if quote.body.version != PROTOCOL_VERSION {
            return Err(PqRascvError::UnsupportedVersion);
        }

        // Nonce must match what we originally sent — if it doesn't, this is a replay or mix-up.
        if &quote.body.nonce != expected_nonce {
            return Err(PqRascvError::VerificationFailed);
        }

        // Make sure the quote was signed with the key we actually trust.
        let expected_id = pub_key_id(verifying_key);
        if quote.body.pub_key_id != expected_id {
            return Err(PqRascvError::VerificationFailed);
        }

        // Re-serialize the body and check the signature over it.
        let body_cbor = quote.body.to_cbor()?;
        MlDsaBackend.verify(&body_cbor, verifying_key, &quote.signature, SIGNING_CONTEXT_QUOTE)?;

        // Finally, check that the quote meets our policy (SLSA level, age, firmware hash, etc.).
        self.policy.evaluate(
            quote.body.provenance.slsa_level(),
            &quote.body.measurements.firmware_hash,
            quote.body.measurements.event_counter,
            quote.body.timestamp,
            now_secs,
        )?;

        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pqrascv_core::{
        crypto::generate_ml_dsa_keypair,
        measurement::SoftwareRoT,
        provenance::SlsaPredicateBuilder,
        quote::{generate_quote, QuoteTimestamp},
    };

    fn setup() -> (
        pqrascv_core::crypto::SigningKeySeed,
        [u8; pqrascv_core::crypto::ML_DSA_65_VERIFYING_KEY_SIZE],
        AttestationQuote,
    ) {
        let (sk, vk) = generate_ml_dsa_keypair().unwrap();
        let rot = SoftwareRoT::new(b"verifier-test-firmware", None, 1);
        let provenance = SlsaPredicateBuilder::new("https://ci.example.com")
            .add_subject("fw.bin", &[0xabu8; 32])
            .with_slsa_level(2)
            .with_timestamps(1_700_000_000, 1_700_001_000)
            .build()
            .unwrap();
        let nonce = [0x77u8; 32];
        let quote = generate_quote(
            &rot,
            &pqrascv_core::crypto::MlDsaBackend,
            sk.as_bytes(),
            &vk,
            &nonce,
            provenance,
            QuoteTimestamp::Rtc(1_700_000_500),
        )
        .unwrap();
        (sk, vk, quote)
    }

    #[test]
    fn verifier_accepts_valid_quote() {
        let (_, vk, quote) = setup();
        let verifier = Verifier::new(PolicyConfig::default());
        let cbor = quote.to_cbor().unwrap();

        let result = verifier.verify_cbor(&cbor, &vk, &[0x77u8; 32], 1_700_000_600);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn verifier_rejects_wrong_nonce() {
        let (_, vk, quote) = setup();
        let verifier = Verifier::new(PolicyConfig::default());
        let cbor = quote.to_cbor().unwrap();

        let result = verifier.verify_cbor(&cbor, &vk, &[0x00u8; 32], 1_700_000_600);
        assert!(result.is_err());
    }

    #[test]
    fn verifier_rejects_tampered_quote() {
        let (_, vk, mut quote) = setup();
        let verifier = Verifier::new(PolicyConfig::default());

        quote.body.measurements.event_counter = 999;
        let cbor = quote.to_cbor().unwrap();

        let result = verifier.verify_cbor(&cbor, &vk, &[0x77u8; 32], 1_700_000_600);
        assert!(result.is_err());
    }

    #[test]
    fn verifier_rejects_wrong_verifying_key() {
        let (_, _vk, quote) = setup();

        let (_, different_vk) = generate_ml_dsa_keypair().unwrap();
        let verifier = Verifier::new(PolicyConfig::default());
        let cbor = quote.to_cbor().unwrap();

        let result = verifier.verify_cbor(&cbor, &different_vk, &[0x77u8; 32], 1_700_000_600);
        assert!(result.is_err());
    }

    #[test]
    fn verifier_rejects_unsupported_version() {
        let (_, vk, mut quote) = setup();
        let verifier = Verifier::new(PolicyConfig::default());

        // Tamper with the version field — signature will break too, but version
        // check must fire first and return UnsupportedVersion.
        quote.body.version = 99;
        let cbor = quote.to_cbor().unwrap();

        let result = verifier.verify_cbor(&cbor, &vk, &[0x77u8; 32], 1_700_000_600);
        assert!(matches!(result, Err(PqRascvError::UnsupportedVersion)));
    }

    #[test]
    fn verifier_rejects_rtcless_by_default() {
        let (sk, vk) = generate_ml_dsa_keypair().unwrap();
        let rot = SoftwareRoT::new(b"fw", None, 1);
        let provenance = SlsaPredicateBuilder::new("https://ci.example.com")
            .add_subject("fw.bin", &[0xabu8; 32])
            .with_slsa_level(2)
            .build()
            .unwrap();
        let quote = generate_quote(
            &rot,
            &pqrascv_core::crypto::MlDsaBackend,
            sk.as_bytes(),
            &vk,
            &[0x77u8; 32],
            provenance,
            QuoteTimestamp::NoRtc,
        )
        .unwrap();
        let cbor = quote.to_cbor().unwrap();
        let verifier = Verifier::new(PolicyConfig::default());
        assert!(matches!(
            verifier.verify_cbor(&cbor, &vk, &[0x77u8; 32], 9_999_999),
            Err(PqRascvError::RtcRequired)
        ));
    }

    #[test]
    fn verify_with_challenge_accepts_valid_quote() {
        let (_, vk, quote) = setup();
        let verifier = Verifier::new(PolicyConfig::default());
        let cbor = quote.to_cbor().unwrap();

        let challenge = pqrascv_core::quote::Challenge::new([0x77u8; 32]);
        let result = verifier.verify_with_challenge(&cbor, &vk, &challenge, 1_700_000_600);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn verify_with_challenge_rejects_wrong_nonce() {
        let (_, vk, quote) = setup();
        let verifier = Verifier::new(PolicyConfig::default());
        let cbor = quote.to_cbor().unwrap();

        let challenge = pqrascv_core::quote::Challenge::new([0x00u8; 32]);
        let result = verifier.verify_with_challenge(&cbor, &vk, &challenge, 1_700_000_600);
        assert!(result.is_err());
    }

    #[test]
    fn verification_result_accessors_return_correct_data() {
        let (_, vk, quote) = setup();
        let verifier = Verifier::new(PolicyConfig::default());
        let expected_firmware_hash = quote.body.measurements.firmware_hash;
        let cbor = quote.to_cbor().unwrap();

        let result = verifier
            .verify_cbor(&cbor, &vk, &[0x77u8; 32], 1_700_000_600)
            .unwrap();

        assert_eq!(result.slsa_level(), 2);
        assert_eq!(result.firmware_hash(), &expected_firmware_hash);
        assert_eq!(result.nonce(), &[0x77u8; 32]);
    }
}

#[cfg(test)]
mod pki_tests {
    use super::*;
    use pqrascv_core::{
        crypto::{generate_ml_dsa_keypair, MlDsaBackend, CryptoBackend, SIGNING_CONTEXT_CERT,
                 ML_DSA_65_VERIFYING_KEY_SIZE},
        measurement::SoftwareRoT,
        pki::{build_device_certificate, CaPublicKey, HardwareIdentity, TrustStore, CERT_VERSION},
        provenance::SlsaPredicateBuilder,
        quote::{generate_quote, QuoteTimestamp},
    };

    fn make_provenance() -> pqrascv_core::provenance::InTotoAttestation {
        SlsaPredicateBuilder::new("https://ci.test")
            .add_subject("fw.bin", &[0xabu8; 32])
            .with_slsa_level(2)
            .build()
            .unwrap()
    }

    fn sign_cert(cert: &mut pqrascv_core::pki::DeviceCertificate, seed: &[u8]) {
        let tbs = cert.tbs_cbor().unwrap();
        let sig = MlDsaBackend.sign(&tbs, seed, SIGNING_CONTEXT_CERT).unwrap();
        cert.issuer_signature = sig.as_ref().to_vec();
    }

    fn make_device_cert(
        device_vk: &[u8; ML_DSA_65_VERIFYING_KEY_SIZE],
        issuer_id: &str,
        serial: &str,
        signer_seed: &[u8],
    ) -> pqrascv_core::pki::DeviceCertificate {
        let subject_key_id = pqrascv_core::crypto::pub_key_id(device_vk);
        let mut cert = build_device_certificate(
            CERT_VERSION,
            serial.to_string(),
            issuer_id.to_string(),
            0,
            u64::MAX,
            device_vk.to_vec(),
            subject_key_id,
            HardwareIdentity::TpmEkCertHash([0u8; 32]),
            None,
            vec![],
            serial.to_string(),
            Some(0),
        );
        sign_cert(&mut cert, signer_seed);
        cert
    }

    #[test]
    fn pki_verification_succeeds_with_valid_chain() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();

        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
        let device_cert = make_device_cert(&dev_vk, "https://ca.test", "DEV-001", ca_seed.as_bytes());

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xAAu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        let result = verifier.verify_cbor_with_pki(
            &cbor, device_cert, vec![], &anchor, None, &nonce, 1_700_000_100,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().device_serial(), "DEV-001");
    }

    #[test]
    fn pki_verification_rejects_revoked_device() {
        use pqrascv_core::pki::revocation::{build_revocation_list, RevocationEntry, RevocationReason};
        use pqrascv_core::crypto::SIGNING_CONTEXT_CRL;

        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
        let device_cert = make_device_cert(&dev_vk, "https://ca.test", "DEV-REVOKED", ca_seed.as_bytes());

        let mut crl = build_revocation_list(
            "https://ca.test".to_string(),
            1_000,
            9_999_999,
            vec![RevocationEntry {
                serial: "DEV-REVOKED".to_string(),
                revoked_at: 1_000,
                reason: RevocationReason::KeyCompromise,
            }],
            vec![],
        );
        let crl_tbs = crl.tbs_cbor().unwrap();
        let crl_sig = MlDsaBackend.sign(&crl_tbs, ca_seed.as_bytes(), SIGNING_CONTEXT_CRL).unwrap();
        crl.issuer_signature = crl_sig.as_ref().to_vec();
        let verified_crl = crl.verify(&ca_vk, 2_000).unwrap();

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xBBu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        let result = verifier.verify_cbor_with_pki(
            &cbor, device_cert, vec![], &anchor, Some(&verified_crl), &nonce, 1_700_000_100,
        );
        assert!(matches!(result, Err(PqRascvError::CertificateRevoked)));
    }

    #[test]
    fn pki_verification_rejects_wrong_trust_anchor() {
        let (ca_seed, _ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (_other_seed, other_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();

        // Anchor uses `other_vk` but cert was signed by `ca_seed`
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: other_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
        let device_cert = make_device_cert(&dev_vk, "https://ca.test", "DEV-001", ca_seed.as_bytes());

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xCCu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        assert!(verifier.verify_cbor_with_pki(
            &cbor, device_cert, vec![], &anchor, None, &nonce, 1_700_000_100,
        ).is_err());
    }

    #[test]
    fn pki_verification_succeeds_with_intermediate_chain() {
        // root CA signs intermediate CA; intermediate CA signs device cert
        let (root_seed, root_vk) = generate_ml_dsa_keypair().unwrap();
        let (int_seed, int_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();

        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: root_vk,
            ca_id: "https://root.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });

        // Intermediate cert: signed by root, self_id = "https://int.test", max_path_length = None
        let int_subject_key_id = pqrascv_core::crypto::pub_key_id(&int_vk);
        let mut intermediate = build_device_certificate(
            CERT_VERSION,
            "INT-001".to_string(),
            "https://root.test".to_string(), // issuer_id must match root ca_id
            0,
            u64::MAX,
            int_vk.to_vec(),
            int_subject_key_id,
            HardwareIdentity::TpmEkCertHash([0u8; 32]),
            None,
            vec![],  // issuer_signature filled in below
            "https://int.test".to_string(), // self_id
            None, // no path length constraint — can sign device cert
        );
        sign_cert(&mut intermediate, root_seed.as_bytes());

        // Device cert: signed by intermediate
        let device_cert = make_device_cert(&dev_vk, "https://int.test", "DEV-CHAIN-001", int_seed.as_bytes());

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xDDu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        let result = verifier.verify_cbor_with_pki(
            &cbor, device_cert, vec![intermediate], &anchor, None, &nonce, 1_700_000_100,
        );
        assert!(result.is_ok(), "intermediate chain verification failed: {result:?}");
        assert_eq!(result.unwrap().device_serial(), "DEV-CHAIN-001");
    }

    #[test]
    fn pki_result_exposes_trust_anchor_metadata() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();

        let expected_fingerprint = pqrascv_core::crypto::pub_key_id(&ca_vk);
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://audit.ca".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
        let device_cert = make_device_cert(&dev_vk, "https://audit.ca", "DEV-AUDIT", ca_seed.as_bytes());

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xCCu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        let result = verifier
            .verify_cbor_with_pki(&cbor, device_cert, vec![], &anchor, None, &nonce, 1_700_000_100)
            .unwrap();

        assert_eq!(result.trust_anchor_id(), "https://audit.ca");
        assert_eq!(result.trust_anchor_fingerprint(), &expected_fingerprint);
        assert_eq!(result.trust_anchor_valid_until(), u64::MAX);
    }

    #[test]
    fn verify_cbor_with_trust_store_accepts_valid_chain() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();

        let store = TrustStore::new(TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://store.ca".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        }));
        let device_cert = make_device_cert(&dev_vk, "https://store.ca", "DEV-STORE", ca_seed.as_bytes());

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xDDu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        let result = verifier.verify_cbor_with_trust_store(
            &cbor, device_cert, vec![], &store, None, &nonce, 1_700_000_100,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().trust_anchor_id(), "https://store.ca");
    }

    #[test]
    fn verify_cbor_with_trust_store_rejects_expired_store() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();

        let store = TrustStore::new(TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://expired.ca".to_string(),
            not_before: 0,
            not_after: 999,
        }));
        let device_cert = make_device_cert(&dev_vk, "https://expired.ca", "DEV-EXP", ca_seed.as_bytes());

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xEEu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        let result = verifier.verify_cbor_with_trust_store(
            &cbor, device_cert, vec![], &store, None, &nonce, 1_700_000_100,
        );
        assert!(matches!(result, Err(PqRascvError::TrustAnchorExpired)));
    }
}
