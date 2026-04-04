//! # pqrascv-verifier
//!
//! Reference verifier for the PQ-RASCV protocol.
//!
//! ## Verification procedure
//!
//! 1. Deserialise the CBOR-encoded [`AttestationQuote`] from the prover.
//! 2. Re-serialise the [`QuoteBody`] to reproduce the signing input.
//! 3. Verify the ML-DSA-65 signature using the prover's known verifying key.
//! 4. Check `body.pub_key_id` matches the expected key fingerprint.
//! 5. Apply [`PolicyConfig`] (SLSA level, age, firmware hash presence, etc.).
//!
//! This crate is `std`-only and intended for server-side or CI use.

use pqrascv_core::{
    config::PolicyConfig,
    crypto::{CryptoBackend, MlDsaBackend},
    error::PqRascvError,
    quote::AttestationQuote,
};

// ────────────────────────────────────────────────────────────────────────────
// VerificationResult
// ────────────────────────────────────────────────────────────────────────────

/// Outcome of a completed attestation verification.
#[derive(Debug)]
pub struct VerificationResult {
    /// `true` if all checks passed.
    pub ok: bool,
    /// The deserialized quote (present even if verification failed, for
    /// diagnostic purposes).
    pub quote: AttestationQuote,
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
        // 1. Deserialise.
        let quote = AttestationQuote::from_cbor(cbor)?;

        self.verify_quote(&quote, verifying_key, expected_nonce, now_secs)?;

        Ok(VerificationResult { ok: true, quote })
    }

    /// Verifies a pre-deserialized [`AttestationQuote`].
    pub fn verify_quote(
        &self,
        quote: &AttestationQuote,
        verifying_key: &[u8],
        expected_nonce: &[u8; 32],
        now_secs: u64,
    ) -> Result<(), PqRascvError> {
        // 2. Nonce check (replay protection).
        if &quote.body.nonce != expected_nonce {
            return Err(PqRascvError::VerificationFailed);
        }

        // 3. Public key fingerprint check.
        let expected_id = MlDsaBackend::pub_key_id(verifying_key);
        if quote.body.pub_key_id != expected_id {
            return Err(PqRascvError::VerificationFailed);
        }

        // 4. Reproduce the signing input and verify signature.
        let body_cbor = quote.body.to_cbor()?;
        MlDsaBackend.verify(&body_cbor, verifying_key, &quote.signature)?;

        // 5. Policy evaluation.
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
        crypto::generate_ml_dsa_keypair, measurement::SoftwareRoT,
        provenance::SlsaPredicateBuilder, quote::generate_quote,
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
            1_700_000_500,
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

        // Tamper with the event counter after signing.
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
}
