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
    /// The decoded quote — included even when verification fails so you can
    /// inspect what went wrong.
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
        let quote = AttestationQuote::from_cbor(cbor)?;

        self.verify_quote(&quote, verifying_key, expected_nonce, now_secs)?;

        Ok(VerificationResult { ok: true, quote })
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
        // Nonce must match what we originally sent — if it doesn't, this is a replay or mix-up.
        if &quote.body.nonce != expected_nonce {
            return Err(PqRascvError::VerificationFailed);
        }

        // Make sure the quote was signed with the key we actually trust.
        let expected_id = MlDsaBackend::pub_key_id(verifying_key);
        if quote.body.pub_key_id != expected_id {
            return Err(PqRascvError::VerificationFailed);
        }

        // Re-serialize the body and check the signature over it.
        let body_cbor = quote.body.to_cbor()?;
        MlDsaBackend.verify(&body_cbor, verifying_key, &quote.signature)?;

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

        // Mess with the event counter after it's been signed — signature should break.
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
