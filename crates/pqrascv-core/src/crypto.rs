//! Post-quantum cryptography abstraction layer.
//!
//! # Design
//!
//! [`CryptoBackend`] is the central trait for all sign/verify operations.
//! Implementations must guarantee:
//!
//! - **Constant-time execution** for all operations involving secret material.
//! - **Zeroize-on-drop** for all secret key types.
//!
//! The default concrete implementation [`MlDsaBackend`] uses ML-DSA-65 (FIPS 204).
//!
//! ## Key representation
//!
//! Signing keys are stored as 32-byte seeds (not the full 4032-byte expanded
//! key).  The seed is expanded on demand before each signing operation, which
//! keeps stored key material minimal.  Verifying keys are the 1952-byte
//! encoded public key.

use crate::error::PqRascvError;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ────────────────────────────────────────────────────────────────────────────
// ────────────────────────────────────────────────────────────────────────────

/// ML-DSA-65 signing key seed size in bytes.
/// The seed is expanded to the full signing key on demand.
pub const ML_DSA_65_SEED_SIZE: usize = 32;

/// ML-DSA-65 verifying (public) key size in bytes (FIPS 204 §5).
pub const ML_DSA_65_VERIFYING_KEY_SIZE: usize = 1952;

/// ML-DSA-65 signature size in bytes.
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;

/// Domain-separation context for ML-DSA-65 attestation quote body signatures.
pub const SIGNING_CONTEXT_QUOTE: &[u8] = b"pqrascv-quote-v1";

/// Domain-separation context for ML-DSA-65 device certificate TBS signatures.
pub const SIGNING_CONTEXT_CERT: &[u8] = b"pqrascv-cert-v2";

/// Domain-separation context for ML-DSA-65 Certificate Revocation List signatures.
/// Used by `RevocationList::verify()` once CRL signature enforcement is wired in (Task 6).
pub const SIGNING_CONTEXT_CRL: &[u8] = b"pqrascv-crl-v2";

// ────────────────────────────────────────────────────────────────────────────
// Signature bytes — fixed-size, stack-allocatable
// ────────────────────────────────────────────────────────────────────────────

/// Raw ML-DSA-65 signature bytes. Fixed-size so usable without `alloc`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureBytes(pub [u8; ML_DSA_65_SIGNATURE_SIZE]);

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Zeroizing seed wrapper
// ────────────────────────────────────────────────────────────────────────────

/// A 32-byte ML-DSA-65 signing seed that zeroizes on drop.
///
/// Always prefer this type over a raw array for secret key storage so that
/// the seed is wiped from memory when the value goes out of scope.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningKeySeed([u8; ML_DSA_65_SEED_SIZE]);

impl SigningKeySeed {
    /// Wraps a raw seed.
    #[must_use]
    pub fn new(bytes: [u8; ML_DSA_65_SEED_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the raw seed bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ML_DSA_65_SEED_SIZE] {
        &self.0
    }
}

// ────────────────────────────────────────────────────────────────────────────
// CryptoBackend trait
// ────────────────────────────────────────────────────────────────────────────

/// Abstraction over post-quantum signing and verification.
///
/// Keys are passed as raw byte slices so the trait stays `no_std`-compatible
/// without needing generic associated types.
///
/// # Safety contract
///
/// - `sign` must run in constant time with respect to `signing_seed`.
/// - `verify` must run in constant time with respect to `verifying_key`.
pub trait CryptoBackend {
    /// Sign `message` using the 32-byte ML-DSA-65 seed and the given `context`.
    ///
    /// `context` must be one of the `SIGNING_CONTEXT_*` constants in this module.
    fn sign(
        &self,
        message: &[u8],
        signing_seed: &[u8],
        context: &[u8],
    ) -> Result<SignatureBytes, PqRascvError>;

    /// Verify `signature` over `message` under `verifying_key` and `context`.
    ///
    /// `context` must match the context used at signing time.
    fn verify(
        &self,
        message: &[u8],
        verifying_key: &[u8],
        signature: &[u8],
        context: &[u8],
    ) -> Result<(), PqRascvError>;
}

/// Derives a 32-byte SHA3-256 fingerprint from a verifying key.
///
/// The fingerprint is embedded in [`QuoteBody`](crate::quote::QuoteBody) so verifiers can
/// confirm a quote was signed by the key they trust without re-doing the full
/// signature check first.
#[must_use]
pub fn pub_key_id(verifying_key: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(verifying_key);
    h.finalize().into()
}

// ────────────────────────────────────────────────────────────────────────────
// MlDsaBackend
// ────────────────────────────────────────────────────────────────────────────

/// Concrete [`CryptoBackend`] using `RustCrypto`'s `ml-dsa` crate (ML-DSA-65, FIPS 204).
///
/// Signing is deterministic (no randomness required at sign-time) and
/// all operations are constant-time as guaranteed by the `ml-dsa` crate.
#[derive(Debug, Default, Clone, Copy)]
pub struct MlDsaBackend;

impl CryptoBackend for MlDsaBackend {
    fn sign(
        &self,
        message: &[u8],
        signing_seed: &[u8],
        context: &[u8],
    ) -> Result<SignatureBytes, PqRascvError> {
        use ml_dsa::{KeyGen, MlDsa65};

        let seed_array: &[u8; ML_DSA_65_SEED_SIZE] = signing_seed
            .try_into()
            .map_err(|_| PqRascvError::SigningFailed)?;

        let seed = ml_dsa::B32::from(*seed_array);
        let sk = MlDsa65::from_seed(&seed);

        let sig = sk
            .signing_key()
            .sign_deterministic(message, context)
            .map_err(|_| PqRascvError::SigningFailed)?;

        let encoded = sig.encode();
        let sig_bytes: [u8; ML_DSA_65_SIGNATURE_SIZE] = (*encoded)
            .try_into()
            .map_err(|_| PqRascvError::SigningFailed)?;

        Ok(SignatureBytes(sig_bytes))
    }

    fn verify(
        &self,
        message: &[u8],
        verifying_key: &[u8],
        signature: &[u8],
        context: &[u8],
    ) -> Result<(), PqRascvError> {
        use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

        if verifying_key.len() != ML_DSA_65_VERIFYING_KEY_SIZE {
            return Err(PqRascvError::VerificationFailed);
        }
        if signature.len() != ML_DSA_65_SIGNATURE_SIZE {
            return Err(PqRascvError::VerificationFailed);
        }

        let vk_array: [u8; ML_DSA_65_VERIFYING_KEY_SIZE] = verifying_key
            .try_into()
            .map_err(|_| PqRascvError::VerificationFailed)?;
        let encoded_vk = EncodedVerifyingKey::<MlDsa65>::from(vk_array);
        let vk = VerifyingKey::<MlDsa65>::decode(&encoded_vk);

        let sig_array: [u8; ML_DSA_65_SIGNATURE_SIZE] = signature
            .try_into()
            .map_err(|_| PqRascvError::VerificationFailed)?;
        let encoded_sig = ml_dsa::EncodedSignature::<MlDsa65>::from(sig_array);
        let sig =
            Signature::<MlDsa65>::decode(&encoded_sig).ok_or(PqRascvError::VerificationFailed)?;

        if vk.verify_with_context(message, context, &sig) {
            Ok(())
        } else {
            Err(PqRascvError::VerificationFailed)
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ────────────────────────────────────────────────────────────────────────────

/// Generates a fresh ML-DSA-65 key pair using the OS random source.
///
/// Returns `(seed, verifying_key_bytes)` where:
/// - `seed` is a 32-byte [`SigningKeySeed`] (zeroizes on drop).
/// - `verifying_key_bytes` is the 1952-byte encoded verifying key.
///
/// # Security
///
/// Uses [`getrandom::SysRng`] internally, which sources entropy from the OS.
/// The returned [`SigningKeySeed`] must be kept secret.
#[cfg(feature = "std")]
pub fn generate_ml_dsa_keypair(
) -> Result<(SigningKeySeed, [u8; ML_DSA_65_VERIFYING_KEY_SIZE]), PqRascvError> {
    use getrandom::rand_core::UnwrapErr;
    use getrandom::SysRng;
    use ml_dsa::signature::Keypair;
    use ml_dsa::{KeyGen, MlDsa65};

    let mut rng = UnwrapErr(SysRng);

    let sk = MlDsa65::key_gen(&mut rng);
    let seed = sk.to_seed();

    let vk_encoded = sk.verifying_key().encode();
    let vk_bytes: [u8; ML_DSA_65_VERIFYING_KEY_SIZE] = (*vk_encoded)
        .try_into()
        .map_err(|_| PqRascvError::KeyGenerationFailed)?;

    let seed_array: [u8; ML_DSA_65_SEED_SIZE] = (*seed)
        .try_into()
        .map_err(|_| PqRascvError::KeyGenerationFailed)?;

    Ok((SigningKeySeed::new(seed_array), vk_bytes))
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Key generation needs OS entropy, so these tests only run with std.
    #[cfg(feature = "std")]
    #[test]
    fn sign_and_verify_roundtrip() {
        let (seed, vk) = generate_ml_dsa_keypair().expect("keygen failed");
        let backend = MlDsaBackend;
        let message = b"hello pqrascv-core";

        let sig = backend
            .sign(message, seed.as_bytes(), b"test-ctx")
            .expect("sign failed");
        backend
            .verify(message, &vk, sig.as_ref(), b"test-ctx")
            .expect("verify failed");
    }

    #[cfg(feature = "std")]
    #[test]
    fn verify_rejects_tampered_message() {
        let (seed, vk) = generate_ml_dsa_keypair().expect("keygen failed");
        let backend = MlDsaBackend;

        let sig = backend
            .sign(b"original", seed.as_bytes(), b"test-ctx")
            .expect("sign failed");
        assert!(backend
            .verify(b"tampered", &vk, sig.as_ref(), b"test-ctx")
            .is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn verify_rejects_wrong_key() {
        let (seed1, _vk1) = generate_ml_dsa_keypair().expect("keygen 1 failed");
        let (_seed2, vk2) = generate_ml_dsa_keypair().expect("keygen 2 failed");
        let backend = MlDsaBackend;

        let sig = backend
            .sign(b"cross-key test", seed1.as_bytes(), b"test-ctx")
            .expect("sign failed");
        assert!(backend
            .verify(b"cross-key test", &vk2, sig.as_ref(), b"test-ctx")
            .is_err());
    }

    #[test]
    fn pub_key_id_is_deterministic() {
        let vk = [0u8; ML_DSA_65_VERIFYING_KEY_SIZE];
        assert_eq!(pub_key_id(&vk), pub_key_id(&vk));
    }

    #[cfg(feature = "std")]
    #[test]
    fn signing_is_deterministic() {
        // Signing the same message twice with the same seed must give the same result.
        let (seed, _vk) = generate_ml_dsa_keypair().expect("keygen failed");
        let backend = MlDsaBackend;
        let message = b"determinism test";

        let sig1 = backend.sign(message, seed.as_bytes(), b"test-ctx").unwrap();
        let sig2 = backend.sign(message, seed.as_bytes(), b"test-ctx").unwrap();
        assert_eq!(sig1, sig2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn different_contexts_produce_incompatible_signatures() {
        let (seed, vk) = generate_ml_dsa_keypair().expect("keygen failed");
        let backend = MlDsaBackend;
        let message = b"domain-separation-test";

        let sig_a = backend
            .sign(message, seed.as_bytes(), SIGNING_CONTEXT_QUOTE)
            .expect("sign failed");
        let sig_b = backend
            .sign(message, seed.as_bytes(), SIGNING_CONTEXT_CERT)
            .expect("sign failed");

        assert_ne!(sig_a, sig_b, "contexts must produce distinct signatures");

        assert!(
            backend
                .verify(message, &vk, sig_a.as_ref(), SIGNING_CONTEXT_CERT)
                .is_err(),
            "quote sig must not verify under cert context"
        );
        assert!(
            backend
                .verify(message, &vk, sig_b.as_ref(), SIGNING_CONTEXT_QUOTE)
                .is_err(),
            "cert sig must not verify under quote context"
        );
    }
}
