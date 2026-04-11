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
// Size constants
// ────────────────────────────────────────────────────────────────────────────

/// ML-DSA-65 signing key seed size in bytes.
/// The seed is expanded to the full signing key on demand.
pub const ML_DSA_65_SEED_SIZE: usize = 32;

/// ML-DSA-65 verifying (public) key size in bytes (FIPS 204 §5).
pub const ML_DSA_65_VERIFYING_KEY_SIZE: usize = 1952;

/// ML-DSA-65 signature size in bytes.
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;

// ────────────────────────────────────────────────────────────────────────────
// Signature bytes — fixed-size, stack-allocatable
// ────────────────────────────────────────────────────────────────────────────

/// Raw ML-DSA-65 signature bytes.  Fixed-size so usable without `alloc`.
#[derive(Clone)]
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
pub struct SigningKeySeed(pub [u8; ML_DSA_65_SEED_SIZE]);

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
    /// Sign `message` using the 32-byte ML-DSA-65 seed.
    ///
    /// The seed is expanded to the full signing key inside this call and is
    /// never stored.  We pass empty context bytes, as the spec requires.
    fn sign(&self, message: &[u8], signing_seed: &[u8]) -> Result<SignatureBytes, PqRascvError>;

    /// Verify `signature` over `message` using the encoded verifying key.
    fn verify(
        &self,
        message: &[u8],
        verifying_key: &[u8],
        signature: &[u8],
    ) -> Result<(), PqRascvError>;

    /// Derive a 32-byte SHA3-256 fingerprint of a verifying key.
    #[must_use]
    fn pub_key_id(verifying_key: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(verifying_key);
        h.finalize().into()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// MlDsaBackend
// ────────────────────────────────────────────────────────────────────────────

/// Concrete [`CryptoBackend`] using `RustCrypto`'s `ml-dsa` crate (ML-DSA-65, FIPS 204).
///
/// Signing is deterministic (no randomness required at sign-time) as
/// per the FIPS 204 §5.2 pure-message deterministic API.
/// All operations are constant-time as guaranteed by the `ml-dsa` crate.
pub struct MlDsaBackend;

impl CryptoBackend for MlDsaBackend {
    fn sign(&self, message: &[u8], signing_seed: &[u8]) -> Result<SignatureBytes, PqRascvError> {
        use ml_dsa::{KeyGen, MlDsa65};

        let seed_array: &[u8; ML_DSA_65_SEED_SIZE] = signing_seed
            .try_into()
            .map_err(|_| PqRascvError::SigningFailed)?;

        let seed = ml_dsa::B32::from(*seed_array);

        // Expand seed → full signing key (constant-time, no heap).
        let sk = MlDsa65::from_seed(&seed);

        // Sign with empty context — deterministic, so no randomness needed here.
        let sig = sk
            .signing_key()
            .sign_deterministic(message, b"")
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

        // Returns bool, not Result — so we convert it ourselves.
        if vk.verify_with_context(message, b"", &sig) {
            Ok(())
        } else {
            Err(PqRascvError::VerificationFailed)
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Key generation
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

        let sig = backend.sign(message, seed.as_bytes()).expect("sign failed");
        backend
            .verify(message, &vk, sig.as_ref())
            .expect("verify failed");
    }

    #[cfg(feature = "std")]
    #[test]
    fn verify_rejects_tampered_message() {
        let (seed, vk) = generate_ml_dsa_keypair().expect("keygen failed");
        let backend = MlDsaBackend;

        let sig = backend
            .sign(b"original", seed.as_bytes())
            .expect("sign failed");
        assert!(backend.verify(b"tampered", &vk, sig.as_ref()).is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn verify_rejects_wrong_key() {
        let (seed1, _vk1) = generate_ml_dsa_keypair().expect("keygen 1 failed");
        let (_seed2, vk2) = generate_ml_dsa_keypair().expect("keygen 2 failed");
        let backend = MlDsaBackend;

        let sig = backend
            .sign(b"cross-key test", seed1.as_bytes())
            .expect("sign failed");
        assert!(backend
            .verify(b"cross-key test", &vk2, sig.as_ref())
            .is_err());
    }

    #[test]
    fn pub_key_id_is_deterministic() {
        let vk = [0u8; ML_DSA_65_VERIFYING_KEY_SIZE];
        assert_eq!(MlDsaBackend::pub_key_id(&vk), MlDsaBackend::pub_key_id(&vk));
    }

    #[cfg(feature = "std")]
    #[test]
    fn signing_is_deterministic() {
        // Signing the same message twice with the same seed must give the same result.
        let (seed, _vk) = generate_ml_dsa_keypair().expect("keygen failed");
        let backend = MlDsaBackend;
        let message = b"determinism test";

        let sig1 = backend.sign(message, seed.as_bytes()).unwrap();
        let sig2 = backend.sign(message, seed.as_bytes()).unwrap();
        assert_eq!(sig1.0, sig2.0);
    }
}
