//! HSM / PKCS#11 key-provider abstraction for CA signing keys.
//!
//! # Design
//!
//! Operators integrate Hardware Security Modules (HSMs) by implementing the
//! [`KeyProvider`] trait against their PKCS#11 module. The trait is the *only*
//! integration hook: `pqrascv-core` itself takes **no** dependency on
//! `cryptoki`/`pkcs11` (or any other HSM SDK). This keeps the core `no_std`-
//! capable and lets each deployment bind to its own vendor library.
//!
//! The trait captures the operations an offline Root CA or HSM-protected
//! intermediate CA needs:
//!
//! - **Session lifecycle** — [`KeyProvider::open_session`] / [`KeyProvider::close_session`].
//! - **Key generation** — [`KeyProvider::generate_keypair`] creates a new
//!   ML-DSA-65 keypair *inside* the provider; the private half never leaves it.
//! - **Import** — [`KeyProvider::import_keypair`] loads an externally generated
//!   seed (e.g. from an air-gapped ceremony) into the provider.
//! - **Public-key export** — [`KeyProvider::public_key`] returns the 1952-byte
//!   ML-DSA-65 verifying key for a handle (public material only).
//! - **Signing** — [`KeyProvider::sign`] signs a TBS blob with a handle's
//!   private key, delegating to the device without exposing private bytes.
//! - **Key lifecycle** — [`KeyProvider::rotate`] provisions a successor handle
//!   and [`KeyProvider::destroy`] permanently removes a handle's key material.
//!
//! # Reference implementation
//!
//! [`SoftwareKeyProvider`] is a pure-software reference backed by the existing
//! [`MlDsaBackend`](crate::crypto::MlDsaBackend) and
//! [`SigningKeySeed`](crate::crypto::SigningKeySeed). It is suitable for tests,
//! CI, and non-HSM deployments. In production, the Root CA private key SHOULD
//! live in an HSM accessed through a real [`KeyProvider`] implementation.
//!
//! # Security note
//!
//! `SoftwareKeyProvider` holds raw signing seeds in process memory (zeroized on
//! drop via [`SigningKeySeed`]). A real HSM keeps the private key non-extractable
//! and performs signing on-device; the [`KeyProvider`] trait deliberately never
//! exposes private bytes so a HSM-backed impl can uphold that guarantee.

extern crate alloc;

use alloc::collections::BTreeMap;

use crate::crypto::{
    CryptoBackend, MlDsaBackend, SignatureBytes, SigningKeySeed, ML_DSA_65_VERIFYING_KEY_SIZE,
};
use crate::error::PqRascvError;

/// Opaque handle identifying a key inside a [`KeyProvider`].
///
/// Handles are stable for the lifetime of a key. They are *not* secret — they
/// are an index into the provider, analogous to a PKCS#11 object handle.
pub type KeyHandle = u64;

/// Abstraction over a key-custody device (HSM / PKCS#11 module / software vault).
///
/// Implementors hold CA private keys and perform signing on the operator's
/// behalf **without ever exposing private key bytes**. See the module docs for
/// the integration model.
///
/// # Errors
///
/// Every method returns [`PqRascvError`]. Common cases:
/// - [`PqRascvError::BackendUnavailable`] — no session open, or handle unknown.
/// - [`PqRascvError::SigningFailed`] — the underlying device failed to sign.
/// - [`PqRascvError::KeyGenerationFailed`] — keygen/import failed.
pub trait KeyProvider {
    /// Opens a session with the provider (e.g. PKCS#11 `C_OpenSession` + login).
    ///
    /// Must be called before any key operation. Idempotent re-opens are
    /// implementation-defined.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::BackendUnavailable`] if the device cannot be reached.
    fn open_session(&mut self) -> Result<(), PqRascvError>;

    /// Closes the session, releasing device resources.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::BackendUnavailable`] if no session was open.
    fn close_session(&mut self) -> Result<(), PqRascvError>;

    /// Generates a fresh ML-DSA-65 keypair inside the provider.
    ///
    /// The private key is created on the device and never leaves it. Returns a
    /// [`KeyHandle`] to reference the key in later calls.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::KeyGenerationFailed`] on RNG/device failure, or
    /// [`PqRascvError::BackendUnavailable`] if no session is open.
    fn generate_keypair(&mut self) -> Result<KeyHandle, PqRascvError>;

    /// Imports an externally generated ML-DSA-65 seed into the provider.
    ///
    /// Used to load a key produced in an air-gapped ceremony. A real HSM would
    /// import this under a wrapping key; the software reference stores it
    /// directly. Returns a handle for the imported key.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::KeyGenerationFailed`] if import fails, or
    /// [`PqRascvError::BackendUnavailable`] if no session is open.
    fn import_keypair(&mut self, seed: SigningKeySeed) -> Result<KeyHandle, PqRascvError>;

    /// Exports the **public** ML-DSA-65 verifying key for `handle` (1952 bytes).
    ///
    /// Only public material is ever returned.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::BackendUnavailable`] if the handle is unknown or
    /// no session is open.
    fn public_key(
        &self,
        handle: KeyHandle,
    ) -> Result<[u8; ML_DSA_65_VERIFYING_KEY_SIZE], PqRascvError>;

    /// Signs `message` with the private key behind `handle` under `context`.
    ///
    /// `context` must be one of the `SIGNING_CONTEXT_*` constants
    /// (e.g. [`SIGNING_CONTEXT_CERT`](crate::crypto::SIGNING_CONTEXT_CERT)).
    /// The signature is produced on-device; private bytes are not exposed.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::SigningFailed`] on device failure, or
    /// [`PqRascvError::BackendUnavailable`] if the handle is unknown / no session.
    fn sign(
        &self,
        handle: KeyHandle,
        message: &[u8],
        context: &[u8],
    ) -> Result<SignatureBytes, PqRascvError>;

    /// Provisions a successor key for `handle` and returns the new handle.
    ///
    /// This does **not** destroy the old key — both remain usable so the
    /// operator can run a dual-trust overlap window (see
    /// [`super::rotation`]). Call [`KeyProvider::destroy`] on the old handle
    /// only after the overlap window closes.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::KeyGenerationFailed`] on failure, or
    /// [`PqRascvError::BackendUnavailable`] if the handle is unknown / no session.
    fn rotate(&mut self, handle: KeyHandle) -> Result<KeyHandle, PqRascvError>;

    /// Permanently destroys the key material behind `handle`.
    ///
    /// After this call the handle is invalid and signing fails. Use only after
    /// any overlap window has closed and no in-flight certs depend on the key.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::BackendUnavailable`] if the handle is unknown or
    /// no session is open.
    fn destroy(&mut self, handle: KeyHandle) -> Result<(), PqRascvError>;
}

/// Software reference [`KeyProvider`] backed by [`MlDsaBackend`].
///
/// **Not a security boundary.** Seeds live in process memory (zeroized on drop).
/// Suitable for tests, CI, and deployments without an HSM. For production CA
/// keys, implement [`KeyProvider`] against a real PKCS#11 module instead.
pub struct SoftwareKeyProvider {
    session_open: bool,
    next_handle: KeyHandle,
    keys: BTreeMap<KeyHandle, SigningKeySeed>,
}

impl SoftwareKeyProvider {
    /// Creates an empty provider with no open session and no keys.
    #[must_use]
    pub fn new() -> Self {
        Self {
            session_open: false,
            next_handle: 1,
            keys: BTreeMap::new(),
        }
    }

    /// Returns the number of keys currently held (for diagnostics/tests).
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Returns `true` if a session is currently open.
    #[must_use]
    pub fn is_session_open(&self) -> bool {
        self.session_open
    }

    fn ensure_session(&self) -> Result<(), PqRascvError> {
        if self.session_open {
            Ok(())
        } else {
            Err(PqRascvError::BackendUnavailable)
        }
    }

    fn allocate_handle(&mut self) -> KeyHandle {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }

    fn seed_for(&self, handle: KeyHandle) -> Result<&SigningKeySeed, PqRascvError> {
        self.keys
            .get(&handle)
            .ok_or(PqRascvError::BackendUnavailable)
    }

    /// Derives the verifying key for a seed using the software backend.
    ///
    /// Signs an empty probe is unnecessary; instead we expand the seed via the
    /// same path `generate_ml_dsa_keypair` uses. This is only reachable with
    /// `std` (keygen needs the OS RNG), so seed-import provides the public key.
    fn vk_from_seed(seed: &SigningKeySeed) -> Result<[u8; ML_DSA_65_VERIFYING_KEY_SIZE], PqRascvError>
    {
        use ml_dsa::signature::Keypair;
        use ml_dsa::{KeyGen, MlDsa65};
        let seed_b32 = ml_dsa::B32::from(*seed.as_bytes());
        let sk = MlDsa65::from_seed(&seed_b32);
        let vk_encoded = sk.verifying_key().encode();
        let vk_bytes: [u8; ML_DSA_65_VERIFYING_KEY_SIZE] = (*vk_encoded)
            .try_into()
            .map_err(|_| PqRascvError::KeyGenerationFailed)?;
        Ok(vk_bytes)
    }
}

impl Default for SoftwareKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for SoftwareKeyProvider {
    fn open_session(&mut self) -> Result<(), PqRascvError> {
        self.session_open = true;
        Ok(())
    }

    fn close_session(&mut self) -> Result<(), PqRascvError> {
        if !self.session_open {
            return Err(PqRascvError::BackendUnavailable);
        }
        self.session_open = false;
        Ok(())
    }

    #[cfg(feature = "std")]
    fn generate_keypair(&mut self) -> Result<KeyHandle, PqRascvError> {
        self.ensure_session()?;
        let (seed, _vk) = crate::crypto::generate_ml_dsa_keypair()?;
        let handle = self.allocate_handle();
        self.keys.insert(handle, seed);
        Ok(handle)
    }

    #[cfg(not(feature = "std"))]
    fn generate_keypair(&mut self) -> Result<KeyHandle, PqRascvError> {
        // Keygen requires an OS RNG (std). Without it, operators must import a
        // seed produced out-of-band via `import_keypair`.
        Err(PqRascvError::BackendUnavailable)
    }

    fn import_keypair(&mut self, seed: SigningKeySeed) -> Result<KeyHandle, PqRascvError> {
        self.ensure_session()?;
        // Validate the seed expands to a usable key before storing it.
        Self::vk_from_seed(&seed)?;
        let handle = self.allocate_handle();
        self.keys.insert(handle, seed);
        Ok(handle)
    }

    fn public_key(
        &self,
        handle: KeyHandle,
    ) -> Result<[u8; ML_DSA_65_VERIFYING_KEY_SIZE], PqRascvError> {
        self.ensure_session()?;
        let seed = self.seed_for(handle)?;
        Self::vk_from_seed(seed)
    }

    fn sign(
        &self,
        handle: KeyHandle,
        message: &[u8],
        context: &[u8],
    ) -> Result<SignatureBytes, PqRascvError> {
        self.ensure_session()?;
        let seed = self.seed_for(handle)?;
        MlDsaBackend.sign(message, seed.as_bytes(), context)
    }

    #[cfg(feature = "std")]
    fn rotate(&mut self, handle: KeyHandle) -> Result<KeyHandle, PqRascvError> {
        self.ensure_session()?;
        // The predecessor must exist; the old key is intentionally retained.
        let _ = self.seed_for(handle)?;
        self.generate_keypair()
    }

    #[cfg(not(feature = "std"))]
    fn rotate(&mut self, handle: KeyHandle) -> Result<KeyHandle, PqRascvError> {
        self.ensure_session()?;
        let _ = self.seed_for(handle)?;
        Err(PqRascvError::BackendUnavailable)
    }

    fn destroy(&mut self, handle: KeyHandle) -> Result<(), PqRascvError> {
        self.ensure_session()?;
        self.keys
            .remove(&handle)
            .map(|_| ())
            .ok_or(PqRascvError::BackendUnavailable)
    }
}

#[cfg(all(test, feature = "alloc", feature = "std"))]
mod tests {
    use super::*;
    use crate::crypto::{generate_ml_dsa_keypair, CryptoBackend, MlDsaBackend, SIGNING_CONTEXT_CERT};

    #[test]
    fn operations_require_open_session() {
        let mut p = SoftwareKeyProvider::new();
        assert!(!p.is_session_open());
        assert!(matches!(
            p.generate_keypair(),
            Err(PqRascvError::BackendUnavailable)
        ));
        p.open_session().unwrap();
        assert!(p.is_session_open());
        assert!(p.generate_keypair().is_ok());
    }

    #[test]
    fn close_without_open_errors() {
        let mut p = SoftwareKeyProvider::new();
        assert!(matches!(
            p.close_session(),
            Err(PqRascvError::BackendUnavailable)
        ));
    }

    #[test]
    fn generated_public_key_verifies_provider_signature() {
        let mut p = SoftwareKeyProvider::new();
        p.open_session().unwrap();
        let h = p.generate_keypair().unwrap();
        let vk = p.public_key(h).unwrap();
        let msg = b"to-be-signed cert bytes";
        let sig = p.sign(h, msg, SIGNING_CONTEXT_CERT).unwrap();
        // The exported public key must verify the provider's own signature.
        MlDsaBackend
            .verify(msg, &vk, sig.as_ref(), SIGNING_CONTEXT_CERT)
            .expect("provider signature must verify under exported public key");
    }

    #[test]
    fn imported_seed_reproduces_its_public_key() {
        let (seed, vk) = generate_ml_dsa_keypair().unwrap();
        let mut p = SoftwareKeyProvider::new();
        p.open_session().unwrap();
        let h = p.import_keypair(seed).unwrap();
        assert_eq!(
            p.public_key(h).unwrap().as_slice(),
            vk.as_slice(),
            "imported seed must export the matching verifying key"
        );
    }

    #[test]
    fn sign_never_exposes_private_bytes_but_still_verifies() {
        // The trait surface returns only SignatureBytes / public keys; there is
        // no API to read the seed back. This test documents that contract by
        // exercising the full sign/verify path through the trait only.
        let (seed, vk) = generate_ml_dsa_keypair().unwrap();
        let mut p = SoftwareKeyProvider::new();
        p.open_session().unwrap();
        let h = p.import_keypair(seed).unwrap();
        let sig = p.sign(h, b"msg", SIGNING_CONTEXT_CERT).unwrap();
        assert!(MlDsaBackend
            .verify(b"msg", &vk, sig.as_ref(), SIGNING_CONTEXT_CERT)
            .is_ok());
    }

    #[test]
    fn unknown_handle_errors() {
        let mut p = SoftwareKeyProvider::new();
        p.open_session().unwrap();
        assert!(matches!(
            p.public_key(999),
            Err(PqRascvError::BackendUnavailable)
        ));
        assert!(matches!(
            p.sign(999, b"x", SIGNING_CONTEXT_CERT),
            Err(PqRascvError::BackendUnavailable)
        ));
    }

    #[test]
    fn rotate_keeps_old_key_and_adds_new() {
        let mut p = SoftwareKeyProvider::new();
        p.open_session().unwrap();
        let old = p.generate_keypair().unwrap();
        let old_vk = p.public_key(old).unwrap();
        let new = p.rotate(old).unwrap();
        assert_ne!(old, new, "rotate must yield a distinct handle");
        // Old key still usable during the overlap window.
        assert_eq!(p.public_key(old).unwrap().as_slice(), old_vk.as_slice());
        let new_vk = p.public_key(new).unwrap();
        assert_ne!(
            old_vk.as_slice(),
            new_vk.as_slice(),
            "successor must have a fresh key"
        );
        assert_eq!(p.key_count(), 2);
    }

    #[test]
    fn destroy_removes_key_and_blocks_signing() {
        let mut p = SoftwareKeyProvider::new();
        p.open_session().unwrap();
        let h = p.generate_keypair().unwrap();
        p.destroy(h).unwrap();
        assert!(matches!(
            p.sign(h, b"x", SIGNING_CONTEXT_CERT),
            Err(PqRascvError::BackendUnavailable)
        ));
        assert!(matches!(p.destroy(h), Err(PqRascvError::BackendUnavailable)));
    }

    #[test]
    fn rotate_unknown_handle_errors() {
        let mut p = SoftwareKeyProvider::new();
        p.open_session().unwrap();
        assert!(matches!(
            p.rotate(123),
            Err(PqRascvError::BackendUnavailable)
        ));
    }
}
