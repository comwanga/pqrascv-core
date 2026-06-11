//! Python bindings for pqrascv-core.
//!
//! Build: cd crates/pqrascv-python && maturin develop --features extension-module
//! Import: import pqrascv_python

use pqrascv_core::crypto::{
    generate_ml_dsa_keypair, CryptoBackend, MlDsaBackend, SIGNING_CONTEXT_QUOTE,
};

// ──────────────────────────────────────────────────────────────────────────────
// Pure-Rust logic layer (no pyo3 dependency, testable without Python runtime)
// ──────────────────────────────────────────────────────────────────────────────

/// Inner keypair, independent of the pyo3 layer so unit tests work without Python.
pub struct MlDsaKeyInner {
    pub(crate) seed_bytes: Vec<u8>, // 32-byte signing seed — never exposed via Debug
    pub vk_bytes: Vec<u8>,          // 1952-byte verifying key
}

impl std::fmt::Debug for MlDsaKeyInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaKeyInner")
            .field("seed_bytes", &"[REDACTED]")
            .field("vk_bytes", &format!("[{} bytes]", self.vk_bytes.len()))
            .finish()
    }
}

impl MlDsaKeyInner {
    pub fn generate() -> Result<Self, pqrascv_core::error::PqRascvError> {
        let (seed, vk) = generate_ml_dsa_keypair()?;
        Ok(Self {
            seed_bytes: seed.as_bytes().to_vec(),
            vk_bytes: vk.to_vec(),
        })
    }

    pub fn sign_msg(&self, message: &[u8]) -> Result<Vec<u8>, pqrascv_core::error::PqRascvError> {
        MlDsaBackend
            .sign(message, &self.seed_bytes, SIGNING_CONTEXT_QUOTE)
            .map(|sig| sig.as_ref().to_vec())
    }

    pub fn verify_msg(
        vk: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), pqrascv_core::error::PqRascvError> {
        MlDsaBackend.verify(message, vk, signature, SIGNING_CONTEXT_QUOTE)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PyO3 bindings — only compiled when the extension-module feature is enabled
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "extension-module")]
mod python_bindings {
    use super::*;
    use pqrascv_core::config::PolicyConfig;
    use pqrascv_verifier::Verifier;
    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;

    /// ML-DSA-65 keypair. The 32-byte seed is kept in memory.
    #[pyclass]
    pub struct MlDsaKey {
        inner: MlDsaKeyInner,
    }

    #[pymethods]
    impl MlDsaKey {
        /// Generate a new ML-DSA-65 keypair.
        #[staticmethod]
        pub fn generate() -> PyResult<Self> {
            MlDsaKeyInner::generate()
                .map(|inner| Self { inner })
                .map_err(|e| PyValueError::new_err(format!("keygen failed: {e}")))
        }

        /// Return the raw verifying (public) key bytes (1952 bytes).
        pub fn verifying_key_bytes(&self) -> Vec<u8> {
            self.inner.vk_bytes.clone()
        }

        /// Sign `message` and return the raw signature bytes.
        pub fn sign(&self, message: &[u8]) -> PyResult<Vec<u8>> {
            self.inner
                .sign_msg(message)
                .map_err(|e| PyValueError::new_err(format!("signing failed: {e}")))
        }

        /// Verify `signature` over `message` with `verifying_key_bytes`.
        /// Returns True on success, raises ValueError on failure.
        #[staticmethod]
        pub fn verify(
            verifying_key_bytes: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> PyResult<bool> {
            MlDsaKeyInner::verify_msg(verifying_key_bytes, message, signature)
                .map(|_| true)
                .map_err(|e| PyValueError::new_err(format!("verification failed: {e}")))
        }
    }

    /// Quote verifier (verifier side).
    #[pyclass]
    pub struct QuoteVerifier {
        inner: Verifier,
    }

    #[pymethods]
    impl QuoteVerifier {
        #[new]
        pub fn new() -> Self {
            Self {
                inner: Verifier::new(PolicyConfig::default()),
            }
        }

        /// Verify a CBOR-encoded AttestationQuote.
        pub fn verify_cbor(
            &self,
            quote_cbor: &[u8],
            verifying_key_bytes: &[u8],
            expected_nonce: &[u8],
            now_secs: u64,
        ) -> PyResult<bool> {
            if expected_nonce.len() != 32 {
                return Err(PyValueError::new_err(
                    "expected_nonce must be exactly 32 bytes",
                ));
            }
            let nonce: [u8; 32] = expected_nonce.try_into().unwrap();
            self.inner
                .verify_cbor(quote_cbor, verifying_key_bytes, &nonce, now_secs)
                .map(|_| true)
                .map_err(|e| PyValueError::new_err(format!("verification failed: {e}")))
        }
    }

    #[pymodule]
    pub fn pqrascv_python(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
        m.add_class::<MlDsaKey>()?;
        m.add_class::<QuoteVerifier>()?;
        Ok(())
    }
}

#[cfg(feature = "extension-module")]
pub use python_bindings::pqrascv_python;

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests — pure Rust, no Python runtime required
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_non_empty_keys() {
        let key = MlDsaKeyInner::generate().unwrap();
        assert!(!key.seed_bytes.is_empty());
        assert!(!key.vk_bytes.is_empty());
    }

    #[test]
    fn sign_verify_roundtrip_succeeds() {
        let key = MlDsaKeyInner::generate().unwrap();
        let message = b"test-attestation-payload";
        let sig = key.sign_msg(message).unwrap();
        MlDsaKeyInner::verify_msg(&key.vk_bytes, message, &sig).unwrap();
    }

    #[test]
    fn verify_wrong_message_fails() {
        let key = MlDsaKeyInner::generate().unwrap();
        let sig = key.sign_msg(b"original").unwrap();
        let result = MlDsaKeyInner::verify_msg(&key.vk_bytes, b"tampered", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_wrong_key_fails() {
        let key1 = MlDsaKeyInner::generate().unwrap();
        let key2 = MlDsaKeyInner::generate().unwrap();
        let sig = key1.sign_msg(b"msg").unwrap();
        let result = MlDsaKeyInner::verify_msg(&key2.vk_bytes, b"msg", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verifying_key_bytes_length_is_correct() {
        let key = MlDsaKeyInner::generate().unwrap();
        assert_eq!(
            key.vk_bytes.len(),
            pqrascv_core::crypto::ML_DSA_65_VERIFYING_KEY_SIZE
        );
        assert_eq!(
            key.seed_bytes.len(),
            pqrascv_core::crypto::ML_DSA_65_SEED_SIZE
        );
    }
}
