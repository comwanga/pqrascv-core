//! ML-DSA keypair storage: filesystem-backed, keyed by string label.
//!
//! Blob format: [seed (32 bytes) || verifying_key (1952 bytes)] = 1984 bytes total.
//! Files are created with mode 0o600 on Unix.

use pqrascv_core::crypto::{
    generate_ml_dsa_keypair, CryptoBackend, MlDsaBackend, ML_DSA_65_SEED_SIZE,
    SIGNING_CONTEXT_QUOTE,
};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const BLOB_LEN: usize = ML_DSA_65_SEED_SIZE + pqrascv_core::crypto::ML_DSA_65_VERIFYING_KEY_SIZE;

pub struct KeyStore {
    base_dir: PathBuf,
}

impl KeyStore {
    pub fn new(base_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        std::fs::create_dir_all(base_dir.as_ref())?;
        Ok(Self {
            base_dir: base_dir.as_ref().to_path_buf(),
        })
    }

    fn key_path(&self, label: &str) -> Result<PathBuf, KeyStoreError> {
        if label.contains("..") || label.starts_with('/') || label.is_empty() {
            return Err(KeyStoreError::Internal("invalid label".into()));
        }
        Ok(self
            .base_dir
            .join(format!("{}.keypair", label.replace('/', "_"))))
    }

    pub fn generate(&self, label: &str) -> Result<Vec<u8>, KeyStoreError> {
        let path = self.key_path(label)?;
        if path.exists() {
            return Err(KeyStoreError::AlreadyExists(label.to_string()));
        }
        let (seed, vk_bytes) =
            generate_ml_dsa_keypair().map_err(|e| KeyStoreError::Internal(e.to_string()))?;

        let mut blob = Zeroizing::new(vec![0u8; BLOB_LEN]);
        blob[..ML_DSA_65_SEED_SIZE].copy_from_slice(seed.as_bytes());
        blob[ML_DSA_65_SEED_SIZE..].copy_from_slice(&vk_bytes);

        write_secret_file(&path, &blob)?;
        Ok(vk_bytes.to_vec())
    }

    pub fn public_key(&self, label: &str) -> Result<Vec<u8>, KeyStoreError> {
        let blob = read_secret_file(&self.key_path(label)?)?;
        if blob.len() != BLOB_LEN {
            return Err(KeyStoreError::Internal("corrupt keypair blob".into()));
        }
        Ok(blob[ML_DSA_65_SEED_SIZE..].to_vec())
    }

    pub fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        let blob = Zeroizing::new(read_secret_file(&self.key_path(label)?)?);
        if blob.len() != BLOB_LEN {
            return Err(KeyStoreError::Internal("corrupt keypair blob".into()));
        }
        let seed_bytes = &blob[..ML_DSA_65_SEED_SIZE];
        let backend = MlDsaBackend;
        let sig = backend
            .sign(data, seed_bytes, SIGNING_CONTEXT_QUOTE)
            .map_err(|e| KeyStoreError::Internal(e.to_string()))?;
        Ok(sig.as_ref().to_vec())
    }

    pub fn delete(&self, label: &str) -> Result<(), KeyStoreError> {
        let path = self.key_path(label)?;
        if !path.exists() {
            return Err(KeyStoreError::NotFound(label.to_string()));
        }
        std::fs::remove_file(path).map_err(|e| KeyStoreError::Io(e.to_string()))
    }

    pub fn rotate(&self, label: &str) -> Result<Vec<u8>, KeyStoreError> {
        let path = self.key_path(label)?;
        let tmp_path = self
            .base_dir
            .join(format!("{}.keypair.new", label.replace('/', "_")));

        let (seed, vk_bytes) =
            generate_ml_dsa_keypair().map_err(|e| KeyStoreError::Internal(e.to_string()))?;
        let mut blob = Zeroizing::new(vec![0u8; BLOB_LEN]);
        blob[..ML_DSA_65_SEED_SIZE].copy_from_slice(seed.as_bytes());
        blob[ML_DSA_65_SEED_SIZE..].copy_from_slice(&vk_bytes);

        write_secret_file(&tmp_path, &blob)?;
        std::fs::rename(&tmp_path, &path).map_err(|e| KeyStoreError::Io(e.to_string()))?;
        Ok(vk_bytes.to_vec())
    }
}

fn write_secret_file(path: &Path, data: &[u8]) -> Result<(), KeyStoreError> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| KeyStoreError::Io(e.to_string()))?;
    f.write_all(data)
        .map_err(|e| KeyStoreError::Io(e.to_string()))
}

fn read_secret_file(path: &Path) -> Result<Vec<u8>, KeyStoreError> {
    if !path.exists() {
        return Err(KeyStoreError::NotFound(path.to_string_lossy().into()));
    }
    std::fs::read(path).map_err(|e| KeyStoreError::Io(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("key already exists: {0}")]
    AlreadyExists(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store() -> (TempDir, KeyStore) {
        let dir = TempDir::new().unwrap();
        let store = KeyStore::new(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn generate_returns_public_key_bytes() {
        let (_dir, store) = store();
        let vk = store.generate("test-key").unwrap();
        assert!(!vk.is_empty());
    }

    #[test]
    fn generate_twice_fails_with_already_exists() {
        let (_dir, store) = store();
        store.generate("key").unwrap();
        let err = store.generate("key").unwrap_err();
        assert!(matches!(err, KeyStoreError::AlreadyExists(_)));
    }

    #[test]
    fn public_key_returns_same_as_generate() {
        let (_dir, store) = store();
        let vk1 = store.generate("key").unwrap();
        let vk2 = store.public_key("key").unwrap();
        assert_eq!(vk1, vk2);
    }

    #[test]
    fn sign_returns_non_empty_signature() {
        let (_dir, store) = store();
        store.generate("key").unwrap();
        let sig = store.sign("key", b"test-message").unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn delete_removes_key() {
        let (_dir, store) = store();
        store.generate("key").unwrap();
        store.delete("key").unwrap();
        let err = store.sign("key", b"msg").unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(_)));
    }

    #[test]
    fn rotate_changes_public_key() {
        let (_dir, store) = store();
        let vk1 = store.generate("key").unwrap();
        let vk2 = store.rotate("key").unwrap();
        assert_ne!(vk1, vk2);
    }

    #[test]
    fn delete_nonexistent_key_fails() {
        let (_dir, store) = store();
        let err = store.delete("ghost").unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(_)));
    }
}
