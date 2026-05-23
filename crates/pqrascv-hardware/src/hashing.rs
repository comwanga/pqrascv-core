use sha3::{Digest, Sha3_256};

/// A standardized hashing wrapper to ensure deterministic algorithm usage across modules.
pub struct Hasher {
    inner: Sha3_256,
}

impl Hasher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha3_256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize().into()
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}
