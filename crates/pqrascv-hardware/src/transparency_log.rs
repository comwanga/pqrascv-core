//! Transparency Log
//!
//! Models append-only transparency structures to commit attestation events
//! to public/immutable logs (e.g. Bitcoin anchoring).

use crate::digest::TypedDigest;
use alloc::string::String;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_256};

/// Error returned when serialization of a transparency event fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransparencySerializationError;

impl core::fmt::Display for TransparencySerializationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("transparency event serialization failed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TransparencySerializationError {}

/// A single event recorded in the system transparency log.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransparencyEvent {
    /// Unix timestamp when the event was recorded.
    pub timestamp: u64,
    /// Unique identification of the device that produced the attestation.
    pub device_id: String,
    /// Cryptographic digest of the underlying attestation record.
    pub event_hash: TypedDigest,
}

impl TransparencyEvent {
    /// Serializes the event to CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, TransparencySerializationError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|_| TransparencySerializationError)?;
        Ok(buf)
    }

    /// Computes the canonical SHA3-256 hash of this event.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if CBOR encoding fails.
    pub fn canonical_hash(&self) -> Result<[u8; 32], TransparencySerializationError> {
        let bytes = self.to_cbor()?;
        let mut hasher = Sha3_256::new();
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }
}
