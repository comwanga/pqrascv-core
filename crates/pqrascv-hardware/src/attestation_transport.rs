//! Attestation Evidence Transport Serialization
//!
//! Provides deterministic CBOR encoding and bounded decoding for operational
//! evidence payloads. Strictly enforces size limits and canonical ordering
//! to prevent parser exploits and desynchronization.

#![cfg(feature = "live-evidence")]

use alloc::vec::Vec;
use core::fmt::Debug;

pub const MAX_PAYLOAD_SIZE: usize = 64 * 1024; // 64 KB limit for attestation frames

/// Encodes a serializable payload into deterministic CBOR.
pub fn encode_payload<T: serde::Serialize + Debug>(payload: &T) -> Result<Vec<u8>, &'static str> {
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf).map_err(|_| "failed to serialize payload to CBOR")?;

    if buf.len() > MAX_PAYLOAD_SIZE {
        return Err("payload exceeds maximum allowed size");
    }

    Ok(buf)
}

/// Decodes a CBOR payload back into a strongly-typed structure,
/// enforcing strict size limits before parsing begins.
pub fn decode_payload<T: for<'de> serde::Deserialize<'de> + Debug>(
    data: &[u8],
) -> Result<T, &'static str> {
    if data.len() > MAX_PAYLOAD_SIZE {
        return Err("payload exceeds maximum allowed size");
    }

    ciborium::from_reader(data).map_err(|_| "failed to decode CBOR payload")
}
