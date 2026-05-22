# Transparency Logging Framework

Transparency logging provides a mechanism to publicly record verification events. By committing verification outcomes to an append-only log, administrators can audit the history of all attestations and detect double-attestation or retrofitted history attacks.

## Transparency Event Model

A single entry in the transparency log is represented by the `TransparencyEvent` struct:

```rust
pub struct TransparencyEvent {
    /// Unix timestamp when the event was recorded.
    pub timestamp: u64,
    /// Unique identification of the device that produced the attestation.
    pub device_id: String,
    /// Cryptographic digest of the underlying attestation record.
    pub event_hash: TypedDigest,
}
```

## Serialization and Canonical Hashing

To ensure the integrity of the log entry and allow inclusion verification, each `TransparencyEvent` is hashed using a deterministic process:

1. **CBOR Serialization**: The event is serialized into Concise Binary Object Representation (CBOR) using `ciborium`.
2. **Canonical Hashing**: The serialized bytes are hashed using **SHA3-256** to yield a stable 32-byte identifier.

```rust
impl TransparencyEvent {
    /// Serializes the event to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, TransparencySerializationError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|_| TransparencySerializationError)?;
        Ok(buf)
    }

    /// Computes the canonical SHA3-256 hash of this event.
    pub fn canonical_hash(&self) -> Result[[u8; 32], TransparencySerializationError> {
        let bytes = self.to_cbor()?;
        let mut hasher = Sha3_256::new();
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }
}
```

These canonical hashes can then be batched and aggregated in a Merkle tree for anchoring to a public blockchain (like Bitcoin).
