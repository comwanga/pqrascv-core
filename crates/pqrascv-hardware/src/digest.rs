//! Typed digest model — eliminates algorithm ambiguity in measurements.
//!
//! # Problem
//!
//! The v1 audit identified that the TPM backend mixed SHA-256 PCRs with
//! SHA3-256 firmware hashes, producing a `PcrBank` where the `algorithm`
//! field claimed `Sha3_256` but some values were actually normalized
//! SHA-256 digests. Policy rules comparing PCR values across backends
//! could silently compare incompatible values.
//!
//! # Solution
//!
//! Every digest in this crate is a [`TypedDigest`] — a value paired with
//! its algorithm. Operations that combine digests from different algorithms
//! are a compile-time type error or an explicit runtime error, never silent.
//!
//! # Wire format
//!
//! `TypedDigest` serializes as a two-field CBOR map:
//! ```text
//! { "alg": <u8>, "val": <bytes> }
//! ```
//! The `alg` field uses the [`DigestAlgorithm`] discriminant. Unknown
//! discriminants are rejected during deserialization.

use core::fmt;

// ── DigestAlgorithm ───────────────────────────────────────────────────────

/// Hash algorithm used to produce a [`TypedDigest`].
///
/// The discriminant values are stable wire identifiers — do not reorder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum DigestAlgorithm {
    /// SHA-256 (FIPS 180-4). Used natively by TPM 2.0 PCR banks.
    Sha256 = 0x01,
    /// SHA3-256 (FIPS 202). Canonical algorithm for all PQ-RASCV measurements.
    Sha3_256 = 0x02,
}

impl DigestAlgorithm {
    /// Returns the output length in bytes for this algorithm.
    #[must_use]
    pub const fn output_len(self) -> usize {
        32 // both SHA-256 and SHA3-256 produce 32-byte digests
    }

    /// Returns a human-readable name for display and logging.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha3_256 => "SHA3-256",
        }
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── TypedDigest ───────────────────────────────────────────────────────────

/// A cryptographic digest paired with its algorithm.
///
/// This is the canonical measurement value type throughout `pqrascv-hardware`.
/// Raw `[u8; 32]` arrays are never used for measurements — the algorithm is
/// always explicit.
///
/// # Equality
///
/// Two `TypedDigest` values are equal only if both the algorithm AND the
/// value match. A SHA-256 digest and a SHA3-256 digest of the same input
/// are NOT equal, even if the byte values happen to collide.
///
/// # Normalization
///
/// The TPM backend produces SHA-256 digests from hardware. Before storing
/// them in a [`PcrMeasurement`](crate::pcr::PcrMeasurement), they are
/// normalized to SHA3-256 via `TypedDigest::normalize_to_sha3_256()`.
/// The original algorithm is preserved in the `source_algorithm` field of
/// the measurement for auditability.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TypedDigest {
    /// The hash algorithm that produced `value`.
    pub algorithm: DigestAlgorithm,
    /// The raw digest bytes.
    pub value: [u8; 32],
}

impl TypedDigest {
    /// Constructs a `TypedDigest` from a known algorithm and value.
    #[must_use]
    pub const fn new(algorithm: DigestAlgorithm, value: [u8; 32]) -> Self {
        Self { algorithm, value }
    }

    /// Constructs a SHA3-256 digest by hashing `data`.
    #[must_use]
    pub fn sha3_256(data: &[u8]) -> Self {
        use sha3::{Digest, Sha3_256};
        let value: [u8; 32] = Sha3_256::digest(data).into();
        Self::new(DigestAlgorithm::Sha3_256, value)
    }

    /// Constructs a SHA-256 digest by hashing `data`.
    #[must_use]
    pub fn sha256(data: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let value: [u8; 32] = Sha256::digest(data).into();
        Self::new(DigestAlgorithm::Sha256, value)
    }

    /// Wraps a raw SHA-256 PCR value (from TPM hardware) without re-hashing.
    ///
    /// Use this when the TPM has already produced the digest and you are
    /// recording it verbatim before normalization.
    #[must_use]
    pub const fn from_tpm_sha256_pcr(raw: [u8; 32]) -> Self {
        Self::new(DigestAlgorithm::Sha256, raw)
    }

    /// Normalizes this digest to SHA3-256 by hashing the value bytes.
    ///
    /// Used by the TPM backend to convert hardware SHA-256 PCRs into the
    /// canonical SHA3-256 representation required by policy rules.
    ///
    /// ```text
    /// normalized = SHA3-256( self.value )
    /// ```
    ///
    /// If `self.algorithm` is already `Sha3_256`, returns `*self` unchanged.
    #[must_use]
    pub fn normalize_to_sha3_256(self) -> Self {
        if self.algorithm == DigestAlgorithm::Sha3_256 {
            return self;
        }
        Self::sha3_256(&self.value)
    }

    /// Returns `true` if this digest uses the canonical PQ-RASCV algorithm.
    #[must_use]
    pub fn is_canonical(self) -> bool {
        self.algorithm == DigestAlgorithm::Sha3_256
    }

    /// Returns a hex-encoded string of the digest value (lowercase).
    #[cfg(feature = "std")]
    #[must_use]
    pub fn hex(&self) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::with_capacity(64);
        for b in &self.value {
            write!(s, "{b:02x}").expect("write to String never fails");
        }
        s
    }
}

impl fmt::Debug for TypedDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TypedDigest({}, ", self.algorithm)?;
        for b in &self.value {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_256_is_deterministic() {
        let d1 = TypedDigest::sha3_256(b"hello");
        let d2 = TypedDigest::sha3_256(b"hello");
        assert_eq!(d1, d2);
        assert_eq!(d1.algorithm, DigestAlgorithm::Sha3_256);
    }

    #[test]
    fn sha256_and_sha3_256_are_not_equal() {
        let d_sha2 = TypedDigest::sha256(b"hello");
        let d_sha3 = TypedDigest::sha3_256(b"hello");
        // Different algorithms → not equal, even if values happened to match.
        assert_ne!(d_sha2.algorithm, d_sha3.algorithm);
        assert_ne!(d_sha2, d_sha3);
    }

    #[test]
    fn normalize_sha256_to_sha3_256() {
        let raw = [0x42u8; 32];
        let tpm_pcr = TypedDigest::from_tpm_sha256_pcr(raw);
        assert_eq!(tpm_pcr.algorithm, DigestAlgorithm::Sha256);

        let normalized = tpm_pcr.normalize_to_sha3_256();
        assert_eq!(normalized.algorithm, DigestAlgorithm::Sha3_256);
        // Normalized value is SHA3-256 of the raw PCR bytes.
        let expected = TypedDigest::sha3_256(&raw);
        assert_eq!(normalized, expected);
    }

    #[test]
    fn normalize_sha3_256_is_identity() {
        let d = TypedDigest::sha3_256(b"firmware");
        assert_eq!(d.normalize_to_sha3_256(), d);
    }

    #[test]
    fn is_canonical_only_for_sha3_256() {
        assert!(TypedDigest::sha3_256(b"x").is_canonical());
        assert!(!TypedDigest::sha256(b"x").is_canonical());
    }

    #[test]
    fn different_data_different_digest() {
        let d1 = TypedDigest::sha3_256(b"firmware-v1");
        let d2 = TypedDigest::sha3_256(b"firmware-v2");
        assert_ne!(d1, d2);
    }

    #[test]
    fn algorithm_output_len() {
        assert_eq!(DigestAlgorithm::Sha256.output_len(), 32);
        assert_eq!(DigestAlgorithm::Sha3_256.output_len(), 32);
    }
}
