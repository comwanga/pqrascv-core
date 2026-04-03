//! Error types for pqrascv-core.
//!
//! [`PqRascvError`] is the single error type used throughout the crate.
//! It is `no_std`-friendly: it never allocates and never stores heap data.

use core::fmt;

/// All errors that can occur within pqrascv-core.
///
/// This type is deliberately kept allocation-free so it is safe to use on bare-metal
/// targets where the heap may not be available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PqRascvError {
    /// A signing operation failed.
    SigningFailed,
    /// A signature verification failed (invalid signature or wrong key).
    VerificationFailed,
    /// Key generation failed (e.g. RNG exhausted).
    KeyGenerationFailed,
    /// A measurement collection step failed.
    MeasurementFailed,
    /// The nonce provided by the verifier had an unexpected length.
    InvalidNonce,
    /// CBOR serialisation failed.
    SerializationFailed,
    /// CBOR deserialisation failed.
    DeserializationFailed,
    /// A provenance/in-toto predicate was malformed.
    InvalidProvenance,
    /// The requested backend is not available (feature not compiled in).
    BackendUnavailable,
    /// The quote failed policy validation.
    PolicyViolation,
    /// An internal invariant was violated.  Should never happen in correct code.
    InternalError,
}

impl fmt::Display for PqRascvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningFailed       => f.write_str("signing failed"),
            Self::VerificationFailed  => f.write_str("signature verification failed"),
            Self::KeyGenerationFailed => f.write_str("key generation failed"),
            Self::MeasurementFailed   => f.write_str("measurement collection failed"),
            Self::InvalidNonce        => f.write_str("invalid nonce"),
            Self::SerializationFailed => f.write_str("CBOR serialisation failed"),
            Self::DeserializationFailed => f.write_str("CBOR deserialisation failed"),
            Self::InvalidProvenance   => f.write_str("invalid provenance attestation"),
            Self::BackendUnavailable  => f.write_str("backend unavailable (feature not compiled in)"),
            Self::PolicyViolation     => f.write_str("quote failed policy validation"),
            Self::InternalError       => f.write_str("internal error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PqRascvError {}
