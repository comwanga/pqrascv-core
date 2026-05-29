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
    ///
    /// The embedded string names the rule that rejected the quote, e.g.
    /// `"RequireHardwareBackend"` or `"MinSlsaLevel"`.
    PolicyViolation(&'static str),
    /// The quote's protocol version is not supported by this verifier.
    UnsupportedVersion,
    /// The quote was generated without a real-time clock and the policy
    /// requires one (`allow_rtcless_devices` is false).
    RtcRequired,
    /// Certificate chain validation failed (v2 PKI).
    CertificateInvalid,
    /// Certificate has been revoked.
    CertificateRevoked,
    /// The trust anchor is outside its valid time window (`not_before`/`not_after`).
    TrustAnchorExpired,
    /// The external provenance bundle signature is invalid (v2 Sigstore).
    ProvenanceBundleInvalid,
    /// Something that should never happen did. This is a bug in the library — please file an issue.
    InternalError,
}

impl fmt::Display for PqRascvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningFailed => f.write_str("signing failed"),
            Self::VerificationFailed => f.write_str("signature verification failed"),
            Self::KeyGenerationFailed => f.write_str("key generation failed"),
            Self::MeasurementFailed => f.write_str("measurement collection failed"),
            Self::InvalidNonce => f.write_str("invalid nonce"),
            Self::SerializationFailed => f.write_str("CBOR serialization failed"),
            Self::DeserializationFailed => f.write_str("CBOR deserialization failed"),
            Self::InvalidProvenance => f.write_str("invalid provenance attestation"),
            Self::BackendUnavailable => {
                f.write_str("backend unavailable (feature not compiled in)")
            }
            Self::PolicyViolation(rule) => write!(f, "policy violation: {rule}"),
            Self::UnsupportedVersion => f.write_str("unsupported protocol version"),
            Self::RtcRequired => {
                f.write_str("quote has no timestamp and policy requires a real-time clock")
            }
            Self::CertificateInvalid => f.write_str("certificate chain validation failed"),
            Self::CertificateRevoked => f.write_str("certificate has been revoked"),
            Self::TrustAnchorExpired => {
                f.write_str("trust anchor is outside its valid time window")
            }
            Self::ProvenanceBundleInvalid => {
                f.write_str("external provenance bundle signature is invalid")
            }
            Self::InternalError => f.write_str("internal error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PqRascvError {}

#[cfg(all(test, feature = "std"))]
mod error_tests {
    use super::*;

    #[test]
    fn trust_anchor_expired_displays_correctly() {
        let e = PqRascvError::TrustAnchorExpired;
        assert_eq!(
            e.to_string(),
            "trust anchor is outside its valid time window"
        );
    }
}
