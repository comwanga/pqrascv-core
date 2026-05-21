//! Certificate revocation list (CRL) types.
//!
//! CRLs are distributed as signed CBOR lists. The verifier caches the CRL
//! locally and checks it during quote verification. For offline operation,
//! the last known CRL is used with a staleness warning.
//!
//! # Audit Finding #4 Fix (revocation component)
//!
//! v1 had no revocation mechanism. A compromised device key could sign
//! attestation quotes indefinitely. v2 adds CRL-based revocation so that
//! compromised device certificates can be invalidated.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::error::PqRascvError;

/// A single revocation entry in a CRL.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RevocationEntry {
    /// Certificate serial number being revoked.
    pub serial: String,
    /// Unix seconds when the certificate was revoked.
    pub revoked_at: u64,
    /// Human-readable reason code.
    pub reason: RevocationReason,
}

/// Reason a certificate was revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RevocationReason {
    /// Key compromise (highest severity — treat all quotes from this key as invalid).
    KeyCompromise,
    /// Device was decommissioned.
    Decommissioned,
    /// Certificate was superseded by a new one.
    Superseded,
    /// Unspecified reason.
    Unspecified,
}

/// A signed Certificate Revocation List.
///
/// Signed by the issuing CA's key. Verifiers must check the CRL signature
/// before trusting its contents.
#[cfg(feature = "alloc")]
#[non_exhaustive]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RevocationList {
    /// URI of the CA that issued this CRL.
    pub issuer_id: String,
    /// Unix seconds when this CRL was issued.
    pub this_update: u64,
    /// Unix seconds when the next CRL will be issued (staleness deadline).
    pub next_update: u64,
    /// List of revoked certificate entries.
    pub entries: Vec<RevocationEntry>,
    /// ML-DSA-65 signature by the issuing CA over the TBS fields.
    #[serde(with = "serde_bytes")]
    pub issuer_signature: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl RevocationList {
    /// Returns `true` if the certificate with `serial` is revoked.
    #[must_use]
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.entries.iter().any(|e| e.serial == serial)
    }

    /// Returns `true` if this CRL is still fresh at `now_secs`.
    ///
    /// A stale CRL should trigger a warning but may still be used for
    /// offline operation (configurable via policy).
    #[must_use]
    pub fn is_fresh(&self, now_secs: u64) -> bool {
        now_secs <= self.next_update
    }

    /// Serializes the to-be-signed fields to CBOR for signature verification.
    pub fn tbs_cbor(&self) -> Result<Vec<u8>, PqRascvError> {
        let tbs = CrlTbs {
            issuer_id: &self.issuer_id,
            this_update: self.this_update,
            next_update: self.next_update,
            entries: &self.entries,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&tbs, &mut buf).map_err(|_| PqRascvError::SerializationFailed)?;
        Ok(buf)
    }
}

#[cfg(feature = "alloc")]
#[derive(serde::Serialize)]
struct CrlTbs<'a> {
    issuer_id: &'a str,
    this_update: u64,
    next_update: u64,
    entries: &'a [RevocationEntry],
}
