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
    /// Verifies the CRL issuer signature and freshness, returning a `VerifiedRevocationList`.
    ///
    /// # Errors
    ///
    /// - `PolicyViolation` — CRL is stale (`next_update < now_secs`).
    /// - `VerificationFailed` — CA signature over TBS is invalid.
    pub fn verify<'a>(
        &'a self,
        ca_key: &[u8],
        now_secs: u64,
    ) -> Result<VerifiedRevocationList<'a>, PqRascvError> {
        use crate::crypto::{CryptoBackend, MlDsaBackend, SIGNING_CONTEXT_CRL};

        if !self.is_fresh(now_secs) {
            return Err(PqRascvError::PolicyViolation);
        }
        let tbs = self.tbs_cbor()?;
        MlDsaBackend.verify(&tbs, ca_key, &self.issuer_signature, SIGNING_CONTEXT_CRL)?;
        Ok(VerifiedRevocationList { inner: self })
    }

    /// Checks whether `serial` appears in the CRL entries.
    ///
    /// # ⚠ Signature Not Verified
    ///
    /// This method does NOT check the CRL signature. Use [`RevocationList::verify`]
    /// to get a [`VerifiedRevocationList`] whose `is_revoked()` is cryptographically backed.
    #[must_use]
    #[deprecated = "use RevocationList::verify() first, then VerifiedRevocationList::is_revoked()"]
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.entries.iter().any(|e| e.serial == serial)
    }

    /// Returns `true` if this CRL is still fresh at `now_secs`.
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

/// Constructs a [`RevocationList`] with all fields explicitly supplied.
///
/// Available under `software-rot-unsafe` to allow test code in external crates
/// to bypass the `#[non_exhaustive]` restriction.
#[cfg(all(feature = "alloc", feature = "software-rot-unsafe"))]
pub fn build_revocation_list(
    issuer_id: String,
    this_update: u64,
    next_update: u64,
    entries: Vec<RevocationEntry>,
    issuer_signature: Vec<u8>,
) -> RevocationList {
    RevocationList {
        issuer_id,
        this_update,
        next_update,
        entries,
        issuer_signature,
    }
}

/// A revocation list whose issuer signature and freshness have been verified.
///
/// Obtain via [`RevocationList::verify`].
/// `is_revoked()` is only available on this type.
#[cfg(feature = "alloc")]
pub struct VerifiedRevocationList<'a> {
    inner: &'a RevocationList,
}

#[cfg(feature = "alloc")]
impl<'a> VerifiedRevocationList<'a> {
    /// Returns `true` if the certificate with `serial` is listed as revoked.
    #[must_use]
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.inner.entries.iter().any(|e| e.serial == serial)
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

#[cfg(all(test, feature = "alloc", feature = "std"))]
mod tests {
    use super::*;
    use crate::crypto::{generate_ml_dsa_keypair, MlDsaBackend, CryptoBackend, SIGNING_CONTEXT_CRL};

    fn make_signed_crl(
        entries: Vec<RevocationEntry>,
        ca_seed: &[u8],
        this_update: u64,
        next_update: u64,
    ) -> RevocationList {
        let mut crl = RevocationList {
            issuer_id: "https://ca.test".to_string(),
            this_update,
            next_update,
            entries,
            issuer_signature: vec![],
        };
        let tbs = crl.tbs_cbor().expect("tbs_cbor failed");
        let sig = MlDsaBackend
            .sign(&tbs, ca_seed, SIGNING_CONTEXT_CRL)
            .expect("sign failed");
        crl.issuer_signature = sig.as_ref().to_vec();
        crl
    }

    #[test]
    fn verified_crl_detects_revoked_serial() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let crl = make_signed_crl(
            vec![RevocationEntry {
                serial: "DEV-001".to_string(),
                revoked_at: 1_000,
                reason: RevocationReason::KeyCompromise,
            }],
            ca_seed.as_bytes(),
            1_000,
            9_999_999,
        );
        let verified = crl.verify(&ca_vk, 2_000).expect("verify failed");
        assert!(verified.is_revoked("DEV-001"));
        assert!(!verified.is_revoked("DEV-002"));
    }

    #[test]
    fn stale_crl_is_refused() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let crl = make_signed_crl(vec![], ca_seed.as_bytes(), 1_000, 2_000);
        // now_secs = 3_000 > next_update = 2_000
        assert!(matches!(crl.verify(&ca_vk, 3_000), Err(PqRascvError::PolicyViolation)));
    }

    #[test]
    fn tampered_crl_entries_fail_signature_check() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let mut crl = make_signed_crl(vec![], ca_seed.as_bytes(), 1_000, 9_999_999);
        // Tamper: inject a revocation entry after signing
        crl.entries.push(RevocationEntry {
            serial: "INJECTED-001".to_string(),
            revoked_at: 1_000,
            reason: RevocationReason::KeyCompromise,
        });
        assert!(crl.verify(&ca_vk, 2_000).is_err(), "tampered CRL must fail");
    }

    #[test]
    fn wrong_ca_key_fails_verification() {
        let (ca_seed, _ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (_other_seed, other_vk) = generate_ml_dsa_keypair().unwrap();
        let crl = make_signed_crl(vec![], ca_seed.as_bytes(), 1_000, 9_999_999);
        assert!(crl.verify(&other_vk, 2_000).is_err());
    }
}
