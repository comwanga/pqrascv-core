/// Fulcio short-lived certificate parsing and temporal validation.
///
/// Implements conditions 2 and 3 of the Provenance Enforcement Invariant:
/// - Condition 2: the signing certificate chains to a trusted Fulcio root
/// - Condition 3: the Fulcio certificate is temporally valid at verification time
///
/// Uses [`x509_cert`] for DER parsing and extracts the OIDC subject and issuer
/// from Fulcio-specific X.509 extensions.
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::string::String;
// `ToString` is in the std prelude but not the bare no_std+alloc prelude.
// Imported by name (not `as _`) because it's used as a path: `ToString::to_string`.
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::string::ToString;

use crate::error::PqRascvError;

/// Error variants for Fulcio certificate operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FulcioError {
    /// The DER bytes could not be parsed as an X.509 certificate.
    ParseError,
    /// The certificate's `not_after` field is before `now_secs` (expired).
    CertExpired,
    /// The certificate's `not_before` field is after `now_secs` (not yet valid).
    CertNotYetValid,
    /// The Subject Alternative Name URI (OIDC subject) is missing or malformed.
    MissingOidcSubject,
    /// The Fulcio OIDC issuer extension (OID 1.3.6.1.4.1.57264.1.1) is absent.
    MissingOidcIssuer,
    /// The certificate issuer does not match the trusted Fulcio root subject.
    ChainValidationFailed,
}

impl From<FulcioError> for PqRascvError {
    fn from(_: FulcioError) -> Self {
        PqRascvError::ProvenanceBundleInvalid
    }
}

/// A parsed and temporally-validated Fulcio short-lived certificate.
///
/// Constructed by [`FulcioCert::from_der`] after the certificate passes
/// all structural and temporal checks. The extracted OIDC claims are
/// consumed by condition 4 ([`IdentityConstraint`]) and the `not_after`
/// timestamp by condition 6 (Rekor time bounds).
///
/// [`IdentityConstraint`]: super::identity::IdentityConstraint
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct FulcioCert {
    pub(crate) oidc_subject: String,
    pub(crate) oidc_issuer: String,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
}

#[cfg(feature = "alloc")]
impl FulcioCert {
    /// Parse and temporally validate a DER-encoded Fulcio X.509 certificate.
    ///
    /// Checks that `now_secs` falls within `[not_before, not_after]`, then
    /// extracts the OIDC subject from the Subject Alternative Name extension
    /// and the OIDC issuer from the Fulcio-specific OID extension.
    pub fn from_der(der: &[u8], now_secs: u64) -> Result<Self, FulcioError> {
        use der::Decode;
        use x509_cert::Certificate;

        let cert = Certificate::from_der(der).map_err(|_| FulcioError::ParseError)?;

        let not_before = time_to_unix(&cert.tbs_certificate.validity.not_before);
        let not_after = time_to_unix(&cert.tbs_certificate.validity.not_after);

        if now_secs < not_before {
            return Err(FulcioError::CertNotYetValid);
        }
        if now_secs > not_after {
            return Err(FulcioError::CertExpired);
        }

        let (oidc_subject, oidc_issuer) = extract_oidc_claims(&cert)?;
        Ok(Self {
            oidc_subject,
            oidc_issuer,
            not_before,
            not_after,
        })
    }

    /// Parse a Fulcio cert and extract OIDC claims without temporal validation.
    ///
    /// Use only after condition 3 has already confirmed temporal validity.
    pub(crate) fn parse_oidc_claims(der: &[u8]) -> Result<(String, String), FulcioError> {
        use der::Decode;
        use x509_cert::Certificate;

        let cert = Certificate::from_der(der).map_err(|_| FulcioError::ParseError)?;
        extract_oidc_claims(&cert)
    }

    /// The OIDC subject URI from the Subject Alternative Name extension.
    #[must_use]
    pub fn oidc_subject(&self) -> &str {
        &self.oidc_subject
    }

    /// The OIDC issuer URI from the Fulcio OID extension.
    #[must_use]
    pub fn oidc_issuer(&self) -> &str {
        &self.oidc_issuer
    }

    /// The `not_after` Unix timestamp from the certificate validity period.
    ///
    /// Condition 6 uses this to verify that the Rekor `integratedTime` does
    /// not exceed the cert's validity window.
    #[must_use]
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
}

/// Verify that a leaf cert DER chains to the trusted root DER.
///
/// Enforces two properties:
/// 1. **Structural**: the leaf's `issuer` DN equals the root's `subject` DN.
/// 2. **Cryptographic**: the root CA's P-256 key produced the DER-encoded ECDSA
///    signature over the leaf's `TBSCertificate` bytes.
///
/// Both checks must pass. A forged cert with the right issuer DN but no valid
/// CA signature is rejected by check 2.
#[cfg(feature = "alloc")]
pub(crate) fn verify_chain(leaf_der: &[u8], root_der: &[u8]) -> Result<(), FulcioError> {
    use der::{Decode, Encode};
    use p256::ecdsa::{signature::Verifier, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;
    use x509_cert::Certificate;

    if leaf_der.is_empty() || root_der.is_empty() {
        return Err(FulcioError::ParseError);
    }

    let leaf = Certificate::from_der(leaf_der).map_err(|_| FulcioError::ParseError)?;
    let root = Certificate::from_der(root_der).map_err(|_| FulcioError::ParseError)?;

    // 1. Issuer-subject name binding.
    if leaf.tbs_certificate.issuer != root.tbs_certificate.subject {
        return Err(FulcioError::ChainValidationFailed);
    }

    // 2. ECDSA P-256 signature: root CA key over leaf TBSCertificate DER bytes.
    let root_spki_der = root
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| FulcioError::ChainValidationFailed)?;
    let vk = VerifyingKey::from_public_key_der(&root_spki_der)
        .map_err(|_| FulcioError::ChainValidationFailed)?;

    let tbs_der = leaf
        .tbs_certificate
        .to_der()
        .map_err(|_| FulcioError::ChainValidationFailed)?;

    // X.509 signatures are DER-encoded ECDSA (not raw r||s).
    let sig_bytes = leaf.signature.raw_bytes();
    let sig = ecdsa::der::Signature::<p256::NistP256>::try_from(sig_bytes)
        .map_err(|_| FulcioError::ChainValidationFailed)?;

    vk.verify(&tbs_der, &sig)
        .map_err(|_| FulcioError::ChainValidationFailed)
}


#[cfg(feature = "alloc")]
fn extract_oidc_claims(cert: &x509_cert::Certificate) -> Result<(String, String), FulcioError> {
    let exts = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(FulcioError::MissingOidcSubject)?;

    let mut oidc_subject: Option<String> = None;
    let mut oidc_issuer: Option<String> = None;

    for ext in exts {
        let oid = alloc::format!("{}", ext.extn_id);
        match oid.as_str() {
            // Subject Alternative Name (2.5.29.17) — first URI GeneralName is the OIDC subject.
            "2.5.29.17" => {
                oidc_subject = extract_san_uri(ext.extn_value.as_bytes());
            }
            // Fulcio OIDC Issuer extension (1.3.6.1.4.1.57264.1.1).
            "1.3.6.1.4.1.57264.1.1" => {
                oidc_issuer = extract_utf8_string(ext.extn_value.as_bytes());
            }
            _ => {}
        }
    }

    let subject = oidc_subject.ok_or(FulcioError::MissingOidcSubject)?;
    let issuer = oidc_issuer.ok_or(FulcioError::MissingOidcIssuer)?;
    Ok((subject, issuer))
}

#[cfg(feature = "alloc")]
fn time_to_unix(t: &x509_cert::time::Time) -> u64 {
    use der::DateTime;
    let dt = match t {
        x509_cert::time::Time::UtcTime(ut) => DateTime::from(*ut),
        x509_cert::time::Time::GeneralTime(gt) => DateTime::from(*gt),
    };
    dt.unix_duration().as_secs()
}

/// Scan the raw DER bytes of a SAN extension value for the first URI [6] entry.
#[cfg(feature = "alloc")]
fn extract_san_uri(san_der: &[u8]) -> Option<String> {
    // SAN extension value: SEQUENCE OF GeneralName
    // GeneralName URI is context-specific primitive [6] → wire tag 0x86
    let mut pos = 0;

    if san_der.first() != Some(&0x30) {
        return None;
    }
    pos += 1;
    let (_, len_bytes) = read_der_length(san_der.get(pos..)?)?;
    pos += len_bytes;

    while pos < san_der.len() {
        let tag = *san_der.get(pos)?;
        pos += 1;
        let (item_len, len_bytes) = read_der_length(san_der.get(pos..)?)?;
        pos += len_bytes;

        if tag == 0x86 {
            let bytes = san_der.get(pos..pos + item_len)?;
            return core::str::from_utf8(bytes).ok().map(ToString::to_string);
        }
        pos = pos.checked_add(item_len)?;
    }
    None
}

/// Decode an extension value that is either a DER `UTF8String` or raw UTF-8 bytes.
#[cfg(feature = "alloc")]
fn extract_utf8_string(der: &[u8]) -> Option<String> {
    if der.is_empty() {
        return None;
    }
    // DER UTF8String has tag 0x0C
    if der[0] == 0x0C && der.len() >= 2 {
        let (len, len_bytes) = read_der_length(&der[1..])?;
        let content = der.get(1 + len_bytes..1 + len_bytes + len)?;
        return core::str::from_utf8(content).ok().map(ToString::to_string);
    }
    // Fallback: treat raw bytes as UTF-8 (Fulcio < 1.4 stored the string directly)
    core::str::from_utf8(der).ok().map(ToString::to_string)
}

/// Read a DER length field.  Returns `(length, bytes_consumed)`.
#[cfg(feature = "alloc")]
fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
        return None;
    }
    let mut len = 0usize;
    for &b in data.get(1..1 + num_bytes)? {
        len = len.checked_shl(8)?.checked_add(b as usize)?;
    }
    Some((len, 1 + num_bytes))
}


#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn empty_der_returns_parse_error() {
        let err = FulcioCert::from_der(&[], 1_700_000_000).unwrap_err();
        assert_eq!(err, FulcioError::ParseError);
    }

    #[test]
    fn garbage_der_returns_parse_error() {
        let err = FulcioCert::from_der(&[0xDE, 0xAD, 0xBE, 0xEF], 1_700_000_000).unwrap_err();
        assert_eq!(err, FulcioError::ParseError);
    }

    #[test]
    fn parse_oidc_claims_empty_der_returns_error() {
        let err = FulcioCert::parse_oidc_claims(&[]).unwrap_err();
        assert_eq!(err, FulcioError::ParseError);
    }

    #[test]
    fn verify_chain_empty_leaf_returns_error() {
        let err = verify_chain(&[], &[0x30, 0x00]).unwrap_err();
        assert_eq!(err, FulcioError::ParseError);
    }

    #[test]
    fn verify_chain_empty_root_returns_error() {
        let err = verify_chain(&[0x30, 0x00], &[]).unwrap_err();
        assert_eq!(err, FulcioError::ParseError);
    }

    // Tests requiring real DER-encoded X.509 certs with specific validity windows
    // and Fulcio-specific extensions are integration tests that need rcgen or
    // pre-generated test fixtures. They are tracked in the implementation plan.
    // The production path is validated end-to-end via the Sigstore bundle tests.
}
