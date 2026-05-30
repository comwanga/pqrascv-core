//! Fulcio certificate issuance client.
//!
//! API: POST /api/v1/signingCert
//! Input: OIDC id_token (Authorization header) + CSR body
//! Output: PEM certificate chain

use serde::Deserialize;
use crate::error::SigstoreClientError;

#[derive(Debug, Clone, Deserialize)]
pub struct FulcioCertResponse {
    #[serde(rename = "signedCertificateEmbeddedSct")]
    pub cert_chain_pem: FulcioChain,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FulcioChain {
    pub chain: FulcioCerts,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FulcioCerts {
    pub certificates: Vec<String>,
}

fn agent() -> ureq::Agent {
    use std::time::Duration;
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(30))
        .build()
}

fn map_ureq_err(e: ureq::Error) -> SigstoreClientError {
    match e {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().unwrap_or_default();
            SigstoreClientError::HttpStatus { status, body }
        }
        ureq::Error::Transport(t) => SigstoreClientError::Transport(t.to_string()),
    }
}

/// Request a short-lived signing certificate from Fulcio.
///
/// Returns the PEM certificate chain (leaf cert is `[0]`).
pub fn request_signing_cert(
    base_url: &str,
    id_token: &str,
    csr_der_b64: &str,
) -> Result<Vec<String>, SigstoreClientError> {
    if id_token.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(SigstoreClientError::Fulcio("invalid id_token: contains CR/LF/NUL".into()));
    }
    let body = serde_json::json!({ "certificateSigningRequest": csr_der_b64 });
    let url = format!("{base_url}/api/v1/signingCert");
    let resp: serde_json::Value = agent().post(&url)
        .set("Authorization", &format!("Bearer {id_token}"))
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(map_ureq_err)?
        .into_json()
        .map_err(|e| SigstoreClientError::Parse(e.to_string()))?;

    let cert_resp: FulcioCertResponse = serde_json::from_value(resp)
        .map_err(|e| SigstoreClientError::Parse(e.to_string()))?;

    Ok(cert_resp.cert_chain_pem.chain.certificates)
}

/// Extract the DER bytes of the leaf certificate from the PEM chain.
///
/// Parses the first item in `cert_chain_pem` as a PEM-encoded X.509 certificate.
/// Returns `Err` if the block is not a `CERTIFICATE` PEM type.
pub fn leaf_cert_der(cert_chain_pem: &[String]) -> Result<Vec<u8>, SigstoreClientError> {
    let leaf_pem = cert_chain_pem.first()
        .ok_or_else(|| SigstoreClientError::Parse("empty cert chain".into()))?;
    let mut reader = std::io::Cursor::new(leaf_pem.as_bytes());
    let item = rustls_pemfile::read_one(&mut reader)
        .map_err(|e| SigstoreClientError::Parse(e.to_string()))?
        .ok_or_else(|| SigstoreClientError::Parse("no PEM block found".into()))?;
    match item {
        rustls_pemfile::Item::X509Certificate(der) => Ok(der.to_vec()),
        _ => Err(SigstoreClientError::Parse("PEM block is not a CERTIFICATE".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn mock_fulcio_response() -> String {
        serde_json::json!({
            "signedCertificateEmbeddedSct": {
                "chain": {
                    "certificates": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t", "cm9vdC1jZXJ0"]
                }
            }
        })
        .to_string()
    }

    #[test]
    fn request_signing_cert_returns_chain() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/v1/signingCert")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_fulcio_response())
            .create();
        let chain = request_signing_cert(&server.url(), "mock-id-token", "bW9jay1jc3I=").unwrap();
        assert_eq!(chain.len(), 2, "must return leaf + root");
        mock.assert();
    }

    #[test]
    fn request_signing_cert_sends_bearer_token() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/v1/signingCert")
            .match_header("Authorization", "Bearer test-token")
            .with_status(200)
            .with_body(mock_fulcio_response())
            .create();
        let _ = request_signing_cert(&server.url(), "test-token", "bW9jay1jc3I=");
        mock.assert();
    }

    #[test]
    fn request_signing_cert_rejects_token_with_crlf() {
        let result = request_signing_cert("http://127.0.0.1:1", "token\r\nX-Injected: evil", "bW9jay1jc3I=");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("CR/LF/NUL") || err.contains("invalid"), "got: {err}");
    }

    #[test]
    fn leaf_cert_der_accepts_certificate_pem_block() {
        use base64::engine::general_purpose::STANDARD as B64;
        let fake_der = b"fake-der-bytes";
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            B64.encode(fake_der)
        );
        let der = leaf_cert_der(&[pem]).unwrap();
        assert_eq!(der, b"fake-der-bytes");
    }

    #[test]
    fn leaf_cert_der_rejects_non_certificate_pem() {
        use base64::engine::general_purpose::STANDARD as B64;
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            B64.encode(b"key-bytes")
        );
        let result = leaf_cert_der(&[pem]);
        assert!(result.is_err(), "non-CERTIFICATE PEM must be rejected");
    }

    #[test]
    fn leaf_cert_der_errors_on_empty_chain() {
        let result = leaf_cert_der(&[] as &[String]);
        assert!(result.is_err(), "empty chain must fail");
    }
}
