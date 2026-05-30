//! Fulcio certificate issuance client.
//!
//! API: POST /api/v1/signingCert
//! Input: OIDC id_token (Authorization header) + CSR body
//! Output: PEM certificate chain

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
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

/// Request a short-lived signing certificate from Fulcio.
///
/// Returns the PEM certificate chain (leaf cert is `[0]`).
pub fn request_signing_cert(
    base_url: &str,
    id_token: &str,
    csr_der_b64: &str,
) -> Result<Vec<String>, SigstoreClientError> {
    let body = serde_json::json!({ "certificateSigningRequest": csr_der_b64 });
    let url = format!("{base_url}/api/v1/signingCert");
    let resp: serde_json::Value = ureq::post(&url)
        .set("Authorization", &format!("Bearer {id_token}"))
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| SigstoreClientError::Fulcio(e.to_string()))?
        .into_json()
        .map_err(|e| SigstoreClientError::Parse(e.to_string()))?;

    let cert_resp: FulcioCertResponse = serde_json::from_value(resp)
        .map_err(|e| SigstoreClientError::Parse(e.to_string()))?;

    Ok(cert_resp.cert_chain_pem.chain.certificates)
}

/// Extract the DER bytes of the leaf certificate from the PEM chain.
pub fn leaf_cert_der(cert_chain_pem: &[String]) -> Result<Vec<u8>, SigstoreClientError> {
    let leaf_pem = cert_chain_pem.first()
        .ok_or_else(|| SigstoreClientError::Parse("empty cert chain".into()))?;
    let b64_body: String = leaf_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    B64.decode(b64_body)
        .map_err(|e| SigstoreClientError::Parse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn leaf_cert_der_strips_pem_headers() {
        let pem = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";
        let chain = vec![pem.to_string()];
        let der = leaf_cert_der(&chain).unwrap();
        assert_eq!(der, b"hello");
    }

    #[test]
    fn leaf_cert_der_errors_on_empty_chain() {
        let result = leaf_cert_der(&[] as &[String]);
        assert!(result.is_err(), "empty chain must fail");
    }
}
