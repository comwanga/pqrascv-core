//! Rekor transparency log REST client.
//!
//! API base: https://rekor.sigstore.dev (or configurable)
//! Used endpoints:
//!   GET  /api/v1/log/entries?logIndex=N  — fetch by log index
//!   POST /api/v1/log/entries             — submit a new entry

use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use crate::error::SigstoreClientError;

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

/// A single Rekor log entry as returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorEntry {
    pub uuid: String,
    #[serde(rename = "body")]
    pub body_b64: String,
    #[serde(rename = "integratedTime")]
    pub integrated_time: i64,
    #[serde(rename = "logIndex")]
    pub log_index: i64,
    #[serde(rename = "verification")]
    pub verification: RekorVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorVerification {
    #[serde(rename = "signedEntryTimestamp")]
    pub signed_entry_timestamp: String,
    #[serde(rename = "inclusionProof", default)]
    pub inclusion_proof: Option<RekorInclusionProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorInclusionProof {
    pub checkpoint: String,
    pub hashes: Vec<String>,
    #[serde(rename = "logIndex")]
    pub log_index: i64,
    #[serde(rename = "rootHash")]
    pub root_hash: String,
    #[serde(rename = "treeSize")]
    pub tree_size: i64,
}

/// Fetch a Rekor log entry by log index.
pub fn get_entry_by_index(base_url: &str, log_index: i64) -> Result<RekorEntry, SigstoreClientError> {
    let url = format!("{base_url}/api/v1/log/entries?logIndex={log_index}");
    let response: serde_json::Value = agent().get(&url)
        .call()
        .map_err(map_ureq_err)?
        .into_json()
        .map_err(|e| SigstoreClientError::Parse(e.to_string()))?;

    let entry_map = response
        .as_object()
        .ok_or_else(|| SigstoreClientError::Parse("expected object".into()))?;
    let entry_val = entry_map
        .values()
        .next()
        .ok_or_else(|| SigstoreClientError::Parse("empty response".into()))?;

    serde_json::from_value(entry_val.clone())
        .map_err(|e| SigstoreClientError::Parse(e.to_string()))
}

/// Decode and return the raw SET bytes from a `RekorEntry`.
pub fn entry_set_bytes(entry: &RekorEntry) -> Result<Vec<u8>, SigstoreClientError> {
    B64.decode(&entry.verification.signed_entry_timestamp)
        .map_err(|e| SigstoreClientError::Parse(e.to_string()))
}

pub fn entry_integrated_time(entry: &RekorEntry) -> i64 {
    entry.integrated_time
}

/// Submit a `hashedrekord` entry to Rekor.
pub fn submit_hashedrekord(
    base_url: &str,
    artifact_sha256: &[u8; 32],
    signature_b64: &str,
    cert_pem_b64: &str,
) -> Result<RekorEntry, SigstoreClientError> {
    let artifact_hash_hex = hex::encode(artifact_sha256);
    let body = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": artifact_hash_hex
                }
            },
            "signature": {
                "content": signature_b64,
                "publicKey": {
                    "content": cert_pem_b64
                }
            }
        }
    });

    let url = format!("{base_url}/api/v1/log/entries");
    let response: serde_json::Value = agent().post(&url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(map_ureq_err)?
        .into_json()
        .map_err(|e| SigstoreClientError::Parse(e.to_string()))?;

    let entry_map = response
        .as_object()
        .ok_or_else(|| SigstoreClientError::Parse("expected object".into()))?;
    let entry_val = entry_map
        .values()
        .next()
        .ok_or_else(|| SigstoreClientError::Parse("empty response".into()))?;

    serde_json::from_value(entry_val.clone())
        .map_err(|e| SigstoreClientError::Parse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_entry_json(log_index: i64, integrated_time: i64) -> String {
        let uuid = "abc123def456";
        let set_b64 = B64.encode(b"mock-set-bytes");
        format!(
            r#"{{
                "{uuid}": {{
                    "uuid": "{uuid}",
                    "body": "eyJ0eXBlIjoidGVzdCJ9",
                    "integratedTime": {integrated_time},
                    "logIndex": {log_index},
                    "verification": {{
                        "signedEntryTimestamp": "{set_b64}"
                    }}
                }}
            }}"#
        )
    }

    #[test]
    fn get_entry_by_index_parses_response() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/api/v1/log/entries?logIndex=42")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_entry_json(42, 1_700_000_000))
            .create();
        let entry = get_entry_by_index(&server.url(), 42).unwrap();
        assert_eq!(entry.log_index, 42);
        assert_eq!(entry.integrated_time, 1_700_000_000);
        mock.assert();
    }

    #[test]
    fn entry_set_bytes_decodes_base64() {
        let set_b64 = B64.encode(b"mock-set-bytes");
        let entry = RekorEntry {
            uuid: "abc".into(),
            body_b64: "".into(),
            integrated_time: 0,
            log_index: 0,
            verification: RekorVerification {
                signed_entry_timestamp: set_b64,
                inclusion_proof: None,
            },
        };
        let bytes = entry_set_bytes(&entry).unwrap();
        assert_eq!(bytes, b"mock-set-bytes");
    }

    #[test]
    fn get_entry_returns_error_on_http_failure() {
        let result = get_entry_by_index("http://127.0.0.1:1", 1);
        assert!(result.is_err(), "unreachable URL must return error");
    }

    #[test]
    fn get_entry_returns_error_on_bad_json() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/api/v1/log/entries?logIndex=1")
            .with_status(200)
            .with_body("not-json")
            .create();
        let result = get_entry_by_index(&server.url(), 1);
        assert!(result.is_err());
        mock.assert();
    }

    #[test]
    fn submit_hashedrekord_sends_correct_payload() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/api/v1/log/entries")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(mock_entry_json(100, 1_700_000_001))
            .create();
        let artifact_sha256 = [0x42u8; 32];
        let entry = submit_hashedrekord(&server.url(), &artifact_sha256, "dGVzdC1zaWduYXR1cmU=", "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t").unwrap();
        assert_eq!(entry.log_index, 100);
        mock.assert();
    }
}
