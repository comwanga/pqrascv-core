//! End-to-end Sigstore signing workflow.

use crate::error::SigstoreClientError;
use crate::fulcio::request_signing_cert;
use crate::rekor::{submit_hashedrekord, RekorEntry};

pub struct WorkflowConfig {
    pub fulcio_url: String,
    pub rekor_url: String,
}

#[derive(Debug)]
pub struct SignedArtifact {
    pub rekor_entry: RekorEntry,
    pub cert_chain_pem: Vec<String>,
    pub signature_b64: String,
}

/// Sign an artifact and submit to Rekor.
#[tracing::instrument(skip_all, err)]
pub fn sign_and_log(
    config: &WorkflowConfig,
    artifact_sha256: &[u8; 32],
    id_token: &str,
    csr_der_b64: &str,
    signature_b64: &str,
) -> Result<SignedArtifact, SigstoreClientError> {
    let cert_chain = request_signing_cert(&config.fulcio_url, id_token, csr_der_b64)?;
    let leaf_pem_b64 = cert_chain
        .first()
        .ok_or_else(|| SigstoreClientError::Fulcio("empty cert chain".into()))?;
    let entry = submit_hashedrekord(
        &config.rekor_url,
        artifact_sha256,
        signature_b64,
        leaf_pem_b64,
    )?;
    Ok(SignedArtifact {
        rekor_entry: entry,
        cert_chain_pem: cert_chain,
        signature_b64: signature_b64.to_string(),
    })
}

/// Build a Sigstore bundle JSON from a `SignedArtifact`.
///
/// The JSON format matches what `pqrascv_core::provenance_v2::ExternalProvenanceBundle`
/// expects for offline verification.
pub fn build_bundle_json(
    signed: &SignedArtifact,
    artifact_sha256: &[u8; 32],
) -> Result<String, SigstoreClientError> {
    let artifact_hash_hex = hex::encode(artifact_sha256);
    let set_b64 = &signed.rekor_entry.verification.signed_entry_timestamp;
    let bundle = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": signed.cert_chain_pem.iter().map(|pem| {
                    serde_json::json!({ "rawBytes": pem })
                }).collect::<Vec<_>>()
            },
            "tlogEntries": [{
                "logIndex": signed.rekor_entry.log_index.to_string(),
                "logId": { "keyId": "" },
                "kindVersion": { "kind": "hashedrekord", "version": "0.0.1" },
                "integratedTime": signed.rekor_entry.integrated_time.to_string(),
                "inclusionPromise": { "signedEntryTimestamp": set_b64 },
                "canonicalizedBody": signed.rekor_entry.body_b64
            }]
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": artifact_hash_hex
            },
            "signature": signed.signature_b64
        }
    });
    serde_json::to_string(&bundle).map_err(|e| SigstoreClientError::Parse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rekor::{RekorEntry, RekorVerification};
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    fn mock_fulcio_body() -> String {
        serde_json::json!({
            "signedCertificateEmbeddedSct": {
                "chain": { "certificates": ["bW9jay1sZWFm", "bW9jay1yb290"] }
            }
        })
        .to_string()
    }

    fn mock_rekor_body(log_index: i64) -> String {
        let set_b64 = B64.encode(b"mock-set");
        let uuid = "deadbeef";
        format!(
            r#"{{"{uuid}": {{"uuid": "{uuid}", "body": "e30=", "integratedTime": 1700000000, "logIndex": {log_index}, "verification": {{"signedEntryTimestamp": "{set_b64}"}}}}}}"#
        )
    }

    #[test]
    fn sign_and_log_returns_signed_artifact() {
        let mut fulcio_server = mockito::Server::new();
        let mut rekor_server = mockito::Server::new();
        let _fm = fulcio_server
            .mock("POST", "/api/v1/signingCert")
            .with_status(200)
            .with_body(mock_fulcio_body())
            .create();
        let _rm = rekor_server
            .mock("POST", "/api/v1/log/entries")
            .with_status(201)
            .with_body(mock_rekor_body(200))
            .create();

        let config = WorkflowConfig {
            fulcio_url: fulcio_server.url(),
            rekor_url: rekor_server.url(),
        };
        let result = sign_and_log(
            &config,
            &[0xABu8; 32],
            "id-token",
            "bW9jay1jc3I=",
            "bW9jay1zaWc=",
        );
        assert!(result.is_ok(), "sign_and_log must succeed: {result:?}");
        let signed = result.unwrap();
        assert_eq!(signed.rekor_entry.log_index, 200);
        assert_eq!(signed.cert_chain_pem.len(), 2);
    }

    #[test]
    fn build_bundle_json_contains_required_fields() {
        let entry = RekorEntry {
            uuid: "abc".into(),
            body_b64: "e30=".into(),
            integrated_time: 1_700_000_000,
            log_index: 42,
            verification: RekorVerification {
                signed_entry_timestamp: B64.encode(b"set"),
                inclusion_proof: None,
            },
        };
        let signed = SignedArtifact {
            rekor_entry: entry,
            cert_chain_pem: vec!["leaf-pem".into()],
            signature_b64: "c2ln".into(),
        };
        let json = build_bundle_json(&signed, &[0x42u8; 32]).unwrap();
        assert!(json.contains("verificationMaterial"));
        assert!(json.contains("messageSignature"));
        assert!(json.contains("tlogEntries"));
    }
}
