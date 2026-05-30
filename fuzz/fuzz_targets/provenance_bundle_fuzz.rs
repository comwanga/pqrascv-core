//! Fuzz target: `ExternalProvenanceBundle` parsing and verification paths.
//!
//! Constructs bundles whose `rekor_entry_json` and `signing_cert_der` fields
//! are filled with arbitrary bytes, then calls `verify_all` so that every
//! parsing sub-step (CBOR predicate serialisation, DER cert parse, JSON Rekor
//! parse, ECDSA signature parse) receives adversarial input.
//!
//! None of these paths may panic for any byte sequence — they must return `Err`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqrascv_core::provenance_v2::{
    ExternalProvenanceBundle, ProvenancePredicate, ProvenanceSubject, SigstoreBundle,
    SigstoreConfig,
};

fuzz_target!(|data: &[u8]| {
    // Need at least 1 byte to derive field seeds from.
    if data.is_empty() {
        return;
    }

    // Split `data`: first half → rekor_entry_json (as lossy UTF-8),
    //               second half → signing_cert_der raw bytes.
    let mid = data.len() / 2;
    let (json_bytes, cert_bytes) = data.split_at(mid);

    // Convert the JSON half to a String (replace invalid UTF-8 with U+FFFD).
    let rekor_entry_json = String::from_utf8_lossy(json_bytes).into_owned();

    // Build a minimal ProvenancePredicate.
    let firmware_hash = [data[0]; 32];
    let predicate = ProvenancePredicate::new(
        "https://slsa.dev/provenance/v1".to_string(),
        "https://github.com/actions/runner".to_string(),
        "fuzz".to_string(),
        0,
        0,
        [0u8; 32],
        2,
        vec![ProvenanceSubject {
            name: "firmware.bin".to_string(),
            digest_sha3_256: firmware_hash,
        }],
    );

    // Build a bundle with an all-zeros predicate_hash to start with.
    // verify_predicate_hash will fail (hash mismatch), exercising condition 1.
    // We then also try a bundle where the hash is "correct" to push deeper.
    let sigstore_bundle_bad_hash = SigstoreBundle::new(
        data.to_vec(),
        cert_bytes.to_vec(),
        rekor_entry_json.clone(),
        [0u8; 32], // wrong predicate hash — condition 1 will reject
    );
    let bundle_bad = ExternalProvenanceBundle::new(predicate.clone(), sigstore_bundle_bad_hash);

    // Exercises condition 1 failure path — must not panic.
    let _ = bundle_bad.verify_predicate_hash();
    let config = stub_config(data, cert_bytes);
    let _ = bundle_bad.verify_all(&config, &firmware_hash, 1_700_000_000);

    // Build a bundle with a correct predicate_hash so condition 1 passes and
    // we reach the Fulcio chain / DER cert / Rekor JSON parsing paths.
    // We compute the hash by calling verify_predicate_hash on a "canonical" bundle
    // and extracting it — but since we can't get the hash directly from outside,
    // use the ExternalProvenanceBundle::new + verify_predicate_hash pattern:
    // repeatedly try with zeroed hash, then flip to the first 32 bytes of data.
    let candidate_hash: [u8; 32] = if data.len() >= 32 {
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[..32]);
        h
    } else {
        [data[0]; 32]
    };
    let sigstore_bundle_candidate = SigstoreBundle::new(
        data.to_vec(),
        cert_bytes.to_vec(),
        rekor_entry_json,
        candidate_hash,
    );
    let bundle_candidate =
        ExternalProvenanceBundle::new(predicate.clone(), sigstore_bundle_candidate);
    let _ = bundle_candidate.verify_predicate_hash();
    let _ = bundle_candidate.verify_all(&config, &firmware_hash, 1_700_000_000);

    // Also exercise the firmware_hash accessor — must not panic.
    let _ = bundle_candidate.firmware_hash();
    let _ = bundle_candidate.slsa_level();
    let _ = bundle_candidate.builder_id();
});

fn stub_config(data: &[u8], cert_bytes: &[u8]) -> SigstoreConfig {
    SigstoreConfig {
        rekor_public_key_der: data.to_vec(),
        fulcio_root_der: cert_bytes.to_vec(),
        required_issuer: "https://token.actions.githubusercontent.com".to_string(),
        allowed_builders: vec![
            "https://github.com/acme/firmware/.github/workflows/release.yml".to_string(),
        ],
        max_clock_skew_secs: 300,
    }
}
