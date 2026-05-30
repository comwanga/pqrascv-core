//! Fuzz target: PKI certificate chain validation.
//!
//! Exercises `pqrascv_core::pki::validate_chain` with arbitrary byte sequences
//! as the device certificate's `issuer_signature` and `subject_key` fields.
//! The ML-DSA-65 signature verification path and all structural checks inside
//! `validate_chain` must never panic for any input.
//!
//! No valid chain can be constructed from random bytes because the signature
//! check will always fail; the target exercises the error-handling paths.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqrascv_core::crypto::ML_DSA_65_VERIFYING_KEY_SIZE;
use pqrascv_core::pki::{
    build_device_certificate, CaPublicKey, HardwareIdentity, TrustAnchor, validate_chain,
    CERT_VERSION,
};

fuzz_target!(|data: &[u8]| {
    // Need at least 1 byte to derive a subject_key_id seed from.
    if data.is_empty() {
        return;
    }

    // Build a trust anchor with a fixed zeroed root key and a wide time window.
    let root_ca = CaPublicKey {
        key_bytes: [0u8; ML_DSA_65_VERIFYING_KEY_SIZE],
        ca_id: "https://fuzz.test".to_string(),
        not_before: 0,
        not_after: u64::MAX,
    };
    let anchor = match TrustAnchor::new(root_ca) {
        Ok(a) => a,
        Err(_) => return,
    };

    // Use the fuzz bytes as the signature so the ML-DSA-65 verify path
    // receives adversarial input.
    let sig_bytes = data.to_vec();
    // subject_key: repeat the first fuzz byte to fill the required 1952 bytes.
    let subject_key = vec![data[0]; ML_DSA_65_VERIFYING_KEY_SIZE];
    let subject_key_id = [data[0]; 32];

    // `build_device_certificate` is only available with `software-rot-unsafe`.
    // It bypasses `#[non_exhaustive]` so test/fuzz code can construct certs.
    let device_cert = build_device_certificate(
        CERT_VERSION,
        "FUZZ-001".to_string(),
        "https://fuzz.test".to_string(),  // matches anchor.ca_id
        0,                                // not_before
        u64::MAX,                         // not_after
        subject_key,
        subject_key_id,
        HardwareIdentity::TpmEkCertHash([0u8; 32]),
        None,
        sig_bytes,                        // arbitrary signature
        "https://device.fuzz".to_string(),
        Some(0),
    );

    // validate_chain must not panic — it will return Err (sig check fails
    // because the signature is not a valid ML-DSA-65 signature).
    let _ = validate_chain(device_cert, vec![], &anchor, 1_000);
});
