//! Integration tests for pqrascv-core.
// These tests all need alloc for quote assembly and std for OS-based key generation.
#![cfg(feature = "std")]

use pqrascv_core::{
    config::PolicyConfig,
    crypto::{generate_ml_dsa_keypair, CryptoBackend, MlDsaBackend, ML_DSA_65_SIGNATURE_SIZE},
    measurement::SoftwareRoT,
    provenance::SlsaPredicateBuilder,
    quote::{generate_quote, AttestationQuote},
};

fn make_provenance() -> pqrascv_core::provenance::InTotoAttestation {
    SlsaPredicateBuilder::new("https://ci.example.com")
        .with_build_config_ref("abc123")
        .with_timestamps(1_700_000_000, 1_700_001_000)
        .with_slsa_level(2)
        .add_subject("firmware.bin", &[0xabu8; 32])
        .build()
        .expect("provenance build failed")
}

#[test]
fn full_pipeline_sign_and_verify() {
    let (sk, vk) = generate_ml_dsa_keypair().expect("keygen failed");
    let rot = SoftwareRoT::new(b"integration-test-firmware", Some(b"my-ai-model"), 7);
    let nonce = [0x11u8; 32];

    let quote = generate_quote(
        &rot,
        &MlDsaBackend,
        sk.as_bytes(),
        &vk,
        &nonce,
        make_provenance(),
        1_700_000_500,
    )
    .expect("generate_quote failed");

    let cbor = quote.to_cbor().expect("serialisation failed");
    let decoded = AttestationQuote::from_cbor(&cbor).expect("deserialisation failed");

    let body_cbor = decoded.body.to_cbor().expect("body serialisation failed");
    MlDsaBackend
        .verify(&body_cbor, &vk, &decoded.signature)
        .expect("signature verification failed");

    assert_eq!(decoded.body.nonce, nonce);
    assert_eq!(decoded.body.version, 1);
    assert_eq!(decoded.body.timestamp, 1_700_000_500);
    assert_ne!(decoded.body.measurements.firmware_hash, [0u8; 32]);
    assert_ne!(decoded.body.measurements.ai_model_hash, [0u8; 32]);
    assert_eq!(decoded.body.measurements.event_counter, 7);
    assert_eq!(decoded.signature.len(), ML_DSA_65_SIGNATURE_SIZE);
}

#[test]
fn policy_accepts_valid_quote() {
    let (sk, vk) = generate_ml_dsa_keypair().unwrap();
    let rot = SoftwareRoT::new(b"fw", None, 1);
    let nonce = [0x22u8; 32];

    let quote = generate_quote(
        &rot,
        &MlDsaBackend,
        sk.as_bytes(),
        &vk,
        &nonce,
        make_provenance(),
        1_700_000_000,
    )
    .unwrap();

    let policy = PolicyConfig {
        min_slsa_level: 2,
        max_quote_age_secs: 300,
        require_firmware_hash: true,
        require_event_counter: false,
    };

    policy
        .evaluate(
            quote.body.provenance.slsa_level(),
            &quote.body.measurements.firmware_hash,
            quote.body.measurements.event_counter,
            quote.body.timestamp,
            1_700_000_100,
        )
        .expect("policy should accept");
}

#[test]
fn tampered_quote_fails_verification() {
    let (sk, vk) = generate_ml_dsa_keypair().unwrap();
    let rot = SoftwareRoT::new(b"fw", None, 0);

    let mut quote = generate_quote(
        &rot,
        &MlDsaBackend,
        sk.as_bytes(),
        &vk,
        &[0x33u8; 32],
        make_provenance(),
        0,
    )
    .unwrap();

    quote.body.measurements.event_counter = 999;
    let body_cbor = quote.body.to_cbor().unwrap();
    assert!(MlDsaBackend
        .verify(&body_cbor, &vk, &quote.signature)
        .is_err());
}

#[test]
fn nonce_is_preserved_in_quote() {
    let (sk, vk) = generate_ml_dsa_keypair().unwrap();
    let nonce = [0xdeu8; 32];

    let quote = generate_quote(
        &rot_fw(b"fw"),
        &MlDsaBackend,
        sk.as_bytes(),
        &vk,
        &nonce,
        make_provenance(),
        0,
    )
    .unwrap();

    assert_eq!(quote.body.nonce, nonce);
}

#[test]
fn pub_key_id_matches_verifying_key_fingerprint() {
    let (sk, vk) = generate_ml_dsa_keypair().unwrap();

    let quote = generate_quote(
        &rot_fw(b"fw"),
        &MlDsaBackend,
        sk.as_bytes(),
        &vk,
        &[0x55u8; 32],
        make_provenance(),
        0,
    )
    .unwrap();

    assert_eq!(quote.body.pub_key_id, MlDsaBackend::pub_key_id(&vk));
}

fn rot_fw(fw: &[u8]) -> SoftwareRoT<'_> {
    SoftwareRoT::new(fw, None, 0)
}
