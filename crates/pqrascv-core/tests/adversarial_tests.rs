//! Adversarial integration tests.
//!
//! Every test here simulates a concrete attack and asserts it is rejected.
#![cfg(all(feature = "std", feature = "alloc", feature = "software-rot-unsafe"))]

use pqrascv_core::{
    config::PolicyConfig,
    crypto::{
        generate_ml_dsa_keypair, CryptoBackend, MlDsaBackend,
        SIGNING_CONTEXT_CERT, SIGNING_CONTEXT_CRL, SIGNING_CONTEXT_QUOTE,
    },
    error::PqRascvError,
    measurement::SoftwareRoT,
    nonce::{InMemoryNonceLedger, NonceLedger},
    pki::{
        build_device_certificate, validate_chain, CaPublicKey, HardwareIdentity, TrustAnchor,
        CERT_VERSION,
    },
    provenance::SlsaPredicateBuilder,
    quote::{generate_quote, AttestationQuote, QuoteTimestamp},
};
use pqrascv_verifier::Verifier;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_provenance() -> pqrascv_core::provenance::InTotoAttestation {
    SlsaPredicateBuilder::new("https://ci.test")
        .add_subject("fw.bin", &[0xabu8; 32])
        .with_slsa_level(2)
        .build()
        .unwrap()
}

fn make_quote_cbor(
    seed: &pqrascv_core::crypto::SigningKeySeed,
    vk: &[u8; pqrascv_core::crypto::ML_DSA_65_VERIFYING_KEY_SIZE],
    nonce: &[u8; 32],
) -> Vec<u8> {
    let rot = SoftwareRoT::new(b"adversarial-fw", None, 1);
    let quote = generate_quote(
        &rot,
        &MlDsaBackend,
        seed.as_bytes(),
        vk,
        nonce,
        make_provenance(),
        QuoteTimestamp::Rtc(1_700_000_000),
    )
    .unwrap();
    quote.to_cbor().unwrap()
}

fn sign_cert(cert: &mut pqrascv_core::pki::DeviceCertificate, signer_seed: &[u8]) {
    let tbs = cert.tbs_cbor().unwrap();
    let sig = MlDsaBackend
        .sign(&tbs, signer_seed, SIGNING_CONTEXT_CERT)
        .unwrap();
    cert.issuer_signature = sig.as_ref().to_vec();
}

// ── Cross-context confusion ───────────────────────────────────────────────────

#[test]
fn cert_signature_cannot_be_reused_as_quote_signature() {
    let (seed, vk) = generate_ml_dsa_keypair().unwrap();
    let message = b"shared-message";

    let cert_sig = MlDsaBackend
        .sign(message, seed.as_bytes(), SIGNING_CONTEXT_CERT)
        .unwrap();
    assert!(
        MlDsaBackend
            .verify(message, &vk, cert_sig.as_ref(), SIGNING_CONTEXT_QUOTE)
            .is_err(),
        "cert signature must not verify under quote context"
    );
}

#[test]
fn quote_signature_cannot_be_reused_as_cert_signature() {
    let (seed, vk) = generate_ml_dsa_keypair().unwrap();
    let message = b"shared-message";

    let quote_sig = MlDsaBackend
        .sign(message, seed.as_bytes(), SIGNING_CONTEXT_QUOTE)
        .unwrap();
    assert!(
        MlDsaBackend
            .verify(message, &vk, quote_sig.as_ref(), SIGNING_CONTEXT_CERT)
            .is_err(),
        "quote signature must not verify under cert context"
    );
}

#[test]
fn crl_signature_cannot_be_reused_as_quote_signature() {
    let (seed, vk) = generate_ml_dsa_keypair().unwrap();
    let message = b"shared-message";

    let crl_sig = MlDsaBackend
        .sign(message, seed.as_bytes(), SIGNING_CONTEXT_CRL)
        .unwrap();
    assert!(MlDsaBackend
        .verify(message, &vk, crl_sig.as_ref(), SIGNING_CONTEXT_QUOTE)
        .is_err());
    assert!(MlDsaBackend
        .verify(message, &vk, crl_sig.as_ref(), SIGNING_CONTEXT_CERT)
        .is_err());
}

// ── Replay attacks ────────────────────────────────────────────────────────────

#[test]
fn consumed_nonce_cannot_be_replayed() {
    let mut ledger = InMemoryNonceLedger::default();
    let nonce = [0x55u8; 32];
    let handle = ledger.register(nonce).unwrap();
    ledger.consume(handle.as_bytes()).unwrap();
    // Replay: attempting to consume the same nonce again must fail
    assert_eq!(
        ledger.consume(&nonce),
        Err(PqRascvError::InvalidNonce),
        "replayed nonce must be rejected"
    );
}

#[test]
fn different_nonce_quote_fails_verification() {
    let (seed, vk) = generate_ml_dsa_keypair().unwrap();
    let nonce_used = [0x11u8; 32];
    let nonce_claimed = [0x22u8; 32]; // different from what was signed into the quote

    let cbor = make_quote_cbor(&seed, &vk, &nonce_used);
    let verifier = Verifier::new(PolicyConfig::default());
    assert!(
        verifier
            .verify_cbor(&cbor, &vk, &nonce_claimed, 1_700_000_100)
            .is_err(),
        "nonce mismatch must be rejected"
    );
}

// ── Quote body forgery ────────────────────────────────────────────────────────

#[test]
fn tampered_firmware_hash_fails_signature_verification() {
    let (seed, vk) = generate_ml_dsa_keypair().unwrap();
    let nonce = [0x33u8; 32];
    let cbor_original = make_quote_cbor(&seed, &vk, &nonce);

    let mut quote = AttestationQuote::from_cbor(&cbor_original).unwrap();
    quote.body.measurements.firmware_hash = [0xFFu8; 32]; // tamper
    let cbor_tampered = quote.to_cbor().unwrap();

    let verifier = Verifier::new(PolicyConfig::default());
    assert!(
        verifier
            .verify_cbor(&cbor_tampered, &vk, &nonce, 1_700_000_100)
            .is_err(),
        "tampered firmware hash must fail signature check"
    );
}

#[test]
fn tampered_slsa_level_fails_signature_verification() {
    let (seed, vk) = generate_ml_dsa_keypair().unwrap();
    let nonce = [0x44u8; 32];
    let cbor_original = make_quote_cbor(&seed, &vk, &nonce);

    let mut quote = AttestationQuote::from_cbor(&cbor_original).unwrap();
    quote.body.provenance.build.slsa_level = 4; // inflate to 4
    let cbor_tampered = quote.to_cbor().unwrap();

    let verifier = Verifier::new(PolicyConfig::default());
    assert!(
        verifier
            .verify_cbor(&cbor_tampered, &vk, &nonce, 1_700_000_100)
            .is_err(),
        "inflated SLSA level must fail signature check"
    );
}

// ── Certificate chain forgery ─────────────────────────────────────────────────

#[test]
fn cert_with_forged_tbs_fails_chain_validation() {
    let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
    let (_, dev_vk) = generate_ml_dsa_keypair().unwrap();
    let anchor = TrustAnchor::new(CaPublicKey {
        key_bytes: ca_vk,
        ca_id: "https://ca.test",
    });

    let subject_key_id = pqrascv_core::crypto::pub_key_id(&dev_vk);
    let mut cert = build_device_certificate(
        CERT_VERSION,
        "DEV-001".to_string(),
        "https://ca.test".to_string(),
        0,
        u64::MAX,
        dev_vk.to_vec(),
        subject_key_id,
        HardwareIdentity::TpmEkCertHash([0u8; 32]),
        None,
        vec![],
        "https://dev.test".to_string(),
        Some(0),
    );
    sign_cert(&mut cert, ca_seed.as_bytes()); // legitimate signature

    // Tamper: change serial AFTER signing
    cert.serial = "DEV-ATTACKER".to_string();

    assert!(
        validate_chain(cert, vec![], &anchor, 1_000).is_err(),
        "cert with forged serial must fail chain validation"
    );
}

#[test]
fn cert_with_wrong_issuer_id_fails_chain_validation() {
    let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
    let (_, dev_vk) = generate_ml_dsa_keypair().unwrap();
    let anchor = TrustAnchor::new(CaPublicKey {
        key_bytes: ca_vk,
        ca_id: "https://ca.test",
    });

    let subject_key_id = pqrascv_core::crypto::pub_key_id(&dev_vk);
    let mut cert = build_device_certificate(
        CERT_VERSION,
        "DEV-001".to_string(),
        "https://evil.ca".to_string(), // wrong issuer
        0,
        u64::MAX,
        dev_vk.to_vec(),
        subject_key_id,
        HardwareIdentity::TpmEkCertHash([0u8; 32]),
        None,
        vec![],
        "https://dev.test".to_string(),
        Some(0),
    );
    sign_cert(&mut cert, ca_seed.as_bytes());

    assert!(matches!(
        validate_chain(cert, vec![], &anchor, 1_000),
        Err(PqRascvError::CertificateInvalid)
    ));
}

// ── Protocol version downgrade ────────────────────────────────────────────────

#[test]
fn protocol_version_downgrade_is_rejected() {
    let (seed, vk) = generate_ml_dsa_keypair().unwrap();
    let nonce = [0x66u8; 32];
    let cbor = make_quote_cbor(&seed, &vk, &nonce);

    let mut quote = AttestationQuote::from_cbor(&cbor).unwrap();
    quote.body.version = 0; // downgrade to version 0
    let cbor_downgraded = quote.to_cbor().unwrap();

    let verifier = Verifier::new(PolicyConfig::default());
    assert!(matches!(
        verifier.verify_cbor(&cbor_downgraded, &vk, &nonce, 1_700_000_100),
        Err(PqRascvError::UnsupportedVersion)
    ));
}
