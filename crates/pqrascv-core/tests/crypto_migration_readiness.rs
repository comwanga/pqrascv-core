//! Cryptographic migration-readiness invariants.
//!
//! These tests lock the discriminators that `CRYPTO_MIGRATION_PLAN.md` depends on.
//! They encode the CURRENT, documented truth about the crypto trust root so that any
//! future change which would silently break a migration assumption fails CI loudly.
//!
//! Phase 1 of the Enterprise Hardening Program: migration READINESS only — no algorithm
//! is changed here. If one of these tests fails after a dependency bump, that is the
//! signal that the migration has left the "byte-identical, same-parameter-set" lane and
//! must escalate to the re-issuance path described in the migration plan.
//!
//! Run: `cargo test -p pqrascv-core --features std,software-rot-unsafe --test crypto_migration_readiness`

#![cfg(all(feature = "std", feature = "alloc"))]

use pqrascv_core::cose_sign::{CoseSign1, ML_DSA_65_ALG_ID};
use pqrascv_core::crypto::{
    generate_ml_dsa_keypair, pub_key_id, CryptoBackend, MlDsaBackend, ML_DSA_65_SEED_SIZE,
    ML_DSA_65_SIGNATURE_SIZE, ML_DSA_65_VERIFYING_KEY_SIZE, SIGNING_CONTEXT_QUOTE,
};
use pqrascv_core::quote::PROTOCOL_VERSION;

/// The implicit-by-length discriminators for ML-DSA-65 must hold exactly.
/// These sizes are how current artifacts are distinguished from a future parameter set.
#[test]
fn ml_dsa_65_sizes_are_locked() {
    assert_eq!(ML_DSA_65_SEED_SIZE, 32, "ML-DSA-65 seed size discriminator");
    assert_eq!(
        ML_DSA_65_VERIFYING_KEY_SIZE, 1952,
        "ML-DSA-65 verifying key size discriminator"
    );
    assert_eq!(
        ML_DSA_65_SIGNATURE_SIZE, 3309,
        "ML-DSA-65 signature size discriminator"
    );
}

/// A freshly generated keypair must match the locked sizes. If a stable `ml-dsa` release
/// changes any of these, the migration is NOT byte-identical and must re-issue artifacts.
#[test]
fn generated_keypair_matches_locked_sizes() {
    let (seed, vk) = generate_ml_dsa_keypair().expect("keygen");
    assert_eq!(seed.as_bytes().len(), ML_DSA_65_SEED_SIZE);
    assert_eq!(vk.len(), ML_DSA_65_VERIFYING_KEY_SIZE);

    let sig = MlDsaBackend
        .sign(
            b"migration-readiness",
            seed.as_bytes(),
            SIGNING_CONTEXT_QUOTE,
        )
        .expect("sign");
    assert_eq!(sig.as_ref().len(), ML_DSA_65_SIGNATURE_SIZE);
}

/// keyd persists `[seed || vk]` with no version header (migration class C). Lock the
/// 1984-byte length so a future versioned blob (e.g. 1985 bytes with a 1-byte tag) is
/// unambiguously distinguishable, and so accidental format drift fails here.
#[test]
fn keyd_blob_length_invariant_is_locked() {
    let blob_len = ML_DSA_65_SEED_SIZE + ML_DSA_65_VERIFYING_KEY_SIZE;
    assert_eq!(
        blob_len, 1984,
        "keyd keypair blob length must remain 1984B (v0/ML-DSA-65); a versioned format must change this length"
    );
}

/// `pub_key_id` is the algorithm-agnostic identity primitive: SHA3-256 over whatever the
/// key bytes are. Device identity must survive a signature-algorithm migration unchanged.
#[test]
fn pub_key_id_is_algorithm_agnostic_and_stable() {
    // Works on arbitrary byte lengths (not tied to 1952) and is deterministic.
    let short = pub_key_id(b"any-key-bytes");
    let short_again = pub_key_id(b"any-key-bytes");
    assert_eq!(short, short_again, "fingerprint must be deterministic");
    assert_eq!(short.len(), 32, "identity fingerprint is always 32 bytes");

    // Distinct inputs → distinct identities (collision-resistance smoke check).
    assert_ne!(pub_key_id(b"key-a"), pub_key_id(b"key-b"));

    // A real VK also fingerprints to 32 bytes regardless of VK encoding length.
    let (_seed, vk) = generate_ml_dsa_keypair().expect("keygen");
    assert_eq!(pub_key_id(&vk).len(), 32);
}

/// COSE_Sign1 is the best-positioned format: it carries an EXPLICIT algorithm id.
/// Lock the value so a future algorithm gets a distinct id and the two can coexist.
#[test]
fn cose_carries_explicit_algorithm_id() {
    assert_eq!(
        ML_DSA_65_ALG_ID, -48,
        "COSE ML-DSA-65 algorithm id is the explicit migration discriminator"
    );

    // Round-trip proves the alg-tagged envelope verifies end to end today — the
    // cross-verification template a migration will reuse.
    let (seed, vk) = generate_ml_dsa_keypair().expect("keygen");
    let signed = CoseSign1::sign(b"provenance-payload".to_vec(), &seed).expect("cose sign");
    assert!(
        signed.verify(&vk).is_ok(),
        "COSE_Sign1 must verify under the same parameter set"
    );
}

/// The signed wire artifacts carry a protocol version the verifier enforces (no silent
/// downgrade). A parameter-set migration bumps this; lock the current value.
#[test]
fn protocol_version_discriminator_is_locked() {
    assert_eq!(
        PROTOCOL_VERSION, 2,
        "quote protocol version is the wire-format migration discriminator"
    );
}

/// Cross-verification readiness gate (same-parameter-set lane): a signature produced now
/// must verify now. This is the exact assertion a dual-build migration step runs to decide
/// whether RC→stable is byte-compatible. If it ever fails post-bump, escalate to re-issuance.
#[test]
fn cross_verification_gate_same_parameter_set() {
    let (seed, vk) = generate_ml_dsa_keypair().expect("keygen");
    let msg = b"cross-verification gate";
    let sig = MlDsaBackend
        .sign(msg, seed.as_bytes(), SIGNING_CONTEXT_QUOTE)
        .expect("sign");
    assert!(
        MlDsaBackend
            .verify(msg, &vk, sig.as_ref(), SIGNING_CONTEXT_QUOTE)
            .is_ok(),
        "same-parameter-set sign/verify must hold (migration byte-compat gate)"
    );

    // Negative control: a different signing context must not verify (domain separation
    // carries forward across migration unchanged).
    assert!(
        MlDsaBackend
            .verify(msg, &vk, sig.as_ref(), b"pqrascv-cert-v2")
            .is_err(),
        "domain separation must hold across the migration boundary"
    );
}
