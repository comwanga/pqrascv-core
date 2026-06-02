//! End-to-end CLI tests: drive the built `pqrascv` binary through the
//! keygen → attest → verify lifecycle and the key failure paths.
//!
//! These invoke the compiled binary via cargo's `CARGO_BIN_EXE_pqrascv` env var,
//! so no extra harness is required. The CLI uses `SoftwareRoT` (gated behind the
//! `--software-rot-acknowledged` flag), which is why `attest` here passes it.

use std::fs;
use std::path::Path;
use std::process::Command;

fn pqrascv() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pqrascv"))
}

/// 64 hex chars = a fixed 32-byte nonce.
const NONCE_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NONCE_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// Runs `keygen` then `attest` in `dir`, returning the (vk, quote) paths.
fn keygen_and_attest(dir: &Path, nonce: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let seed = dir.join("seed.bin");
    let vk = dir.join("vk.bin");
    let fw = dir.join("fw.bin");
    let quote = dir.join("quote.cbor");
    fs::write(&fw, b"test-firmware-image").unwrap();

    let out = pqrascv()
        .args([
            "keygen",
            "--out-seed",
            seed.to_str().unwrap(),
            "--out-vk",
            vk.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::metadata(&seed).unwrap().len(), 32, "seed is 32 bytes");
    assert_eq!(fs::metadata(&vk).unwrap().len(), 1952, "vk is 1952 bytes");

    let out = pqrascv()
        .args([
            "attest",
            "--seed",
            seed.to_str().unwrap(),
            "--vk",
            vk.to_str().unwrap(),
            "--firmware",
            fw.to_str().unwrap(),
            "--nonce",
            nonce,
            "--out",
            quote.to_str().unwrap(),
            "--software-rot-acknowledged",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "attest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(quote.exists(), "quote file written");
    (vk, quote)
}

#[test]
fn keygen_attest_verify_roundtrip_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let (vk, quote) = keygen_and_attest(dir.path(), NONCE_A);

    let out = pqrascv()
        .args([
            "verify",
            "--vk",
            vk.to_str().unwrap(),
            "--quote",
            quote.to_str().unwrap(),
            "--nonce",
            NONCE_A,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "verify of a valid quote must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn verify_rejects_wrong_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let (vk, quote) = keygen_and_attest(dir.path(), NONCE_A);

    // Verify with a different nonce than the quote was bound to.
    let out = pqrascv()
        .args([
            "verify",
            "--vk",
            vk.to_str().unwrap(),
            "--quote",
            quote.to_str().unwrap(),
            "--nonce",
            NONCE_B,
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "verify with the wrong nonce must fail (non-zero exit)"
    );
}

#[test]
fn attest_requires_software_rot_acknowledged() {
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("seed.bin");
    let vk = dir.path().join("vk.bin");
    let fw = dir.path().join("fw.bin");
    fs::write(&fw, b"fw").unwrap();
    let out = pqrascv()
        .args([
            "keygen",
            "--out-seed",
            seed.to_str().unwrap(),
            "--out-vk",
            vk.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // attest WITHOUT the acknowledgement flag must be refused.
    let out = pqrascv()
        .args([
            "attest",
            "--seed",
            seed.to_str().unwrap(),
            "--vk",
            vk.to_str().unwrap(),
            "--firmware",
            fw.to_str().unwrap(),
            "--nonce",
            NONCE_A,
            "--out",
            dir.path().join("q.cbor").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "attest without --software-rot-acknowledged must be refused"
    );
}

#[test]
fn verify_rejects_garbage_quote() {
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("seed.bin");
    let vk = dir.path().join("vk.bin");
    let quote = dir.path().join("garbage.cbor");
    let out = pqrascv()
        .args([
            "keygen",
            "--out-seed",
            seed.to_str().unwrap(),
            "--out-vk",
            vk.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    fs::write(&quote, b"not a valid cbor quote").unwrap();

    let out = pqrascv()
        .args([
            "verify",
            "--vk",
            vk.to_str().unwrap(),
            "--quote",
            quote.to_str().unwrap(),
            "--nonce",
            NONCE_A,
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "verify of a malformed quote must fail"
    );
}
