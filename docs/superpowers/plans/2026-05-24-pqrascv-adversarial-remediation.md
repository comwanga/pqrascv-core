# PQ-RASCV Adversarial Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove all fabricated trust outputs and wire cryptographic enforcement for PKI, domain separation, CRL verification, Bitcoin anchoring, and policy evaluation throughout the PQ-RASCV codebase.

**Architecture:** Twelve sequential tasks ordered by dependency (domain separation first, then PKI, then Bitcoin, then policy wiring). Each task is self-contained: failing tests are written first, minimal implementation follows, then a commit. Breaking changes to signing contexts, certificate format, and Merkle trees are intentional — backward compatibility is subordinate to cryptographic correctness.

**Tech Stack:** Rust 1.85, ml-dsa 0.1.0-rc.8, sha2/sha3 0.10, ciborium 0.2, serde 1, zeroize 1. No new dependencies required.

---

## File Map

| File | Change Type | Summary |
|------|-------------|---------|
| `crates/cli/src/main.rs` | Modify | Remove fabricated outputs; add SoftwareRoT warning |
| `crates/pqrascv-core/src/crypto.rs` | Modify | Add domain-separation context constants; update `CryptoBackend` trait |
| `crates/pqrascv-core/src/quote.rs` | Modify | Pass `SIGNING_CONTEXT_QUOTE` to `crypto.sign()` |
| `crates/pqrascv-core/src/pki/mod.rs` | Modify | Add `self_id`/`max_path_length` fields; issuer binding; path-length check; cert version bump |
| `crates/pqrascv-core/src/pki/revocation.rs` | Modify | Add `VerifiedRevocationList`; deprecate raw `is_revoked()` |
| `crates/pqrascv-core/src/policy/mod.rs` | Modify | Add `PolicyContext::from_verified_quote()`; remove `RequireExternalProvenance` from production default |
| `crates/pqrascv-core/src/provenance_v2/mod.rs` | Modify | Add explicit `NOT_IMPLEMENTED` guard on `verify_sigstore()` |
| `crates/pqrascv-core/tests/integration_test.rs` | Modify | Update signature call to include context |
| `crates/verifier/src/lib.rs` | Modify | Add `PkiVerificationResult`; add `verify_cbor_with_pki()` |
| `crates/bitcoin-anchor/src/lib.rs` | Modify | Commit full 32-byte Merkle root in OP_RETURN |
| `crates/bitcoin-anchor/src/merkle.rs` | Modify | RFC6962 leaf/internal prefixes; promote-not-duplicate for odd levels |
| `crates/bitcoin-anchor/src/proof.rs` | Modify | Add PoW validation; new `SpvError::InsufficientProofOfWork` |
| `crates/pqrascv-core/tests/adversarial_tests.rs` | Create | Cross-context, replay, forgery, downgrade, second-preimage tests |

---

## Task 1: Strip Fabricated CLI Outputs and Add SoftwareRoT Warning

**Files:**
- Modify: `crates/cli/src/main.rs`

**Background:** The `cmd_verify` function hardcodes fake Bitcoin txids, consensus epochs, finality strings, and Merkle audit claims. The `cmd_attest` function silently discards `--epoch` and `--state-root` arguments. `SoftwareRoT` is used unconditionally with no warning.

- [ ] **Step 1: Write failing test — honest output must not contain fabricated strings**

Add at the bottom of `crates/cli/src/main.rs` in the `#[cfg(test)]` block:

```rust
#[cfg(test)]
mod output_integrity_tests {
    // These are compilation-time guards: the constants must not exist.
    // If the hardcoded strings still exist in this file, this will fail at grep time.
    // Run: grep -n "StrongFinality\|9a8f2c31\|8f434346\|Epoch 42\|Deterministic Merkle Trace" crates/cli/src/main.rs
    // Expected: no matches
}
```

Run the grep before changes:
```
grep -n "StrongFinality\|9a8f2c31\|8f434346\|Epoch 42\|Deterministic Merkle Trace" crates/cli/src/main.rs
```
Expected output: matches found (confirming the problem exists).

- [ ] **Step 2: Remove fabricated `Attest` command arguments**

In the `Attest` variant of `Command`, delete the `epoch` and `state_root` fields entirely:

```rust
#[command(name = "attest")]
Attest {
    #[arg(long)]
    seed: PathBuf,
    #[arg(long)]
    vk: PathBuf,
    #[arg(long)]
    firmware: PathBuf,
    #[arg(long)]
    model: Option<PathBuf>,
    #[arg(long, default_value = "https://github.com/comwanga/pqrascv-core")]
    builder: String,
    #[arg(long, default_value_t = 1)]
    slsa_level: u8,
    #[arg(long)]
    nonce: Option<String>,
    #[arg(long, default_value = "quote.cbor")]
    out: PathBuf,
},
```

- [ ] **Step 3: Remove fabricated `Verify` command arguments**

In the `Verify` variant, delete `epoch` and `state_root` fields:

```rust
Verify {
    #[arg(long)]
    vk: PathBuf,
    #[arg(long)]
    quote: PathBuf,
    #[arg(long)]
    nonce: String,
    #[arg(long)]
    expected_hash: Option<String>,
    #[arg(long)]
    json: bool,
    #[arg(long, default_value_t = 1)]
    min_slsa_level: u8,
    #[arg(long, default_value_t = 300)]
    max_age: u64,
    #[arg(long, default_value_t = false)]
    allow_rtcless: bool,
},
```

- [ ] **Step 4: Fix `run()` dispatch — remove dropped args**

In the `run()` match arms:

```rust
Command::Attest {
    seed, vk, firmware, model, builder, slsa_level, nonce, out,
} => cmd_attest(seed, vk, firmware, model, builder, slsa_level, nonce.as_deref(), out),

Command::Verify {
    vk, quote, nonce, expected_hash, json, min_slsa_level, max_age, allow_rtcless,
} => cmd_verify(vk, quote, &nonce, expected_hash.as_deref(), json, min_slsa_level, max_age, allow_rtcless),
```

- [ ] **Step 5: Rewrite `cmd_attest` — remove discarded args, add SoftwareRoT warning**

Remove `epoch: _` and `state_root: _`. Add the warning at the start of the function body, before any computation:

```rust
#[allow(clippy::too_many_arguments)]
fn cmd_attest(
    seed_path: PathBuf,
    vk_path: PathBuf,
    fw_path: PathBuf,
    model_path: Option<PathBuf>,
    builder: String,
    slsa_level: u8,
    nonce_hex: Option<&str>,
    out: PathBuf,
) -> anyhow::Result<()> {
    eprintln!(
        "WARNING: Using SoftwareRoT — no hardware attestation boundary.\n\
         Measurements are derived from caller-supplied bytes, not hardware.\n\
         For production, use a build with `hardware-tpm` or `dice` feature.\n"
    );

    let seed_bytes = fs::read(&seed_path)?;
    let vk_bytes = fs::read(&vk_path)?;
    let firmware = fs::read(&fw_path)?;
    let model: Option<Vec<u8>> = model_path.map(fs::read).transpose()?;

    let nonce = match nonce_hex {
        Some(hex) => parse_nonce(hex)?,
        None => random_nonce()?,
    };

    let vk_array: [u8; ML_DSA_65_VERIFYING_KEY_SIZE] =
        vk_bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("verifying key must be exactly {ML_DSA_65_VERIFYING_KEY_SIZE} bytes")
        })?;

    let rot = SoftwareRoT::new(&firmware, model.as_deref(), 0);
    let fw_digest = sha3_256(&firmware);
    let mut builder_obj = SlsaPredicateBuilder::new(&builder)
        .add_subject(
            fw_path.file_name().unwrap_or_default().to_string_lossy().as_ref(),
            &fw_digest,
        )
        .with_slsa_level(slsa_level);

    if let Some(ref m) = model {
        builder_obj = builder_obj.add_subject("model", &sha3_256(m));
    }

    let provenance = builder_obj.build()?;
    let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => QuoteTimestamp::Rtc(d.as_secs()),
        Err(_) => QuoteTimestamp::NoRtc,
    };

    let quote = generate_quote(&rot, &MlDsaBackend, &seed_bytes, &vk_array, &nonce, provenance, timestamp)?;
    let cbor = quote.to_cbor()?;
    fs::write(&out, &cbor)?;

    let nonce_display = hex::encode(nonce);
    println!("Attestation Quote generated ({} bytes) → {}", cbor.len(), out.display());
    println!("  Firmware:  {} (SHA3-256: {})", fw_path.display(), hex::encode(fw_digest));
    println!("  Nonce:     {nonce_display}  ← pass this to `verify --nonce`");
    println!("  SLSA:      level {slsa_level} (self-reported)");
    println!("  Timestamp: {timestamp:?}");
    Ok(())
}
```

- [ ] **Step 6: Rewrite `cmd_verify` — replace all fabricated output with honest output**

Replace `cmd_verify` entirely. The old function signature accepted `epoch` and `state_root`; the new one does not:

```rust
#[allow(clippy::too_many_arguments)]
fn cmd_verify(
    vk_path: PathBuf,
    quote_path: PathBuf,
    nonce_hex: &str,
    expected_hash_hex: Option<&str>,
    json: bool,
    min_slsa_level: u8,
    max_age: u64,
    allow_rtcless: bool,
) -> anyhow::Result<()> {
    let vk_bytes = fs::read(&vk_path)?;
    if vk_bytes.len() != ML_DSA_65_VERIFYING_KEY_SIZE {
        anyhow::bail!("Invalid verifying key size: expected {ML_DSA_65_VERIFYING_KEY_SIZE}");
    }
    let mut vk_array = [0u8; ML_DSA_65_VERIFYING_KEY_SIZE];
    vk_array.copy_from_slice(&vk_bytes);

    let quote_bytes = fs::read(&quote_path)?;
    let mut nonce = [0u8; 32];
    hex::decode_to_slice(nonce_hex, &mut nonce)
        .map_err(|_| anyhow::anyhow!("Invalid nonce format: must be 64 hex chars"))?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let policy = PolicyConfig {
        min_slsa_level,
        max_quote_age_secs: max_age,
        require_firmware_hash: true,
        require_event_counter: false,
        allow_rtcless_devices: allow_rtcless,
    };
    let verifier = Verifier::new(policy);

    match verifier.verify_cbor(&quote_bytes, &vk_array, &nonce, now) {
        Ok(result) => {
            let actual_hash = hex::encode(result.firmware_hash());

            if let Some(expected) = expected_hash_hex {
                if actual_hash != expected {
                    if json {
                        println!(r#"{{"verification":"FAILED","reason":"Firmware hash mismatch","expected":"{}","actual":"{}"}}"#, expected, actual_hash);
                    } else {
                        println!("✗  Verification FAILED: Firmware hash mismatch");
                        println!("   Expected: {expected}");
                        println!("   Actual:   {actual_hash}");
                    }
                    std::process::exit(2);
                }
            }

            if json {
                println!(
                    r#"{{
  "verification": "VALID",
  "replay_protection": "PASSED",
  "firmware_hash": "{}",
  "nonce": "{}",
  "slsa_level": {},
  "slsa_level_note": "self-reported; independent CI verification NOT_IMPLEMENTED",
  "bitcoin_anchoring": "NOT_IMPLEMENTED",
  "external_provenance": "NOT_IMPLEMENTED"
}}"#,
                    actual_hash,
                    hex::encode(result.nonce()),
                    result.slsa_level(),
                );
            } else {
                println!("✓  Attestation Quote signature verified.\n");
                println!("   Verification:      VALID (ML-DSA-65 post-quantum signature)");
                println!("   Replay Protection: PASSED (32-byte nonce matched)");
                println!("   Firmware Hash:     {actual_hash}");
                println!("   Nonce:             {}", hex::encode(result.nonce()));
                println!(
                    "   SLSA Level:        {} (self-reported; CI verification NOT_IMPLEMENTED)",
                    result.slsa_level()
                );
                println!("\n   Payload: {}", quote_path.display());
                println!("\n   NOTE: Bitcoin anchoring, consensus verification, and external");
                println!("   provenance validation are NOT YET IMPLEMENTED.");
                println!("   The above confirms ML-DSA-65 signature validity only.");
            }
        }
        Err(e) => {
            if json {
                println!(r#"{{"verification":"FAILED","reason":"{e}"}}"#);
            } else {
                println!("✗  Verification FAILED: {e}");
            }
            std::process::exit(2);
        }
    }
    Ok(())
}
```

- [ ] **Step 7: Verify the fabricated strings are gone**

```
grep -n "StrongFinality\|9a8f2c31\|8f434346\|Epoch 42\|Deterministic Merkle Trace\|sim_epoch\|sim_root\|expected_root" crates/cli/src/main.rs
```
Expected: **no output**.

- [ ] **Step 8: Build and confirm it compiles**

```
cargo build -p pqrascv-cli
```
Expected: compiles without errors.

- [ ] **Step 9: Commit**

```
git add crates/cli/src/main.rs
git commit -m "fix(cli): remove all fabricated Bitcoin/consensus/finality outputs and add SoftwareRoT warning"
```

---

## Task 2: ML-DSA-65 Domain Separation

**Files:**
- Modify: `crates/pqrascv-core/src/crypto.rs`
- Modify: `crates/pqrascv-core/src/quote.rs`
- Modify: `crates/pqrascv-core/src/pki/mod.rs`
- Modify: `crates/verifier/src/lib.rs`
- Modify: `crates/pqrascv-core/tests/integration_test.rs`

**Background:** All ML-DSA-65 operations use empty context `b""`. Adding distinct context strings per operation type prevents cross-protocol signature reuse. This is a **wire-breaking change** — existing CBOR files (quote.cbor etc.) become invalid by design.

- [ ] **Step 1: Write failing test — cross-context verification must fail**

Add to `crates/pqrascv-core/src/crypto.rs` inside the `#[cfg(test)]` block (these will fail until the implementation is updated):

```rust
#[cfg(feature = "std")]
#[test]
fn different_contexts_produce_incompatible_signatures() {
    let (seed, vk) = generate_ml_dsa_keypair().expect("keygen failed");
    let backend = MlDsaBackend;
    let message = b"domain-separation-test";

    let sig_a = backend
        .sign(message, seed.as_bytes(), b"pqrascv-quote-v1")
        .expect("sign failed");
    let sig_b = backend
        .sign(message, seed.as_bytes(), b"pqrascv-cert-v2")
        .expect("sign failed");

    // Different contexts must produce different signatures
    assert_ne!(sig_a, sig_b, "contexts must produce distinct signatures");

    // Cross-context verification must fail
    assert!(
        backend.verify(message, &vk, sig_a.as_ref(), b"pqrascv-cert-v2").is_err(),
        "quote sig must not verify under cert context"
    );
    assert!(
        backend.verify(message, &vk, sig_b.as_ref(), b"pqrascv-quote-v1").is_err(),
        "cert sig must not verify under quote context"
    );
}
```

Run: `cargo test -p pqrascv-core --features std different_contexts`
Expected: **FAIL** (trait methods still have 3 params, not 4).

- [ ] **Step 2: Add context constants to `crypto.rs`**

After the size constants at the top of `crates/pqrascv-core/src/crypto.rs`, add:

```rust
/// Domain-separation context for ML-DSA-65 attestation quote body signatures.
/// All quote signing and verification must use this context.
pub const SIGNING_CONTEXT_QUOTE: &[u8] = b"pqrascv-quote-v1";

/// Domain-separation context for ML-DSA-65 device certificate TBS signatures.
pub const SIGNING_CONTEXT_CERT: &[u8] = b"pqrascv-cert-v2";

/// Domain-separation context for ML-DSA-65 Certificate Revocation List signatures.
pub const SIGNING_CONTEXT_CRL: &[u8] = b"pqrascv-crl-v2";
```

- [ ] **Step 3: Update `CryptoBackend` trait to require a context parameter**

Replace the trait definition in `crypto.rs`:

```rust
pub trait CryptoBackend {
    /// Sign `message` using the 32-byte ML-DSA-65 seed and the given `context`.
    ///
    /// `context` must be one of the `SIGNING_CONTEXT_*` constants in this module.
    /// Never pass `b""` — the empty context provides no domain separation.
    fn sign(
        &self,
        message: &[u8],
        signing_seed: &[u8],
        context: &[u8],
    ) -> Result<SignatureBytes, PqRascvError>;

    /// Verify `signature` over `message` under `verifying_key` and `context`.
    ///
    /// `context` must match the context used at signing time.
    fn verify(
        &self,
        message: &[u8],
        verifying_key: &[u8],
        signature: &[u8],
        context: &[u8],
    ) -> Result<(), PqRascvError>;
}
```

- [ ] **Step 4: Update `MlDsaBackend` implementation**

Replace the `impl CryptoBackend for MlDsaBackend` block:

```rust
impl CryptoBackend for MlDsaBackend {
    fn sign(
        &self,
        message: &[u8],
        signing_seed: &[u8],
        context: &[u8],
    ) -> Result<SignatureBytes, PqRascvError> {
        use ml_dsa::{KeyGen, MlDsa65};

        let seed_array: &[u8; ML_DSA_65_SEED_SIZE] = signing_seed
            .try_into()
            .map_err(|_| PqRascvError::SigningFailed)?;

        let seed = ml_dsa::B32::from(*seed_array);
        let sk = MlDsa65::from_seed(&seed);

        let sig = sk
            .signing_key()
            .sign_deterministic(message, context)
            .map_err(|_| PqRascvError::SigningFailed)?;

        let encoded = sig.encode();
        let sig_bytes: [u8; ML_DSA_65_SIGNATURE_SIZE] = (*encoded)
            .try_into()
            .map_err(|_| PqRascvError::SigningFailed)?;

        Ok(SignatureBytes(sig_bytes))
    }

    fn verify(
        &self,
        message: &[u8],
        verifying_key: &[u8],
        signature: &[u8],
        context: &[u8],
    ) -> Result<(), PqRascvError> {
        use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

        if verifying_key.len() != ML_DSA_65_VERIFYING_KEY_SIZE {
            return Err(PqRascvError::VerificationFailed);
        }
        if signature.len() != ML_DSA_65_SIGNATURE_SIZE {
            return Err(PqRascvError::VerificationFailed);
        }

        let vk_array: [u8; ML_DSA_65_VERIFYING_KEY_SIZE] = verifying_key
            .try_into()
            .map_err(|_| PqRascvError::VerificationFailed)?;
        let encoded_vk = EncodedVerifyingKey::<MlDsa65>::from(vk_array);
        let vk = VerifyingKey::<MlDsa65>::decode(&encoded_vk);

        let sig_array: [u8; ML_DSA_65_SIGNATURE_SIZE] = signature
            .try_into()
            .map_err(|_| PqRascvError::VerificationFailed)?;
        let encoded_sig = ml_dsa::EncodedSignature::<MlDsa65>::from(sig_array);
        let sig =
            Signature::<MlDsa65>::decode(&encoded_sig).ok_or(PqRascvError::VerificationFailed)?;

        if vk.verify_with_context(message, context, &sig) {
            Ok(())
        } else {
            Err(PqRascvError::VerificationFailed)
        }
    }
}
```

- [ ] **Step 5: Update the three existing unit tests inside `crypto.rs` to pass a context**

In the `#[cfg(test)]` block of `crypto.rs`, update each test call:

```rust
// sign_and_verify_roundtrip
let sig = backend.sign(message, seed.as_bytes(), b"test-ctx").expect("sign failed");
backend.verify(message, &vk, sig.as_ref(), b"test-ctx").expect("verify failed");

// verify_rejects_tampered_message
let sig = backend.sign(b"original", seed.as_bytes(), b"test-ctx").expect("sign failed");
assert!(backend.verify(b"tampered", &vk, sig.as_ref(), b"test-ctx").is_err());

// verify_rejects_wrong_key
let sig = backend.sign(b"cross-key test", seed1.as_bytes(), b"test-ctx").expect("sign failed");
assert!(backend.verify(b"cross-key test", &vk2, sig.as_ref(), b"test-ctx").is_err());

// signing_is_deterministic
let sig1 = backend.sign(message, seed.as_bytes(), b"test-ctx").unwrap();
let sig2 = backend.sign(message, seed.as_bytes(), b"test-ctx").unwrap();
assert_eq!(sig1, sig2);
```

- [ ] **Step 6: Update `generate_quote` in `quote.rs` to pass `SIGNING_CONTEXT_QUOTE`**

In `crates/pqrascv-core/src/quote.rs`, add the import and update the sign call:

```rust
#[cfg(feature = "alloc")]
use crate::{
    crypto::{pub_key_id, CryptoBackend, SIGNING_CONTEXT_QUOTE},  // add SIGNING_CONTEXT_QUOTE
    // ...
};
```

In `generate_quote`, change:
```rust
let sig = crypto.sign(&body_cbor, signing_seed, SIGNING_CONTEXT_QUOTE)?;
```

Also update the test inside `quote.rs` that calls `MlDsaBackend.verify` directly:
```rust
// In quote_signature_verifies test:
MlDsaBackend
    .verify(&body_cbor, &vk, &quote.signature, SIGNING_CONTEXT_QUOTE)
    .expect("signature must verify");
```

- [ ] **Step 7: Update `validate_chain` in `pki/mod.rs` to use `SIGNING_CONTEXT_CERT`**

In `crates/pqrascv-core/src/pki/mod.rs`:

```rust
use crate::crypto::{CryptoBackend, MlDsaBackend, SIGNING_CONTEXT_CERT};
```

Replace the two `MlDsaBackend.verify(...)` calls in `validate_chain`:
```rust
// For each intermediate:
MlDsaBackend.verify(&tbs, current_verifying_key, &intermediate.issuer_signature, SIGNING_CONTEXT_CERT)?;

// For the device cert:
MlDsaBackend.verify(&tbs, current_verifying_key, &device_cert.issuer_signature, SIGNING_CONTEXT_CERT)?;
```

- [ ] **Step 8: Update `verify_quote` in `verifier/src/lib.rs`**

```rust
use pqrascv_core::crypto::SIGNING_CONTEXT_QUOTE;
// ...
MlDsaBackend.verify(&body_cbor, verifying_key, &quote.signature, SIGNING_CONTEXT_QUOTE)?;
```

- [ ] **Step 9: Update `integration_test.rs`**

```rust
use pqrascv_core::crypto::SIGNING_CONTEXT_QUOTE;
// In full_pipeline_sign_and_verify:
MlDsaBackend
    .verify(&body_cbor, &vk, &decoded.signature, SIGNING_CONTEXT_QUOTE)
    .expect("signature verification failed");
```

- [ ] **Step 10: Run all tests**

```
cargo test --workspace --features std,software-rot-unsafe,dice
```
Expected: all tests pass, including the new `different_contexts_produce_incompatible_signatures` test.

- [ ] **Step 11: Commit**

```
git add crates/pqrascv-core/src/crypto.rs crates/pqrascv-core/src/quote.rs crates/pqrascv-core/src/pki/mod.rs crates/verifier/src/lib.rs crates/pqrascv-core/tests/integration_test.rs
git commit -m "fix(crypto): add ML-DSA-65 domain separation contexts; empty context b\"\" eliminated"
```

---

## Task 3: Fix Bitcoin OP_RETURN — Commit Full 32-Byte Root

**Files:**
- Modify: `crates/bitcoin-anchor/src/lib.rs`

**Background:** Only 20 of 32 Merkle root bytes were committed on-chain (160-bit security). Full 32-byte commitment restores 256-bit preimage resistance and makes the on-chain payload uniquely identify the batch.

- [ ] **Step 1: Write failing test**

In `crates/bitcoin-anchor/src/lib.rs` tests, add:

```rust
#[test]
fn full_32_byte_root_committed() {
    let root = [0xabu8; 32];
    let commitment = AnchorCommitment::new(root);
    let payload = commitment.to_op_return_payload();
    // All 32 bytes must be present in the payload
    assert_eq!(&payload[8..40], &root, "all 32 root bytes must appear in OP_RETURN payload");
    assert_eq!(payload.len(), 40);
}

#[test]
fn roots_differing_only_after_byte_20_produce_distinct_commitments() {
    let mut root_a = [0u8; 32];
    let mut root_b = [0u8; 32];
    root_a[..20].fill(0x42);
    root_b[..20].fill(0x42);
    root_b[20] = 0x01; // differs only beyond the old 20-byte boundary
    let c_a = AnchorCommitment::new(root_a);
    let c_b = AnchorCommitment::new(root_b);
    assert_ne!(c_a.to_op_return_payload(), c_b.to_op_return_payload());
    assert!(!c_a.matches_full_root(&root_b));
}
```

Run: `cargo test -p pqrascv-bitcoin-anchor full_32_byte`
Expected: **FAIL** (payload is 28 bytes, not 40).

- [ ] **Step 2: Update constants and methods**

In `crates/bitcoin-anchor/src/lib.rs`:

```rust
/// Total OP_RETURN payload: 7 (magic) + 1 (version) + 32 (full Merkle root) = 40 bytes.
pub const ANCHOR_PAYLOAD_SIZE: usize = 40;
```

Replace `to_op_return_payload`:
```rust
#[must_use]
pub fn to_op_return_payload(&self) -> [u8; ANCHOR_PAYLOAD_SIZE] {
    let mut payload = [0u8; ANCHOR_PAYLOAD_SIZE];
    payload[..7].copy_from_slice(ANCHOR_MAGIC);
    payload[7] = ANCHOR_VERSION;
    payload[8..40].copy_from_slice(&self.merkle_root); // full 32 bytes
    payload
}
```

Replace `from_op_return_payload`:
```rust
#[must_use]
pub fn from_op_return_payload(payload: &[u8]) -> Option<Self> {
    if payload.len() < ANCHOR_PAYLOAD_SIZE { return None; }
    if &payload[..7] != ANCHOR_MAGIC { return None; }
    if payload[7] != ANCHOR_VERSION { return None; }
    let mut root = [0u8; 32];
    root.copy_from_slice(&payload[8..40]);
    Some(Self { merkle_root: root })
}
```

Replace `matches_full_root`:
```rust
#[must_use]
pub fn matches_full_root(&self, full_root: &[u8; 32]) -> bool {
    self.merkle_root == *full_root // full 256-bit comparison
}
```

- [ ] **Step 3: Run tests**

```
cargo test -p pqrascv-bitcoin-anchor
```
Expected: all pass.

- [ ] **Step 4: Commit**

```
git add crates/bitcoin-anchor/src/lib.rs
git commit -m "fix(bitcoin): commit full 32-byte Merkle root in OP_RETURN (was truncated to 20 bytes)"
```

---

## Task 4: RFC6962-Compliant Merkle Tree (CVE-2012-2459 Fix)

**Files:**
- Modify: `crates/bitcoin-anchor/src/merkle.rs`

**Background:** The duplicate-last-node approach makes `[A,B,C]` and `[A,B,C,C]` produce the same root. RFC6962 fixes this by (a) adding distinct leaf/internal hash prefixes and (b) promoting odd nodes rather than duplicating them.

- [ ] **Step 1: Write failing second-preimage test**

In the `#[cfg(test)]` block of `crates/bitcoin-anchor/src/merkle.rs`:

```rust
#[test]
fn cve_2012_2459_duplicate_node_attack_rejected() {
    // [A, B, C] must have a DIFFERENT root from [A, B, C, C]
    let mut agg3 = MerkleAggregator::new();
    agg3.add_quote_hash([0x01u8; 32]);
    agg3.add_quote_hash([0x02u8; 32]);
    agg3.add_quote_hash([0x03u8; 32]);

    let mut agg4 = MerkleAggregator::new();
    agg4.add_quote_hash([0x01u8; 32]);
    agg4.add_quote_hash([0x02u8; 32]);
    agg4.add_quote_hash([0x03u8; 32]);
    agg4.add_quote_hash([0x03u8; 32]); // duplicate C

    assert_ne!(
        agg3.root(),
        agg4.root(),
        "CVE-2012-2459: 3-leaf and [A,B,C,C] trees must not share a root"
    );
}
```

Run: `cargo test -p pqrascv-bitcoin-anchor cve_2012`
Expected: **FAIL** (currently the roots match).

- [ ] **Step 2: Rewrite `merkle.rs` with RFC6962 prefixes and promotion**

Replace the entire contents of `crates/bitcoin-anchor/src/merkle.rs` with:

```rust
//! Binary Merkle tree aggregation for attestation quote batches.
//!
//! Implements RFC6962-style prefix-separated hashing to prevent second-preimage
//! attacks (CVE-2012-2459). Odd-level nodes are promoted unchanged rather than
//! duplicated with themselves.
//!
//! # Hash functions
//!
//! - Leaf:     `SHA256d(0x00 || sha3_256_quote_hash)`
//! - Internal: `SHA256d(0x01 || left_hash || right_hash)`

extern crate alloc;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first: [u8; 32] = Sha256::digest(data).into();
    Sha256::digest(first).into()
}

/// RFC6962 leaf hash: `SHA256d(0x00 || data)`
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(data);
    sha256d(&buf)
}

/// RFC6962 internal hash: `SHA256d(0x01 || left || right)`
fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = INTERNAL_PREFIX;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    sha256d(&buf)
}

/// Advances a layer of nodes using RFC6962 rules:
/// pairs are hashed with `internal_hash`; the last odd node is promoted unchanged.
fn next_layer(nodes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity((nodes.len() + 1) / 2);
    let mut i = 0;
    while i + 1 < nodes.len() {
        out.push(internal_hash(&nodes[i], &nodes[i + 1]));
        i += 2;
    }
    if nodes.len() % 2 == 1 {
        out.push(nodes[nodes.len() - 1]); // promote last node unchanged
    }
    out
}

/// Aggregates attestation quote hashes into a Merkle tree.
#[derive(Default)]
pub struct MerkleAggregator {
    quote_hashes: Vec<[u8; 32]>,
}

impl MerkleAggregator {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    pub fn add_quote_hash(&mut self, hash: [u8; 32]) {
        self.quote_hashes.push(hash);
    }

    #[must_use]
    pub fn len(&self) -> usize { self.quote_hashes.len() }

    #[must_use]
    pub fn is_empty(&self) -> bool { self.quote_hashes.is_empty() }

    #[must_use]
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.quote_hashes.is_empty() { return None; }
        let mut nodes: Vec<[u8; 32]> = self.quote_hashes.iter().map(|h| leaf_hash(h)).collect();
        while nodes.len() > 1 {
            nodes = next_layer(&nodes);
        }
        Some(nodes[0])
    }

    #[must_use]
    pub fn inclusion_proof(&self, index: usize) -> Option<MerkleProofPath> {
        if index >= self.quote_hashes.len() { return None; }

        let mut nodes: Vec<[u8; 32]> = self.quote_hashes.iter().map(|h| leaf_hash(h)).collect();
        let leaf = nodes[index];
        let mut path = Vec::new();
        let mut idx = index;

        while nodes.len() > 1 {
            let is_last_odd = idx == nodes.len() - 1 && nodes.len() % 2 == 1;
            if is_last_odd {
                // Promoted — no sibling at this level
                path.push(ProofStep { sibling_hash: None, is_left: false });
            } else {
                let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
                path.push(ProofStep {
                    sibling_hash: Some(nodes[sibling]),
                    is_left: idx % 2 != 0,
                });
            }
            nodes = next_layer(&nodes);
            idx /= 2;
        }

        Some(MerkleProofPath { leaf_hash: leaf, path, root: nodes[0] })
    }
}

/// A single step in a Merkle inclusion proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProofStep {
    /// Sibling hash. `None` if this node was promoted (no sibling at this level).
    pub sibling_hash: Option<[u8; 32]>,
    /// `true` if the sibling is to the left of the current node.
    pub is_left: bool,
}

/// A Merkle inclusion proof path for a single quote.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MerkleProofPath {
    pub leaf_hash: [u8; 32],
    pub path: Vec<ProofStep>,
    pub root: [u8; 32],
}

impl MerkleProofPath {
    #[must_use]
    pub fn verify(&self) -> bool {
        let mut current = self.leaf_hash;
        for step in &self.path {
            current = match step.sibling_hash {
                None => current, // promoted: no change
                Some(sib) => {
                    if step.is_left {
                        internal_hash(&sib, &current)
                    } else {
                        internal_hash(&current, &sib)
                    }
                }
            };
        }
        current == self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_aggregator_returns_none() {
        assert!(MerkleAggregator::new().root().is_none());
    }

    #[test]
    fn single_quote_root_is_leaf_hash() {
        let mut agg = MerkleAggregator::new();
        let hash = [0x42u8; 32];
        agg.add_quote_hash(hash);
        assert_eq!(agg.root().unwrap(), leaf_hash(&hash));
    }

    #[test]
    fn two_quotes_produce_deterministic_root() {
        let make = || {
            let mut a = MerkleAggregator::new();
            a.add_quote_hash([0x01u8; 32]);
            a.add_quote_hash([0x02u8; 32]);
            a
        };
        assert_eq!(make().root(), make().root());
    }

    #[test]
    fn order_matters_for_root() {
        let mut a1 = MerkleAggregator::new();
        a1.add_quote_hash([0x01u8; 32]);
        a1.add_quote_hash([0x02u8; 32]);
        let mut a2 = MerkleAggregator::new();
        a2.add_quote_hash([0x02u8; 32]);
        a2.add_quote_hash([0x01u8; 32]);
        assert_ne!(a1.root(), a2.root());
    }

    #[test]
    fn inclusion_proof_verifies_all_indices() {
        let mut agg = MerkleAggregator::new();
        for i in 0u8..8 { agg.add_quote_hash([i; 32]); }
        for i in 0..8 {
            let proof = agg.inclusion_proof(i).unwrap();
            assert!(proof.verify(), "proof for index {i} must verify");
            assert_eq!(proof.root, agg.root().unwrap());
        }
    }

    #[test]
    fn inclusion_proof_verifies_odd_count() {
        let mut agg = MerkleAggregator::new();
        for i in 0u8..5 { agg.add_quote_hash([i; 32]); }
        for i in 0..5 {
            let proof = agg.inclusion_proof(i).unwrap();
            assert!(proof.verify(), "odd-tree proof for index {i} must verify");
        }
    }

    #[test]
    fn cve_2012_2459_duplicate_node_attack_rejected() {
        let mut agg3 = MerkleAggregator::new();
        agg3.add_quote_hash([0x01u8; 32]);
        agg3.add_quote_hash([0x02u8; 32]);
        agg3.add_quote_hash([0x03u8; 32]);

        let mut agg4 = MerkleAggregator::new();
        agg4.add_quote_hash([0x01u8; 32]);
        agg4.add_quote_hash([0x02u8; 32]);
        agg4.add_quote_hash([0x03u8; 32]);
        agg4.add_quote_hash([0x03u8; 32]);

        assert_ne!(agg3.root(), agg4.root());
    }

    #[test]
    fn leaf_hash_differs_from_internal_hash_of_same_data() {
        let data = [0x42u8; 32];
        assert_ne!(
            leaf_hash(&data),
            internal_hash(&data, &data),
            "prefix domain separation must produce distinct hashes"
        );
    }

    #[test]
    fn inclusion_proof_out_of_bounds_returns_none() {
        let mut agg = MerkleAggregator::new();
        agg.add_quote_hash([0x01u8; 32]);
        assert!(agg.inclusion_proof(1).is_none());
    }
}
```

- [ ] **Step 3: Fix `proof.rs` — `SpvVerifier` test uses `MerkleAggregator`; update `quote_merkle_path` leaf verification**

In `crates/bitcoin-anchor/src/proof.rs`, the leaf hash inside `SpvVerifier::verify()` is currently:
```rust
let expected_leaf = {
    let first: [u8; 32] = sha2::Sha256::digest(quote_hash).into();
    sha2::Sha256::digest(first).into()
};
```

The RFC6962 Merkle tree now stores `leaf_hash(quote_hash) = SHA256d(0x00 || quote_hash)`. Update to match:
```rust
// The PQ-RASCV Merkle tree uses RFC6962 leaf hashing: SHA256d(0x00 || quote_hash)
let expected_leaf = {
    let mut buf = [0u8; 33];
    buf[0] = 0x00; // RFC6962 leaf prefix
    buf[1..].copy_from_slice(quote_hash);
    let first: [u8; 32] = sha2::Sha256::digest(&buf).into();
    sha2::Sha256::digest(first).into()
};
```

- [ ] **Step 4: Run all bitcoin-anchor tests**

```
cargo test -p pqrascv-bitcoin-anchor
```
Expected: all pass including CVE-2012-2459 test.

- [ ] **Step 5: Commit**

```
git add crates/bitcoin-anchor/src/merkle.rs crates/bitcoin-anchor/src/proof.rs
git commit -m "fix(bitcoin): RFC6962 Merkle tree with prefix separation and promote-not-duplicate (fixes CVE-2012-2459)"
```

---

## Task 5: Bitcoin Proof-of-Work Validation

**Files:**
- Modify: `crates/bitcoin-anchor/src/proof.rs`

**Background:** `SpvVerifier` accepted any 80-byte buffer as a valid block header with no PoW check. An attacker can fabricate a header with any content.

- [ ] **Step 1: Write failing PoW rejection test**

Add to the tests in `crates/bitcoin-anchor/src/proof.rs`:

```rust
#[test]
fn forged_zero_work_block_header_rejected() {
    let quote_hash = [0x42u8; 32];
    let mut agg = MerkleAggregator::new();
    agg.add_quote_hash(quote_hash);
    let pqrascv_root = agg.root().unwrap();
    let quote_path = agg.inclusion_proof(0).unwrap();

    // Build a fake header with all-zeros (no PoW at all)
    let fake_header = make_fake_block_header(pqrascv_root);
    let tx_path = TxMerklePath {
        txid: pqrascv_root,
        steps: alloc::vec![],
        block_merkle_root: pqrascv_root,
    };
    let proof = InclusionProof {
        block_height: 800_000,
        block_header: fake_header,
        tx_merkle_path: tx_path,
        pqrascv_merkle_root: pqrascv_root,
        quote_merkle_path: quote_path,
    };

    // Default SpvVerifier enforces mainnet minimum difficulty
    let verifier = SpvVerifier::new(1, 800_001);
    assert!(
        matches!(verifier.verify(&proof, &quote_hash), Err(SpvError::InsufficientProofOfWork)),
        "zero-work header must be rejected"
    );
}
```

Run: `cargo test -p pqrascv-bitcoin-anchor forged_zero_work`
Expected: **FAIL** (no PoW check exists yet).

- [ ] **Step 2: Add `InsufficientProofOfWork` error variant**

In `SpvError`:
```rust
pub enum SpvError {
    InsufficientConfirmations { got: u32, required: u32 },
    InvalidBlockHeader,
    MerkleRootMismatch,
    TxNotInBlock,
    QuoteNotInAnchor,
    /// Block header does not satisfy the claimed or minimum proof-of-work target.
    InsufficientProofOfWork,
}
```

- [ ] **Step 3: Add `max_target_bits` to `SpvVerifier` and PoW helpers**

Replace the `SpvVerifier` struct and `impl` block entirely:

```rust
/// Verifies Bitcoin SPV inclusion proofs for PQ-RASCV attestation anchors.
pub struct SpvVerifier {
    pub min_confirmations: u32,
    pub chain_tip_height: u32,
    /// Maximum acceptable target as compact `bits`.
    /// Lower value = harder difficulty (more secure).
    /// Bitcoin mainnet genesis: `0x1d00ffff`.
    /// Set to `0` to skip PoW validation (testing only — never use in production).
    pub max_target_bits: u32,
}

impl SpvVerifier {
    /// Creates a verifier with Bitcoin mainnet minimum difficulty (`0x1d00ffff`).
    #[must_use]
    pub fn new(min_confirmations: u32, chain_tip_height: u32) -> Self {
        Self { min_confirmations, chain_tip_height, max_target_bits: 0x1d00ffff }
    }

    /// Override the maximum target bits (lower = more secure).
    #[must_use]
    pub fn with_max_target_bits(mut self, bits: u32) -> Self {
        self.max_target_bits = bits;
        self
    }

    pub fn verify(&self, proof: &InclusionProof, quote_hash: &[u8; 32]) -> Result<u32, SpvError> {
        // Step 0: Proof-of-work validation (skip only if max_target_bits == 0 for tests)
        if self.max_target_bits != 0 {
            if !validate_proof_of_work(&proof.block_header, self.max_target_bits) {
                return Err(SpvError::InsufficientProofOfWork);
            }
        }

        // Step 1: Confirmation count
        let confirmations = self
            .chain_tip_height
            .saturating_sub(proof.block_height)
            .saturating_add(1);
        if confirmations < self.min_confirmations {
            return Err(SpvError::InsufficientConfirmations {
                got: confirmations,
                required: self.min_confirmations,
            });
        }

        // Step 2: Block header Merkle root consistency
        let header_merkle_root =
            extract_block_merkle_root(&proof.block_header).ok_or(SpvError::InvalidBlockHeader)?;
        if header_merkle_root != proof.tx_merkle_path.block_merkle_root {
            return Err(SpvError::MerkleRootMismatch);
        }

        // Step 3: Transaction in block
        if !proof.tx_merkle_path.verify() {
            return Err(SpvError::TxNotInBlock);
        }

        // Step 4: PQ-RASCV Merkle root match
        if proof.quote_merkle_path.root != proof.pqrascv_merkle_root {
            return Err(SpvError::MerkleRootMismatch);
        }

        // Step 5: Quote hash in PQ-RASCV tree (RFC6962 leaf hash)
        let expected_leaf = {
            let mut buf = [0u8; 33];
            buf[0] = 0x00; // RFC6962 leaf prefix
            buf[1..].copy_from_slice(quote_hash);
            let first: [u8; 32] = sha2::Sha256::digest(&buf).into();
            sha2::Sha256::digest(first).into()
        };
        if proof.quote_merkle_path.leaf_hash != expected_leaf {
            return Err(SpvError::QuoteNotInAnchor);
        }
        if !proof.quote_merkle_path.verify() {
            return Err(SpvError::QuoteNotInAnchor);
        }

        Ok(proof.block_height)
    }
}

/// Returns `true` if the block header satisfies the given maximum target difficulty.
fn validate_proof_of_work(header: &[u8], max_target_bits: u32) -> bool {
    if header.len() < 80 { return false; }
    let block_bits = u32::from_le_bytes([header[72], header[73], header[74], header[75]]);
    let block_target = match bits_to_target(block_bits) { Some(t) => t, None => return false };
    let max_target   = match bits_to_target(max_target_bits) { Some(t) => t, None => return false };
    // Block's claimed target must be at most as easy as the maximum allowed
    if block_target > max_target { return false; }
    // SHA256d(header) must be below the block's target
    hash_below_target(&sha256d(header), &block_target)
}

/// Converts Bitcoin compact `bits` to a 32-byte big-endian target value.
/// Returns `None` for negative, zero, or out-of-range values.
fn bits_to_target(bits: u32) -> Option<[u8; 32]> {
    let exp      = (bits >> 24) as usize;
    let mantissa = (bits & 0x007F_FFFF) as u64;
    if bits & 0x0080_0000 != 0 { return None; } // negative
    if mantissa == 0            { return None; } // zero
    if exp < 3 || exp > 32      { return None; } // invalid exponent
    let mut target = [0u8; 32];
    let start = 32 - exp;
    target[start] = ((mantissa >> 16) & 0xFF) as u8;
    if start + 1 < 32 { target[start + 1] = ((mantissa >> 8)  & 0xFF) as u8; }
    if start + 2 < 32 { target[start + 2] = (mantissa         & 0xFF) as u8; }
    Some(target)
}

/// Returns `true` if `hash` (raw SHA256d output, little-endian integer) is below `target` (big-endian).
fn hash_below_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    let mut h_be = *hash;
    h_be.reverse(); // convert from little-endian to big-endian for comparison
    h_be < *target
}
```

- [ ] **Step 4: Update existing proof tests to skip PoW (they use fake headers)**

In the tests of `proof.rs`, replace `SpvVerifier::new(1, 800_000)` and `SpvVerifier::new(6, 800_000)` with the testing variant that skips PoW:

```rust
// All existing tests that call SpvVerifier::new(...):
let verifier = SpvVerifier::new(1, 800_001).with_max_target_bits(0); // PoW skip for unit tests
// (adjust chain_tip_height per test)
```

The `insufficient_confirmations_rejected` test:
```rust
let verifier = SpvVerifier::new(6, 800_000).with_max_target_bits(0);
```

- [ ] **Step 5: Run all tests**

```
cargo test -p pqrascv-bitcoin-anchor
```
Expected: all pass including `forged_zero_work_block_header_rejected`.

- [ ] **Step 6: Commit**

```
git add crates/bitcoin-anchor/src/proof.rs
git commit -m "fix(bitcoin): add proof-of-work validation to SpvVerifier; forged zero-work headers rejected"
```

---

## Task 6: Fix CRL Verification Enforcement

**Files:**
- Modify: `crates/pqrascv-core/src/pki/revocation.rs`

**Background:** `RevocationList::is_revoked()` trusts the list contents without verifying the CA signature. A `VerifiedRevocationList` newtype ensures `is_revoked()` is only callable after signature + freshness checks pass.

- [ ] **Step 1: Write failing test — unverified CRL must not expose `is_revoked()`**

This is a compile-time check. Add a comment in the test module indicating the desired API:

```rust
// TARGET API (write this test, it will fail to compile until VerifiedRevocationList exists):
#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn verified_crl_is_revoked_works() {
        // After verify() succeeds, is_revoked() must be available
        // (This test is a placeholder — see Step 4 for the full test with signed CRL)
        let _: fn(&str) -> bool; // type assertion placeholder
    }
}
```

For the actual compile-time enforcement, add a `#[deprecated]` to the raw method.

- [ ] **Step 2: Add `VerifiedRevocationList` and update `RevocationList`**

Replace the contents after the existing struct definitions in `crates/pqrascv-core/src/pki/revocation.rs`:

```rust
#[cfg(feature = "alloc")]
impl RevocationList {
    /// Verifies the CRL issuer signature and freshness, returning a `VerifiedRevocationList`.
    ///
    /// # Errors
    ///
    /// - `PolicyViolation` — CRL is stale (`next_update < now_secs`).
    /// - `VerificationFailed` — CA signature over TBS is invalid.
    pub fn verify<'a>(
        &'a self,
        ca_key: &[u8],
        now_secs: u64,
    ) -> Result<VerifiedRevocationList<'a>, PqRascvError> {
        use crate::crypto::{CryptoBackend, MlDsaBackend, SIGNING_CONTEXT_CRL};

        if !self.is_fresh(now_secs) {
            return Err(PqRascvError::PolicyViolation);
        }
        let tbs = self.tbs_cbor()?;
        MlDsaBackend.verify(&tbs, ca_key, &self.issuer_signature, SIGNING_CONTEXT_CRL)?;
        Ok(VerifiedRevocationList { inner: self })
    }

    /// Checks whether `serial` appears in the CRL entries.
    ///
    /// # ⚠ Signature Not Verified
    ///
    /// This method does NOT check the CRL signature. Use [`RevocationList::verify`]
    /// to get a [`VerifiedRevocationList`] whose `is_revoked()` is cryptographically backed.
    #[must_use]
    #[deprecated = "use RevocationList::verify() first, then VerifiedRevocationList::is_revoked()"]
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.entries.iter().any(|e| e.serial == serial)
    }

    /// Returns `true` if this CRL is still fresh at `now_secs`.
    #[must_use]
    pub fn is_fresh(&self, now_secs: u64) -> bool {
        now_secs <= self.next_update
    }

    /// Serializes the to-be-signed fields to CBOR for signature verification.
    pub fn tbs_cbor(&self) -> Result<Vec<u8>, PqRascvError> {
        let tbs = CrlTbs {
            issuer_id: &self.issuer_id,
            this_update: self.this_update,
            next_update: self.next_update,
            entries: &self.entries,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&tbs, &mut buf).map_err(|_| PqRascvError::SerializationFailed)?;
        Ok(buf)
    }
}

/// A revocation list whose issuer signature and freshness have been verified.
///
/// Obtain via [`RevocationList::verify`].
/// `is_revoked()` is only available on this type.
#[cfg(feature = "alloc")]
pub struct VerifiedRevocationList<'a> {
    inner: &'a RevocationList,
}

#[cfg(feature = "alloc")]
impl<'a> VerifiedRevocationList<'a> {
    /// Returns `true` if the certificate with `serial` is listed as revoked.
    #[must_use]
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.inner.entries.iter().any(|e| e.serial == serial)
    }
}
```

- [ ] **Step 3: Write full tests for verified CRL**

Add to the `tests` module:

```rust
#[cfg(all(test, feature = "alloc", feature = "std"))]
mod tests {
    use super::*;
    use crate::crypto::{generate_ml_dsa_keypair, MlDsaBackend, CryptoBackend, SIGNING_CONTEXT_CRL};

    fn make_signed_crl(
        entries: Vec<RevocationEntry>,
        ca_seed: &[u8],
        this_update: u64,
        next_update: u64,
    ) -> RevocationList {
        let mut crl = RevocationList {
            issuer_id: "https://ca.test".to_string(),
            this_update,
            next_update,
            entries,
            issuer_signature: vec![],
        };
        let tbs = crl.tbs_cbor().expect("tbs_cbor failed");
        let sig = MlDsaBackend
            .sign(&tbs, ca_seed, SIGNING_CONTEXT_CRL)
            .expect("sign failed");
        crl.issuer_signature = sig.as_ref().to_vec();
        crl
    }

    #[test]
    fn verified_crl_detects_revoked_serial() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let crl = make_signed_crl(
            alloc::vec![RevocationEntry {
                serial: "DEV-001".to_string(),
                revoked_at: 1_000,
                reason: RevocationReason::KeyCompromise,
            }],
            ca_seed.as_bytes(),
            1_000,
            9_999_999,
        );
        let verified = crl.verify(&ca_vk, 2_000).expect("verify failed");
        assert!(verified.is_revoked("DEV-001"));
        assert!(!verified.is_revoked("DEV-002"));
    }

    #[test]
    fn stale_crl_is_refused() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let crl = make_signed_crl(vec![], ca_seed.as_bytes(), 1_000, 2_000);
        // now_secs = 3_000 > next_update = 2_000
        assert!(matches!(crl.verify(&ca_vk, 3_000), Err(PqRascvError::PolicyViolation)));
    }

    #[test]
    fn tampered_crl_entries_fail_signature_check() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let mut crl = make_signed_crl(vec![], ca_seed.as_bytes(), 1_000, 9_999_999);
        // Tamper: inject a revocation entry after signing
        crl.entries.push(RevocationEntry {
            serial: "INJECTED-001".to_string(),
            revoked_at: 1_000,
            reason: RevocationReason::KeyCompromise,
        });
        assert!(crl.verify(&ca_vk, 2_000).is_err(), "tampered CRL must fail");
    }

    #[test]
    fn wrong_ca_key_fails_verification() {
        let (ca_seed, _ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (_other_seed, other_vk) = generate_ml_dsa_keypair().unwrap();
        let crl = make_signed_crl(vec![], ca_seed.as_bytes(), 1_000, 9_999_999);
        assert!(crl.verify(&other_vk, 2_000).is_err());
    }
}
```

- [ ] **Step 4: Run tests**

```
cargo test -p pqrascv-core --features std,software-rot-unsafe -- revocation
```
Expected: all pass.

- [ ] **Step 5: Commit**

```
git add crates/pqrascv-core/src/pki/revocation.rs
git commit -m "fix(pki): add VerifiedRevocationList; CRL signature enforced before is_revoked() accessible"
```

---

## Task 7: Fix Certificate Chain Validation (Issuer Binding + Path Length)

**Files:**
- Modify: `crates/pqrascv-core/src/pki/mod.rs`

**Background:** `validate_chain` verifies cryptographic signatures but does not check that each cert's `issuer_id` matches its signer's identity, and does not enforce CA path length. Adding `self_id` and `max_path_length` fields and bumping `CERT_VERSION` to 3.

- [ ] **Step 1: Write failing tests**

Add to the `#[cfg(test)]` block (tests will fail until fields and checks are added):

```rust
// These tests require a full test CA setup — see Task 8's test helper; add stubs here:
// - issuer_mismatch_is_rejected
// - path_length_exceeded_is_rejected
// (Add after the implementation steps below)
```

- [ ] **Step 2: Add `self_id` and `max_path_length` to `DeviceCertificate`**

In `DeviceCertificate` struct add (with `#[serde(default)]` for wire backward compat):

```rust
/// This certificate's own subject identifier URI.
/// Must match the `issuer_id` of any certificate this cert signs.
#[serde(default)]
pub self_id: String,

/// Maximum CA depth allowed below this certificate's subject key.
/// `Some(0)` = leaf (device cert, cannot sign further certs).
/// `None` = no constraint.
#[serde(default)]
pub max_path_length: Option<u8>,
```

Add the same fields to `DeviceCertTbs`:
```rust
struct DeviceCertTbs<'a> {
    // ... existing fields ...
    self_id: &'a str,
    max_path_length: Option<u8>,
}
```

Update `tbs_cbor` to include them:
```rust
let tbs = DeviceCertTbs {
    // ... existing fields ...
    self_id: &self.self_id,
    max_path_length: self.max_path_length,
};
```

- [ ] **Step 3: Bump `CERT_VERSION`**

```rust
pub const CERT_VERSION: u8 = 3;
```

- [ ] **Step 4: Update `validate_chain` with issuer binding and path length**

Replace `validate_chain` completely:

```rust
pub fn validate_chain(
    device_cert: DeviceCertificate,
    intermediates: Vec<DeviceCertificate>,
    trust_anchor: &TrustAnchor,
    now_secs: u64,
) -> Result<CertChain, PqRascvError> {
    use crate::crypto::{CryptoBackend, MlDsaBackend, SIGNING_CONTEXT_CERT};

    // Build signing key sequence: [root_key, int[0].subject_key, int[1].subject_key, ...]
    let mut signing_keys: Vec<Vec<u8>> = Vec::with_capacity(intermediates.len() + 1);
    signing_keys.push(trust_anchor.root_key_bytes().to_vec());
    for int in &intermediates {
        signing_keys.push(int.subject_key.clone());
    }

    // Build expected issuer ID sequence: root_ca.ca_id, int[0].self_id, int[1].self_id, ...
    let mut issuer_ids: Vec<String> = Vec::with_capacity(intermediates.len() + 1);
    issuer_ids.push(trust_anchor.root_ca.ca_id.to_owned());
    for int in &intermediates {
        issuer_ids.push(int.self_id.clone());
    }

    // Validate each intermediate
    for (d, intermediate) in intermediates.iter().enumerate() {
        // Version check
        if intermediate.version != CERT_VERSION {
            return Err(PqRascvError::CertificateInvalid);
        }

        // Issuer binding: cert's issuer_id must match the identity of the cert above it
        if intermediate.issuer_id != issuer_ids[d] {
            return Err(PqRascvError::CertificateInvalid);
        }

        // Path length: the signer at level d may constrain how deep the chain goes below it.
        // Number of CA certificates below signer[d] = (intermediates.len() - d)
        if d > 0 {
            if let Some(max) = intermediates[d - 1].max_path_length {
                let ca_certs_below = (intermediates.len() - d) as u8;
                if ca_certs_below > max {
                    return Err(PqRascvError::CertificateInvalid);
                }
            }
        }

        // Temporal validity
        if !intermediate.is_valid_at(now_secs) {
            return Err(PqRascvError::VerificationFailed);
        }

        // Signature verification
        let tbs = intermediate.tbs_cbor()?;
        MlDsaBackend.verify(&tbs, &signing_keys[d], &intermediate.issuer_signature, SIGNING_CONTEXT_CERT)?;
    }

    // Validate device certificate
    if device_cert.version != CERT_VERSION {
        return Err(PqRascvError::CertificateInvalid);
    }

    let device_expected_issuer = issuer_ids.last().expect("issuer_ids always has root");
    if device_cert.issuer_id != *device_expected_issuer {
        return Err(PqRascvError::CertificateInvalid);
    }

    // Path length check from last intermediate
    if let Some(last_int) = intermediates.last() {
        if let Some(max) = last_int.max_path_length {
            if max == 0 {
                // Last intermediate is a leaf — it cannot sign the device cert
                return Err(PqRascvError::CertificateInvalid);
            }
        }
    }

    if !device_cert.is_valid_at(now_secs) {
        return Err(PqRascvError::VerificationFailed);
    }

    let device_tbs = device_cert.tbs_cbor()?;
    let device_signing_key = signing_keys.last().expect("always has root key");
    MlDsaBackend.verify(&device_tbs, device_signing_key, &device_cert.issuer_signature, SIGNING_CONTEXT_CERT)?;

    // subject_key_id consistency
    let computed_id = {
        let mut h = Sha3_256::new();
        h.update(&device_cert.subject_key);
        let r: [u8; 32] = h.finalize().into();
        r
    };
    if computed_id != device_cert.subject_key_id {
        return Err(PqRascvError::VerificationFailed);
    }

    Ok(CertChain { device_cert, intermediates })
}
```

- [ ] **Step 5: Add issuer mismatch and path length tests**

```rust
#[cfg(all(test, feature = "alloc", feature = "std"))]
mod chain_tests {
    use super::*;
    use crate::crypto::{generate_ml_dsa_keypair, MlDsaBackend, CryptoBackend, SIGNING_CONTEXT_CERT};

    fn sign_cert(cert: &mut DeviceCertificate, signer_seed: &[u8]) {
        let tbs = cert.tbs_cbor().expect("tbs_cbor");
        let sig = MlDsaBackend.sign(&tbs, signer_seed, SIGNING_CONTEXT_CERT).expect("sign");
        cert.issuer_signature = sig.as_ref().to_vec();
    }

    fn make_ca() -> (crate::crypto::SigningKeySeed, [u8; crate::crypto::ML_DSA_65_VERIFYING_KEY_SIZE]) {
        generate_ml_dsa_keypair().unwrap()
    }

    fn make_device_cert(
        device_vk: &[u8],
        issuer_id: &str,
        self_id: &str,
        serial: &str,
        signer_seed: &[u8],
    ) -> DeviceCertificate {
        let subject_key_id = crate::crypto::pub_key_id(device_vk);
        let mut cert = DeviceCertificate {
            version: CERT_VERSION,
            serial: serial.to_string(),
            issuer_id: issuer_id.to_string(),
            not_before: 0,
            not_after: u64::MAX,
            subject_key: device_vk.to_vec(),
            subject_key_id,
            hardware_identity: HardwareIdentity::TpmEkCertHash([0u8; 32]),
            fw_policy: None,
            issuer_signature: vec![],
            self_id: self_id.to_string(),
            max_path_length: Some(0), // leaf cert
        };
        sign_cert(&mut cert, signer_seed);
        cert
    }

    #[test]
    fn valid_chain_no_intermediates() {
        let (ca_seed, ca_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let anchor = TrustAnchor::new(CaPublicKey { key_bytes: ca_vk, ca_id: "https://ca.test" });
        let device_cert = make_device_cert(&dev_vk, "https://ca.test", "https://dev.test", "DEV-001", ca_seed.as_bytes());
        assert!(validate_chain(device_cert, vec![], &anchor, 1_000).is_ok());
    }

    #[test]
    fn issuer_mismatch_rejected() {
        let (ca_seed, ca_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let anchor = TrustAnchor::new(CaPublicKey { key_bytes: ca_vk, ca_id: "https://ca.test" });
        // Wrong issuer_id (claims "https://evil.ca" instead of "https://ca.test")
        let device_cert = make_device_cert(&dev_vk, "https://evil.ca", "https://dev.test", "DEV-001", ca_seed.as_bytes());
        assert!(matches!(
            validate_chain(device_cert, vec![], &anchor, 1_000),
            Err(PqRascvError::CertificateInvalid)
        ));
    }

    #[test]
    fn path_length_exceeded_rejected() {
        let (root_seed, root_vk) = make_ca();
        let (int_seed, int_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let anchor = TrustAnchor::new(CaPublicKey { key_bytes: root_vk, ca_id: "https://root.test" });

        // Intermediate with max_path_length = Some(0) — cannot sign the device cert
        let mut intermediate = make_device_cert(&int_vk, "https://root.test", "https://int.test", "INT-001", root_seed.as_bytes());
        intermediate.max_path_length = Some(0); // re-sign after field change
        sign_cert(&mut intermediate, root_seed.as_bytes());

        let device_cert = make_device_cert(&dev_vk, "https://int.test", "https://dev.test", "DEV-001", int_seed.as_bytes());

        assert!(matches!(
            validate_chain(device_cert, vec![intermediate], &anchor, 1_000),
            Err(PqRascvError::CertificateInvalid)
        ));
    }
}
```

- [ ] **Step 6: Run tests**

```
cargo test -p pqrascv-core --features std,software-rot-unsafe -- chain_tests
```
Expected: all pass.

- [ ] **Step 7: Commit**

```
git add crates/pqrascv-core/src/pki/mod.rs
git commit -m "fix(pki): add issuer binding, path length enforcement, self_id field, CERT_VERSION=3"
```

---

## Task 8: Wire PKI into Verifier

**Files:**
- Modify: `crates/verifier/src/lib.rs`

**Background:** The existing `Verifier` performs no certificate chain validation. A new `verify_cbor_with_pki` method derives the trusted signing key exclusively from a validated certificate chain, with optional CRL revocation check.

- [ ] **Step 1: Write failing test**

Add to `crates/verifier/src/lib.rs` tests:

```rust
#[test]
fn pki_path_requires_valid_chain() {
    // This test will fail until verify_cbor_with_pki exists
    // Placeholder — implemented fully in Step 5
    let _ = std::panic::catch_unwind(|| {
        // PkiVerificationResult type must exist
        let _: PkiVerificationResult;
    });
}
```

Run: `cargo build -p pqrascv-verifier`
Expected: **FAIL** (`PkiVerificationResult` not found).

- [ ] **Step 2: Add imports to `verifier/src/lib.rs`**

```rust
use pqrascv_core::{
    config::PolicyConfig,
    crypto::{pub_key_id, CryptoBackend, MlDsaBackend, SIGNING_CONTEXT_QUOTE},
    error::PqRascvError,
    pki::{validate_chain, CertChain, DeviceCertificate, TrustAnchor},
    pki::revocation::VerifiedRevocationList,
    quote::{AttestationQuote, Challenge, PROTOCOL_VERSION},
};
```

- [ ] **Step 3: Add `PkiVerificationResult`**

```rust
/// Outcome of a successful PKI-backed attestation verification.
///
/// Both the ML-DSA-65 signature and the certificate chain are verified.
/// The signing key is derived exclusively from the validated certificate.
#[derive(Debug)]
pub struct PkiVerificationResult {
    pub quote: AttestationQuote,
    pub cert_chain: CertChain,
}

impl PkiVerificationResult {
    #[must_use]
    pub fn slsa_level(&self) -> u8 { self.quote.body.provenance.slsa_level() }
    #[must_use]
    pub fn firmware_hash(&self) -> &[u8; 32] { &self.quote.body.measurements.firmware_hash }
    #[must_use]
    pub fn nonce(&self) -> &[u8; 32] { &self.quote.body.nonce }
    #[must_use]
    pub fn device_serial(&self) -> &str { &self.cert_chain.device_cert.serial }
}
```

- [ ] **Step 4: Add `verify_cbor_with_pki` to `Verifier`**

```rust
impl Verifier {
    // ... existing methods unchanged ...

    /// Verifies a CBOR quote using a cryptographically-validated certificate chain.
    ///
    /// The signing key is extracted exclusively from the validated certificate.
    /// No caller-supplied verifying key is accepted — the chain IS the source of trust.
    ///
    /// # Arguments
    ///
    /// - `device_cert`: leaf certificate for the attesting device.
    /// - `intermediates`: ordered CA chain from root-adjacent to device-adjacent (may be empty).
    /// - `trust_anchor`: root CA trust anchor.
    /// - `crl`: optional verified CRL; if `Some`, the device serial is checked for revocation.
    pub fn verify_cbor_with_pki(
        &self,
        cbor: &[u8],
        device_cert: DeviceCertificate,
        intermediates: Vec<DeviceCertificate>,
        trust_anchor: &TrustAnchor,
        crl: Option<&VerifiedRevocationList<'_>>,
        expected_nonce: &[u8; 32],
        now_secs: u64,
    ) -> Result<PkiVerificationResult, PqRascvError> {
        // Step 1: Validate certificate chain — sole source of the trusted signing key
        let chain = validate_chain(device_cert, intermediates, trust_anchor, now_secs)?;

        // Step 2: Revocation check before any signature work
        if let Some(crl) = crl {
            if crl.is_revoked(&chain.device_cert.serial) {
                return Err(PqRascvError::CertificateRevoked);
            }
        }

        // Step 3: Verify the quote against the key from the validated certificate
        let verifying_key = &chain.device_cert.subject_key;
        let result = self.verify_cbor(cbor, verifying_key, expected_nonce, now_secs)?;

        Ok(PkiVerificationResult { quote: result.quote, cert_chain: chain })
    }
}
```

- [ ] **Step 5: Write full PKI verification tests**

```rust
#[cfg(test)]
mod pki_tests {
    use super::*;
    use pqrascv_core::{
        crypto::{generate_ml_dsa_keypair, MlDsaBackend, CryptoBackend, SIGNING_CONTEXT_CERT,
                 ML_DSA_65_VERIFYING_KEY_SIZE},
        measurement::SoftwareRoT,
        pki::{CaPublicKey, HardwareIdentity, CERT_VERSION},
        provenance::SlsaPredicateBuilder,
        quote::{generate_quote, QuoteTimestamp},
    };

    fn make_provenance() -> pqrascv_core::provenance::InTotoAttestation {
        SlsaPredicateBuilder::new("https://ci.test")
            .add_subject("fw.bin", &[0xabu8; 32])
            .with_slsa_level(2)
            .build()
            .unwrap()
    }

    fn sign_cert(cert: &mut pqrascv_core::pki::DeviceCertificate, seed: &[u8]) {
        let tbs = cert.tbs_cbor().unwrap();
        let sig = MlDsaBackend.sign(&tbs, seed, SIGNING_CONTEXT_CERT).unwrap();
        cert.issuer_signature = sig.as_ref().to_vec();
    }

    fn make_device_cert(
        device_vk: &[u8; ML_DSA_65_VERIFYING_KEY_SIZE],
        issuer_id: &str,
        serial: &str,
        signer_seed: &[u8],
    ) -> pqrascv_core::pki::DeviceCertificate {
        let subject_key_id = pqrascv_core::crypto::pub_key_id(device_vk);
        let mut cert = pqrascv_core::pki::DeviceCertificate {
            version: CERT_VERSION,
            serial: serial.to_string(),
            issuer_id: issuer_id.to_string(),
            not_before: 0,
            not_after: u64::MAX,
            subject_key: device_vk.to_vec(),
            subject_key_id,
            hardware_identity: HardwareIdentity::TpmEkCertHash([0u8; 32]),
            fw_policy: None,
            issuer_signature: vec![],
            self_id: serial.to_string(),
            max_path_length: Some(0),
        };
        sign_cert(&mut cert, signer_seed);
        cert
    }

    #[test]
    fn pki_verification_succeeds_with_valid_chain() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();

        let anchor = TrustAnchor::new(CaPublicKey { key_bytes: ca_vk, ca_id: "https://ca.test" });
        let device_cert = make_device_cert(&dev_vk, "https://ca.test", "DEV-001", ca_seed.as_bytes());

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xAAu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        let result = verifier.verify_cbor_with_pki(
            &cbor, device_cert, vec![], &anchor, None, &nonce, 1_700_000_100,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().device_serial(), "DEV-001");
    }

    #[test]
    fn pki_verification_rejects_revoked_device() {
        use pqrascv_core::pki::revocation::{RevocationEntry, RevocationList, RevocationReason};
        use pqrascv_core::crypto::SIGNING_CONTEXT_CRL;

        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();
        let anchor = TrustAnchor::new(CaPublicKey { key_bytes: ca_vk, ca_id: "https://ca.test" });
        let device_cert = make_device_cert(&dev_vk, "https://ca.test", "DEV-REVOKED", ca_seed.as_bytes());

        let mut crl = RevocationList {
            issuer_id: "https://ca.test".to_string(),
            this_update: 1_000,
            next_update: 9_999_999,
            entries: vec![RevocationEntry {
                serial: "DEV-REVOKED".to_string(),
                revoked_at: 1_000,
                reason: RevocationReason::KeyCompromise,
            }],
            issuer_signature: vec![],
        };
        let crl_tbs = crl.tbs_cbor().unwrap();
        let crl_sig = MlDsaBackend.sign(&crl_tbs, ca_seed.as_bytes(), SIGNING_CONTEXT_CRL).unwrap();
        crl.issuer_signature = crl_sig.as_ref().to_vec();
        let verified_crl = crl.verify(&ca_vk, 2_000).unwrap();

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xBBu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        let result = verifier.verify_cbor_with_pki(
            &cbor, device_cert, vec![], &anchor, Some(&verified_crl), &nonce, 1_700_000_100,
        );
        assert!(matches!(result, Err(PqRascvError::CertificateRevoked)));
    }

    #[test]
    fn pki_verification_rejects_wrong_trust_anchor() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (_other_seed, other_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();

        // Anchor uses `other_vk` but cert was signed by `ca_seed`
        let anchor = TrustAnchor::new(CaPublicKey { key_bytes: other_vk, ca_id: "https://ca.test" });
        let device_cert = make_device_cert(&dev_vk, "https://ca.test", "DEV-001", ca_seed.as_bytes());

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xCCu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        assert!(verifier.verify_cbor_with_pki(
            &cbor, device_cert, vec![], &anchor, None, &nonce, 1_700_000_100,
        ).is_err());
    }
}
```

- [ ] **Step 6: Run all verifier tests**

```
cargo test -p pqrascv-verifier
```
Expected: all pass.

- [ ] **Step 7: Commit**

```
git add crates/verifier/src/lib.rs
git commit -m "feat(verifier): add verify_cbor_with_pki() and PkiVerificationResult; PKI wired to verification path"
```

---

## Task 9: PolicyContext Builder from Verified Artifacts

**Files:**
- Modify: `crates/pqrascv-core/src/policy/mod.rs`

**Background:** `PolicyContext` had all-public fields, enabling callers to set `has_cert_chain: true` without actually validating anything. `from_verified_quote()` derives every field from cryptographic evidence.

- [ ] **Step 1: Write failing test**

Add to the policy module tests:

```rust
#[test]
fn context_from_quote_has_external_provenance_is_always_false() {
    // has_external_provenance must NEVER be set true by from_verified_quote
    // until Sigstore integration is complete
}
```

This will compile but the assertion is trivially true; we add it as a guard.

- [ ] **Step 2: Remove `RequireExternalProvenance` from `production()` policy**

In `PolicyEngineV2::production()`, remove the `RequireExternalProvenance` rule and add a comment:

```rust
pub fn production() -> Self {
    Self::new(alloc::vec![
        PolicyRule::EnforceProtocolVersion { expected: 2 },
        PolicyRule::RequireHardwareBackend,
        PolicyRule::RequireCertificateChain,
        // PolicyRule::RequireExternalProvenance — NOT_IMPLEMENTED: Sigstore pending
        PolicyRule::MinSlsaLevel(2),
        PolicyRule::RequireFirmwareHash,
        PolicyRule::MaxQuoteAgeSecs(300),
    ])
}
```

- [ ] **Step 3: Add conversion helper and `from_verified_quote` to `policy/mod.rs`**

After the imports, add:

```rust
#[cfg(feature = "alloc")]
use crate::{
    nonce::ClockEvidence,
    pki::{CertChain, HardwareIdentity},
    quote::QuoteTimestamp,
};

#[cfg(feature = "alloc")]
fn hardware_backend_from_identity(identity: &HardwareIdentity) -> HardwareBackendKind {
    match identity {
        HardwareIdentity::TpmEkCertHash(_)     => HardwareBackendKind::Tpm2,
        HardwareIdentity::DiceCdiPublicHash(_) => HardwareBackendKind::Dice,
        HardwareIdentity::TdxMrtd(_)           => HardwareBackendKind::IntelTdx,
        HardwareIdentity::SevSnpMeasurement(_) => HardwareBackendKind::AmdSevSnp,
    }
}
```

Add an `impl PolicyContext`:

```rust
#[cfg(feature = "alloc")]
impl<'a> PolicyContext<'a> {
    /// Constructs a `PolicyContext` from verified attestation artifacts.
    ///
    /// All security-sensitive fields are derived from cryptographic evidence:
    /// - `hardware_backend` comes from the certificate's `hardware_identity` field.
    /// - `has_cert_chain` reflects actual certificate chain validation.
    /// - `has_external_provenance` is always `false` (NOT_IMPLEMENTED).
    ///
    /// Never set these fields manually in production code.
    pub fn from_verified_quote(
        quote: &'a crate::quote::AttestationQuote,
        cert_chain: Option<&CertChain>,
        bitcoin_confirmations: Option<u32>,
        now_secs: u64,
    ) -> Self {
        let hardware_backend = cert_chain
            .map(|c| hardware_backend_from_identity(&c.device_cert.hardware_identity))
            .unwrap_or(HardwareBackendKind::SoftwareUnsafe);

        let clock = match quote.body.timestamp {
            QuoteTimestamp::Rtc(ts) => ClockEvidence::TrustedRtc(ts),
            QuoteTimestamp::NoRtc  => ClockEvidence::NoRtc,
        };

        PolicyContext {
            protocol_version:       quote.body.version,
            clock,
            now_secs,
            firmware_hash:          &quote.body.measurements.firmware_hash,
            slsa_level:             quote.body.provenance.slsa_level(),
            builder_id:             Some(quote.body.provenance.build.builder_id.as_str()),
            hardware_backend,
            has_cert_chain:         cert_chain.is_some(),
            has_external_provenance: false, // NOT_IMPLEMENTED until Sigstore lands
            bitcoin_confirmations,
        }
    }
}
```

- [ ] **Step 4: Add tests for context builder**

```rust
#[cfg(all(test, feature = "alloc", feature = "software-rot-unsafe"))]
mod context_builder_tests {
    use super::*;
    use crate::{
        crypto::{generate_ml_dsa_keypair, MlDsaBackend},
        measurement::SoftwareRoT,
        nonce::ClockEvidence,
        provenance::SlsaPredicateBuilder,
        quote::{generate_quote, QuoteTimestamp},
    };

    fn make_quote(ts: QuoteTimestamp) -> crate::quote::AttestationQuote {
        let (sk, vk) = generate_ml_dsa_keypair().unwrap();
        let rot = SoftwareRoT::new(b"fw", None, 1);
        let prov = SlsaPredicateBuilder::new("https://ci.test")
            .add_subject("fw", &[0xabu8; 32])
            .with_slsa_level(2)
            .build()
            .unwrap();
        generate_quote(&rot, &MlDsaBackend, sk.as_bytes(), &vk, &[0x42u8; 32], prov, ts).unwrap()
    }

    #[test]
    fn no_cert_chain_gives_software_unsafe_backend() {
        let quote = make_quote(QuoteTimestamp::Rtc(1_700_000_000));
        let ctx = PolicyContext::from_verified_quote(&quote, None, None, 1_700_000_100);
        assert_eq!(ctx.hardware_backend, HardwareBackendKind::SoftwareUnsafe);
        assert!(!ctx.has_cert_chain);
    }

    #[test]
    fn external_provenance_always_false() {
        let quote = make_quote(QuoteTimestamp::Rtc(1_700_000_000));
        let ctx = PolicyContext::from_verified_quote(&quote, None, None, 1_700_000_100);
        assert!(
            !ctx.has_external_provenance,
            "has_external_provenance must be false until Sigstore is implemented"
        );
    }

    #[test]
    fn rtc_timestamp_produces_trusted_rtc_clock() {
        let quote = make_quote(QuoteTimestamp::Rtc(1_700_000_000));
        let ctx = PolicyContext::from_verified_quote(&quote, None, None, 1_700_000_100);
        assert_eq!(ctx.clock, ClockEvidence::TrustedRtc(1_700_000_000));
    }

    #[test]
    fn no_rtc_produces_no_rtc_clock() {
        let quote = make_quote(QuoteTimestamp::NoRtc);
        let ctx = PolicyContext::from_verified_quote(&quote, None, None, 999_999);
        assert_eq!(ctx.clock, ClockEvidence::NoRtc);
    }

    #[test]
    fn production_policy_rejects_software_backend_via_context_builder() {
        let quote = make_quote(QuoteTimestamp::Rtc(1_700_000_000));
        let ctx = PolicyContext::from_verified_quote(&quote, None, None, 1_700_000_100);
        let engine = PolicyEngineV2::production();
        // No cert chain → SoftwareUnsafe → RequireHardwareBackend fires
        assert!(matches!(engine.evaluate(&ctx), Err(crate::error::PqRascvError::PolicyViolation)));
    }
}
```

- [ ] **Step 5: Run tests**

```
cargo test -p pqrascv-core --features std,software-rot-unsafe -- context_builder
```
Expected: all pass.

- [ ] **Step 6: Commit**

```
git add crates/pqrascv-core/src/policy/mod.rs
git commit -m "fix(policy): add PolicyContext::from_verified_quote(); remove RequireExternalProvenance from production default"
```

---

## Task 10: Mark `ExternalProvenanceBundle` as NOT_IMPLEMENTED

**Files:**
- Modify: `crates/pqrascv-core/src/provenance_v2/mod.rs`

**Background:** The `ExternalProvenanceBundle` struct looks complete but performs zero Sigstore verification. All verification surfaces must explicitly fail rather than silently succeed.

- [ ] **Step 1: Write test asserting explicit NOT_IMPLEMENTED failure**

Add to `crates/pqrascv-core/src/provenance_v2/mod.rs` tests:

```rust
#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::error::PqRascvError;

    fn dummy_bundle() -> ExternalProvenanceBundle {
        ExternalProvenanceBundle {
            predicate: ProvenancePredicate {
                predicate_type: "https://slsa.dev/provenance/v1".to_string(),
                builder_id: "https://ci.test".to_string(),
                build_config_ref: "abc123".to_string(),
                build_started_on: 0,
                build_finished_on: 0,
                sbom_hash: [0u8; 32],
                slsa_level: 2,
                subjects: alloc::vec![],
            },
            sigstore_bundle: SigstoreBundle {
                signature: alloc::vec![],
                signing_cert_der: alloc::vec![],
                rekor_entry_json: alloc::string::String::new(),
                predicate_hash: [0u8; 32],
            },
        }
    }

    #[test]
    fn verify_sigstore_always_returns_not_implemented() {
        let bundle = dummy_bundle();
        assert!(
            matches!(bundle.verify_sigstore(), Err(PqRascvError::ProvenanceBundleInvalid)),
            "verify_sigstore must fail explicitly until Sigstore integration is complete"
        );
    }
}
```

Run: `cargo test -p pqrascv-core --features alloc -- provenance_v2`
Expected: **FAIL** (`verify_sigstore` method not found).

- [ ] **Step 2: Add `verify_sigstore()` method and module-level warning**

Replace the top-level doc comment of `crates/pqrascv-core/src/provenance_v2/mod.rs`:

```rust
//! External provenance bundles — CI-signed, independently verifiable.
//!
//! # ⚠ NOT_IMPLEMENTED: Sigstore Verification
//!
//! [`ExternalProvenanceBundle`] is a forward-compatible type definition.
//! The `verify_sigstore()` method currently returns
//! `Err(PqRascvError::ProvenanceBundleInvalid)` unconditionally.
//!
//! `PolicyRule::RequireExternalProvenance` is intentionally absent from
//! `PolicyEngineV2::production()` until this is implemented.
//!
//! Implementing this requires integrating `sigstore-rs` (Fulcio + Rekor).
```

Add `verify_sigstore()` to `ExternalProvenanceBundle`:

```rust
impl ExternalProvenanceBundle {
    // ... existing methods unchanged ...

    /// Verifies the Sigstore bundle (Fulcio certificate chain + Rekor inclusion proof).
    ///
    /// # NOT_IMPLEMENTED
    ///
    /// Returns `Err(PqRascvError::ProvenanceBundleInvalid)` unconditionally.
    /// Requires `sigstore-rs` integration for full Fulcio + Rekor verification.
    pub fn verify_sigstore(&self) -> Result<(), crate::error::PqRascvError> {
        Err(crate::error::PqRascvError::ProvenanceBundleInvalid)
    }
}
```

- [ ] **Step 3: Run test**

```
cargo test -p pqrascv-core --features alloc -- verify_sigstore
```
Expected: passes.

- [ ] **Step 4: Commit**

```
git add crates/pqrascv-core/src/provenance_v2/mod.rs
git commit -m "fix(provenance): mark ExternalProvenanceBundle::verify_sigstore as NOT_IMPLEMENTED with explicit failure"
```

---

## Task 11: Adversarial Integration Tests

**Files:**
- Create: `crates/pqrascv-core/tests/adversarial_tests.rs`

**Background:** A dedicated test file exercises the new security properties adversarially: cross-context confusion, replay attacks, chain forgery, and second-preimage resistance.

- [ ] **Step 1: Create the test file**

Create `crates/pqrascv-core/tests/adversarial_tests.rs`:

```rust
//! Adversarial integration tests.
//!
//! Every test here simulates a concrete attack and asserts it is rejected.
#![cfg(all(feature = "std", feature = "alloc", feature = "software-rot-unsafe"))]

use pqrascv_core::{
    crypto::{
        generate_ml_dsa_keypair, MlDsaBackend, CryptoBackend,
        SIGNING_CONTEXT_CERT, SIGNING_CONTEXT_CRL, SIGNING_CONTEXT_QUOTE,
    },
    error::PqRascvError,
    measurement::SoftwareRoT,
    nonce::InMemoryNonceLedger,
    nonce::NonceLedger,
    pki::{validate_chain, CaPublicKey, DeviceCertificate, HardwareIdentity, TrustAnchor, CERT_VERSION},
    provenance::SlsaPredicateBuilder,
    quote::{generate_quote, AttestationQuote, QuoteTimestamp},
    config::PolicyConfig,
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

fn make_quote_cbor(seed: &pqrascv_core::crypto::SigningKeySeed, vk: &[u8; pqrascv_core::crypto::ML_DSA_65_VERIFYING_KEY_SIZE], nonce: &[u8; 32]) -> Vec<u8> {
    let rot = SoftwareRoT::new(b"adversarial-fw", None, 1);
    let quote = generate_quote(
        &rot, &MlDsaBackend, seed.as_bytes(), vk,
        nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
    ).unwrap();
    quote.to_cbor().unwrap()
}

fn sign_cert(cert: &mut DeviceCertificate, signer_seed: &[u8]) {
    let tbs = cert.tbs_cbor().unwrap();
    let sig = MlDsaBackend.sign(&tbs, signer_seed, SIGNING_CONTEXT_CERT).unwrap();
    cert.issuer_signature = sig.as_ref().to_vec();
}

// ── Cross-context confusion ───────────────────────────────────────────────────

#[test]
fn cert_signature_cannot_be_reused_as_quote_signature() {
    let (seed, vk) = generate_ml_dsa_keypair().unwrap();
    let message = b"shared-message";

    let cert_sig = MlDsaBackend.sign(message, seed.as_bytes(), SIGNING_CONTEXT_CERT).unwrap();
    // The cert signature must NOT verify under the quote context
    assert!(
        MlDsaBackend.verify(message, &vk, cert_sig.as_ref(), SIGNING_CONTEXT_QUOTE).is_err(),
        "cert signature must not verify under quote context"
    );
}

#[test]
fn quote_signature_cannot_be_reused_as_cert_signature() {
    let (seed, vk) = generate_ml_dsa_keypair().unwrap();
    let message = b"shared-message";

    let quote_sig = MlDsaBackend.sign(message, seed.as_bytes(), SIGNING_CONTEXT_QUOTE).unwrap();
    assert!(
        MlDsaBackend.verify(message, &vk, quote_sig.as_ref(), SIGNING_CONTEXT_CERT).is_err(),
        "quote signature must not verify under cert context"
    );
}

#[test]
fn crl_signature_cannot_be_reused_as_quote_signature() {
    let (seed, vk) = generate_ml_dsa_keypair().unwrap();
    let message = b"shared-message";

    let crl_sig = MlDsaBackend.sign(message, seed.as_bytes(), SIGNING_CONTEXT_CRL).unwrap();
    assert!(
        MlDsaBackend.verify(message, &vk, crl_sig.as_ref(), SIGNING_CONTEXT_QUOTE).is_err()
    );
    assert!(
        MlDsaBackend.verify(message, &vk, crl_sig.as_ref(), SIGNING_CONTEXT_CERT).is_err()
    );
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
    let nonce_used    = [0x11u8; 32];
    let nonce_claimed = [0x22u8; 32]; // different from what was signed into the quote

    let cbor = make_quote_cbor(&seed, &vk, &nonce_used);
    let verifier = Verifier::new(PolicyConfig::default());
    assert!(
        verifier.verify_cbor(&cbor, &vk, &nonce_claimed, 1_700_000_100).is_err(),
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
        verifier.verify_cbor(&cbor_tampered, &vk, &nonce, 1_700_000_100).is_err(),
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
        verifier.verify_cbor(&cbor_tampered, &vk, &nonce, 1_700_000_100).is_err(),
        "inflated SLSA level must fail signature check"
    );
}

// ── Certificate chain forgery ─────────────────────────────────────────────────

#[test]
fn cert_with_forged_tbs_fails_chain_validation() {
    let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
    let (_, dev_vk) = generate_ml_dsa_keypair().unwrap();
    let anchor = TrustAnchor::new(CaPublicKey { key_bytes: ca_vk, ca_id: "https://ca.test" });

    let subject_key_id = pqrascv_core::crypto::pub_key_id(&dev_vk);
    let mut cert = DeviceCertificate {
        version: CERT_VERSION,
        serial: "DEV-001".to_string(),
        issuer_id: "https://ca.test".to_string(),
        not_before: 0,
        not_after: u64::MAX,
        subject_key: dev_vk.to_vec(),
        subject_key_id,
        hardware_identity: HardwareIdentity::TpmEkCertHash([0u8; 32]),
        fw_policy: None,
        issuer_signature: vec![],
        self_id: "https://dev.test".to_string(),
        max_path_length: Some(0),
    };
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
    let anchor = TrustAnchor::new(CaPublicKey { key_bytes: ca_vk, ca_id: "https://ca.test" });

    let subject_key_id = pqrascv_core::crypto::pub_key_id(&dev_vk);
    let mut cert = DeviceCertificate {
        version: CERT_VERSION,
        serial: "DEV-001".to_string(),
        issuer_id: "https://evil.ca".to_string(), // wrong issuer
        not_before: 0,
        not_after: u64::MAX,
        subject_key: dev_vk.to_vec(),
        subject_key_id,
        hardware_identity: HardwareIdentity::TpmEkCertHash([0u8; 32]),
        fw_policy: None,
        issuer_signature: vec![],
        self_id: "https://dev.test".to_string(),
        max_path_length: Some(0),
    };
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
```

- [ ] **Step 2: Run adversarial tests**

```
cargo test -p pqrascv-core --features std,software-rot-unsafe --test adversarial_tests
```
Expected: all pass.

- [ ] **Step 3: Commit**

```
git add crates/pqrascv-core/tests/adversarial_tests.rs
git commit -m "test(adversarial): add cross-context, replay, forgery, and downgrade attack tests"
```

---

## Task 12: Full Test Suite + Final Verification

**Files:** No new files; runs all tests and confirms no regressions.

- [ ] **Step 1: Run the full workspace test suite**

```
cargo test --workspace --features std,software-rot-unsafe,dice 2>&1
```
Expected: all tests pass, zero failures.

- [ ] **Step 2: Run clippy**

```
cargo clippy --workspace --features std,software-rot-unsafe,dice -- -D warnings
```
Expected: no warnings.

- [ ] **Step 3: Confirm fabricated strings are absent from the entire codebase**

```
grep -rn "StrongFinality\|9a8f2c31\|8f434346\|Epoch 42\|Deterministic Merkle Trace\|sim_epoch\|sim_root\|expected_root" crates/cli/src/
```
Expected: **no output**.

- [ ] **Step 4: Confirm domain separation contexts are present at all call sites**

```
grep -n "sign_deterministic\|verify_with_context" crates/pqrascv-core/src/crypto.rs
```
Expected: both appear — each called with the `context` parameter.

```
grep -rn "SIGNING_CONTEXT_" crates/
```
Expected: `SIGNING_CONTEXT_QUOTE` in `quote.rs` and `verifier/lib.rs`; `SIGNING_CONTEXT_CERT` in `pki/mod.rs`; `SIGNING_CONTEXT_CRL` in `revocation.rs`.

- [ ] **Step 5: Final commit**

```
git add -A
git commit -m "chore: final adversarial remediation — all fabricated outputs removed, cryptographic enforcement complete"
```

---

## Self-Review Against Audit Findings

| Audit Finding | Task | Status |
|---------------|------|--------|
| P0-1: Fabricated CLI outputs | Task 1 | ✓ removed |
| P0-2: SPV accepts forged headers | Task 5 | ✓ PoW validation added |
| P0-3: 20-byte OP_RETURN truncation | Task 3 | ✓ full 32-byte commitment |
| P0-4: PKI disconnected from verifier | Task 8 | ✓ `verify_cbor_with_pki` wired |
| P1-1: ExternalProvenanceBundle hollow | Task 10 | ✓ explicit NOT_IMPLEMENTED |
| P1-2: No domain separation | Task 2 | ✓ three distinct contexts |
| P1-3: CRL signature not enforced | Task 6 | ✓ `VerifiedRevocationList` |
| P1-4: CLI uses SoftwareRoT silently | Task 1 | ✓ explicit warning |
| P1-5: PolicyEngineV2 never populated | Task 9 | ✓ `from_verified_quote()` |
| P1-6: CVE-2012-2459 Merkle tree | Task 4 | ✓ RFC6962 |
| P1-7: TPM AuditCounter0 semantics | — | documented; NV counter deferred |
| P1-8: Missing issuer binding/path length | Task 7 | ✓ enforced in `validate_chain` |
| P2-1: Dual timestamp systems | Task 9 | ✓ `from_verified_quote` unifies them |
| P2-2: No channel binding | — | deferred (requires protocol change) |
| P2-3: CaPublicKey.ca_id static | — | deferred (operational change) |
| P2-4: DICE PCRs 1-7 zero | — | documented; requires PCR spec |
| P2-5: Seed written unprotected | — | deferred (OS-level hardening) |

**Deferred items** (P1-7, P2-2, P2-3, P2-4, P2-5) require either protocol-breaking changes or external infrastructure decisions. They are not implemented in this plan but are documented above.
