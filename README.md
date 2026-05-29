<div align="center">

# pqrascv-core

**Post-Quantum Remote Attestation & Supply-Chain Verification (PQ-RASCV)**

[![Crates.io](https://img.shields.io/crates/v/pqrascv-core.svg)](https://crates.io/crates/pqrascv-core)
[![docs.rs](https://docs.rs/pqrascv-core/badge.svg)](https://docs.rs/pqrascv-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![no\_std](https://img.shields.io/badge/no__std-compatible-green.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)
[![CI](https://github.com/comwanga/pqrascv-core/actions/workflows/ci.yml/badge.svg)](https://github.com/comwanga/pqrascv-core/actions/workflows/ci.yml)

*Hardware-rooted · supply-chain-verified · post-quantum signed — everywhere Rust runs.*

</div>

---

`pqrascv-core` is a `no_std + alloc` Rust library for issuing and verifying tamper-evident device
attestation quotes. Every quote is signed with **ML-DSA-65 (FIPS 204)** and carries a
**SLSA v1 / in-toto provenance predicate** binding a device's firmware identity to its build
pipeline in a single compact CBOR message — on bare-metal Cortex-M4, RISC-V, WASM, or Linux.

---

## Why PQ-RASCV?

Two converging threats are making classical attestation obsolete:

**Supply-chain attacks are accelerating.** SolarWinds, XZ Utils, and dozens of lesser-known
incidents show that firmware can be compromised at build time. Existing attestation stacks
(TPM 2.0, DICE, TDX) prove *what* is running — but carry no cryptographic proof of *how* it was
built or *who* signed it off.

**Post-quantum migration is overdue.** RSA and ECDSA underpin today's attestation chains and are
broken by Shor's algorithm. NIST finalised ML-DSA (FIPS 204) and ML-KEM (FIPS 203) in 2024.
Devices deployed today may still be in service when cryptographically-relevant quantum computers
arrive.

PQ-RASCV addresses both in a single embedded-first library. Every attestation quote is
post-quantum signed *and* supply-chain provenance-linked.

---

## Features

- **Post-quantum by default** — ML-DSA-65 signatures; no RSA or ECDSA anywhere
- **Supply-chain provenance** — SLSA v1 predicates + SBOM hash inside every signed quote
- **Device PKI** — CBOR-native certificate chains (Root CA → Intermediate → Device), CRL revocation, and trust anchor lifecycle management
- **Three measurement backends** — Software SHA3-256, hardware TPM 2.0, DICE CDI derivation
- **`no_std + alloc`** — one API across Cortex-M4, RISC-V, WASM, and Linux
- **Allocation-free measurement path** — `RoT::measure()` never touches the heap
- **Replay protection** — verifier-supplied 32-byte nonce bound inside the signature
- **Constant-time PQ ops** — RustCrypto crates; key material is `Zeroize`-on-drop
- **Compact wire format** — CBOR (RFC 8949), ~3.7 KB total quote including signature
- **Bitcoin anchoring SDK** — `pqrascv-bitcoin-anchor` builds OP_RETURN payloads and verifies RFC 6962 Merkle + SPV inclusion proofs; requires operator-provided Bitcoin node for broadcast and confirmation

---

## Quick Start

```toml
# std (default)
pqrascv-core = "1.0.0-rc.3"

# bare-metal — bring your own allocator
pqrascv-core = { version = "1.0.0-rc.3", default-features = false, features = ["alloc"] }
```

### CLI

The fastest way to test attestation is the `pqrascv` CLI:

```bash
cargo install pqrascv-cli

# 1. Generate a post-quantum keypair
pqrascv keygen --out-seed seed.bin --out-vk vk.bin

# 2. Generate an attestation quote (prover side)
#    --software-rot-acknowledged is required when using the software backend
#    (no real TPM/DICE/TDX hardware). The nonce is generated automatically
#    and printed — copy the hex string for use in step 3.
pqrascv attest \
  --seed seed.bin --vk vk.bin \
  --firmware firmware.bin \
  --slsa-level 3 \
  --out quote.cbor \
  --software-rot-acknowledged

# 3. Verify the quote (verifier side)
#    --nonce must be the 64-hex-char value printed by the attest step above.
pqrascv verify \
  --vk vk.bin \
  --quote quote.cbor \
  --nonce <64-HEX-CHAR-NONCE-FROM-ATTEST-OUTPUT> \
  --json
```

### Prover — device side

```rust
use pqrascv_core::{
    crypto::{generate_ml_dsa_keypair, MlDsaBackend},
    measurement::SoftwareRoT,
    provenance::SlsaPredicateBuilder,
    quote::{generate_quote, QuoteTimestamp},
};

let (sk, vk) = generate_ml_dsa_keypair().unwrap();

// SoftwareRoT is for testing only. Use TpmRoT or DiceRoT in production.
let rot = SoftwareRoT::new(b"my-firmware-image", None, 1);

let provenance = SlsaPredicateBuilder::new("https://ci.example.com/pipeline/42")
    .add_subject("firmware.bin", &[0xabu8; 32])
    .with_slsa_level(2)
    .build()
    .unwrap();

let nonce = [0x42u8; 32]; // received from the verifier's Challenge

let quote = generate_quote(
    &rot, &MlDsaBackend, sk.as_bytes(), &vk, &nonce,
    provenance, QuoteTimestamp::Rtc(1_700_000_000),
)
.unwrap();

let cbor_bytes = quote.to_cbor().unwrap(); // send to verifier
```

### Verifier — server side

Simple key-based verification:

```rust
use pqrascv_verifier::Verifier;
use pqrascv_core::config::PolicyConfig;

let verifier = Verifier::new(PolicyConfig {
    min_slsa_level: 2,
    max_quote_age_secs: 300,
    require_firmware_hash: true,
    ..Default::default()
});

match verifier.verify_cbor(&cbor_bytes, &trusted_vk, &nonce, now_secs) {
    Ok(r)  => println!("Verified — SLSA {}", r.slsa_level()),
    Err(e) => eprintln!("Rejected: {e}"),
}
```

PKI-based verification with a certificate chain:

```rust
use pqrascv_verifier::Verifier;
use pqrascv_core::pki::{CaPublicKey, TrustAnchor, validate_chain};

let root_ca = CaPublicKey {
    ca_id: "root-ca-v1".to_string(),
    key_bytes: ROOT_CA_VK_BYTES,
    not_before: 1_700_000_000,
    not_after:  1_800_000_000,
};
let anchor = TrustAnchor::new(root_ca);

let result = verifier.verify_cbor_with_pki(
    &cbor_bytes, &device_cert, &intermediates, &anchor, &nonce, now_secs,
)?;

println!("anchor: {}", result.trust_anchor_id());
println!("valid until: {}", result.trust_anchor_valid_until());
```

CA rollover with `TrustStore`:

```rust
use pqrascv_core::pki::TrustStore;

let store = TrustStore::new(old_anchor)
    .with_rollover(new_anchor); // old and new CAs coexist during migration

let result = verifier.verify_cbor_with_trust_store(
    &cbor_bytes, &device_cert, &intermediates, &store, &nonce, now_secs,
)?;
```

---

## How It Works

PQ-RASCV is a **challenge–response** protocol. The verifier drives; the prover measures,
attests, and signs:

```
Verifier                                  Prover (device)
   │                                           │
   │──── Challenge { nonce: [u8; 32] } ──────► │
   │                                           ├── measure()  → PCRs, fw_hash
   │                                           ├── provenance → SLSA v1 predicate
   │                                           └── sign body  → ML-DSA-65 sig
   │                                           │
   │ ◄──── AttestationQuote (CBOR) ─────────── │
   │                                           │
   ├── verify ML-DSA-65 signature
   ├── check nonce match + pub_key_id fingerprint
   ├── optionally: validate cert chain → root CA + CRL
   └── evaluate PolicyConfig  →  accept / reject
```

### Signed payload fields (`QuoteBody`)

| Field | Content |
|-------|---------|
| `version` | Protocol version |
| `timestamp` | Unix epoch seconds (or `NoRtc` for embedded targets without a clock) |
| `nonce` | 32-byte replay-protection token |
| `measurements.pcrs` | 8 × 32-byte PCR-style hash bank |
| `measurements.firmware_hash` | SHA3-256 of firmware image |
| `measurements.ai_model_hash` | SHA3-256 of AI model weights (optional) |
| `provenance` | SLSA v1 predicate — builder ID, subjects, SBOM hash |
| `pub_key_id` | SHA3-256 fingerprint of signer's ML-DSA-65 verifying key |
| `signature` | 3 309-byte ML-DSA-65 signature over CBOR-encoded body |

---

## Architecture

```
╔══════════════════════════════════════════════════════╗
║          generate_quote()  ← public entry point      ║
╚══════╤═══════════════╤══════════════╤════════════════╝
       │               │              │
  ┌────▼─────┐   ┌─────▼──────┐  ┌───▼──────────────────┐
  │ RoT      │   │ Crypto     │  │ Provenance            │
  │ trait    │   │ Backend    │  │ SlsaPredicateBuilder  │
  │ measure()│   │ ML-DSA-65  │  │ (v1: self-asserted)   │
  └────┬─────┘   └─────┬──────┘  └───┬──────────────────┘
       │               │              │
  ┌────▼───────────────▼──────────────▼───────────────┐
  │        AttestationQuote  (CBOR · ML-DSA signed)   │
  └───────────────────────────────────────────────────┘
           │                         │
  ┌────────▼────────┐    ┌───────────▼─────────────┐
  │  PKI / CertChain│    │  Bitcoin Anchor          │
  │  TrustStore     │    │  OP_RETURN + Merkle tree │
  └─────────────────┘    └─────────────────────────┘
```

| Layer | Module | Heap? |
|-------|--------|-------|
| Measurement (`RoT` trait) | `measurement`, `backends/` | No |
| Cryptography (`CryptoBackend` trait) | `crypto` | No |
| Provenance builder | `provenance` | Yes — `alloc` |
| Quote assembly | `quote` | Yes — `alloc` |
| PKI / certificate chains | `pki` | Yes — `alloc` |
| Policy evaluation | `config`, `policy` | No |

---

## Device PKI

PQ-RASCV v2 replaces arbitrary key trust with a full CBOR-native PKI.

### Certificate hierarchy

```
Offline Root CA (air-gapped)
  └── Manufacturer Intermediate CA (HSM-protected)
        └── DeviceCertificate
              ├── subject_key: ML-DSA-65 verifying key (1 952 bytes)
              ├── hardware_id: TPM EK cert hash / DICE UDS fingerprint
              └── fw_policy: allowed firmware hash set (optional)
```

Certificates are CBOR-native (`DeviceCertificate`), not X.509, to avoid ASN.1 parsing on
embedded targets.

### Trust anchor lifecycle

`CaPublicKey` includes `not_before` and `not_after` timestamps. `validate_chain` enforces the
trust anchor's temporal validity window **before** any signature work:

```rust
pub struct CaPublicKey {
    pub ca_id: String,
    pub key_bytes: [u8; ML_DSA_65_VERIFYING_KEY_SIZE],
    pub not_before: u64,  // Unix seconds — CA is not trusted before this
    pub not_after:  u64,  // Unix seconds — CA must not be trusted after this
}
```

If the anchor is outside its validity window, `validate_chain` returns
`PqRascvError::TrustAnchorExpired` immediately, without attempting any signature verification.

### CA rollover with `TrustStore`

`TrustStore` holds multiple trust anchors for staged CA migration:

```rust
let store = TrustStore::new(current_anchor)
    .with_rollover(incoming_anchor);

// Returns the first valid anchor that successfully validates the chain.
// Returns TrustAnchorExpired if no anchors are in their validity window.
let chain = validate_chain_with_store(&device_cert, &intermediates, &store, now_secs)?;
```

`PkiVerificationResult` exposes audit fields for the anchor that accepted the chain:

```rust
result.trust_anchor_id()          // ca_id of the accepting anchor
result.trust_anchor_fingerprint() // SHA3-256 of its verifying key
result.trust_anchor_valid_until() // not_after of the accepting anchor
```

### Revocation

CRLs are signed CBOR lists (`RevocationList`). `VerifiedRevocationList` wraps a CRL whose
signature has been checked — `is_revoked()` is only accessible after signature verification,
preventing callers from bypassing the check.

### End-to-end PKI walkthrough

The following example shows the complete flow from CA setup through quote verification.
In production the CA operations would run on an air-gapped HSM and ship only the signed
certificates; the prover and verifier sides never share private key material.

```rust
use pqrascv_core::{
    config::PolicyConfig,
    crypto::{generate_ml_dsa_keypair, pub_key_id, CryptoBackend, MlDsaBackend,
             ML_DSA_65_VERIFYING_KEY_SIZE, SIGNING_CONTEXT_CERT},
    measurement::SoftwareRoT,
    pki::{CaPublicKey, DeviceCertificate, HardwareIdentity, TrustAnchor, CERT_VERSION},
    provenance::SlsaPredicateBuilder,
    quote::{generate_quote, QuoteTimestamp},
};
use pqrascv_verifier::Verifier;
use sha3::{Digest, Sha3_256};

// ── 1. CA setup (offline / HSM in production) ───────────────────────────────

let (ca_seed, ca_vk) = generate_ml_dsa_keypair()?;

let trust_anchor = TrustAnchor::new(CaPublicKey {
    ca_id:      "https://pki.example.com/root".to_string(),
    key_bytes:  ca_vk,
    not_before: 0,
    not_after:  u64::MAX,  // use a real expiry in production
})?;

// ── 2. Device provisioning (factory / secure enclave) ───────────────────────

let (dev_seed, dev_vk) = generate_ml_dsa_keypair()?;

let mut device_cert = DeviceCertificate {
    version:           CERT_VERSION,
    serial:            "DEV-2025-001".to_string(),
    issuer_id:         "https://pki.example.com/root".to_string(),
    self_id:           "https://pki.example.com/devices/DEV-2025-001".to_string(),
    not_before:        0,
    not_after:         u64::MAX,
    subject_key:       dev_vk.to_vec(),
    subject_key_id:    pub_key_id(&dev_vk),
    hardware_identity: HardwareIdentity::TpmEkCertHash([0u8; 32]), // real EK hash in prod
    fw_policy:         None,
    issuer_signature:  vec![],
    max_path_length:   Some(0),  // leaf certificate
};

// CA signs the device certificate (runs on HSM in production)
let tbs = device_cert.tbs_cbor()?;
let sig = MlDsaBackend.sign(&tbs, ca_seed.as_bytes(), SIGNING_CONTEXT_CERT)?;
device_cert.issuer_signature = sig.as_ref().to_vec();

// ── 3. Quote generation (prover / device) ───────────────────────────────────

let firmware: &[u8] = b"firmware image bytes";
let nonce = [0x42u8; 32];  // supplied by the verifier in a real flow

let fw_hash: [u8; 32] = Sha3_256::digest(firmware).into();
let rot  = SoftwareRoT::new(firmware, None, 0);  // use hardware backend in prod
let prov = SlsaPredicateBuilder::new("https://ci.example.com")
    .add_subject("firmware.bin", &fw_hash)
    .with_slsa_level(1)
    .build()?;

let dev_vk_array: [u8; ML_DSA_65_VERIFYING_KEY_SIZE] = dev_vk.try_into().unwrap();

let quote = generate_quote(
    &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk_array,
    &nonce, prov, QuoteTimestamp::NoRtc,
)?;
let cbor = quote.to_cbor()?;

// ── 4. Quote verification (verifier / server) ───────────────────────────────

let verifier = Verifier::new(PolicyConfig::default());

let result = verifier.verify_cbor_with_pki(
    &cbor,
    device_cert,
    vec![],   // no intermediate CAs in this example
    &trust_anchor,
    None,     // no CRL
    &nonce,
    0,        // now_secs — use SystemTime::now() in production
)?;

println!("Firmware hash: {}", hex::encode(result.firmware_hash()));
println!("Verified by CA: {}", result.trust_anchor_id());
```

This example uses `SoftwareRoT` (testing only). Replace it with `TpmRoT`, `DiceRoT`, or the
hardware TDX/SEV-SNP backends for production deployments where `PolicyEngineV2::production()`
is active.

---

## Supported Backends

### Software RoT *(development/testing — `features = ["software-rot-unsafe"]`)*

Hashes memory regions with SHA3-256. **Never use in production** — the `PolicyEngineV2`
rejects this backend by default.

```rust
let rot = SoftwareRoT::new(b"firmware", Some(b"ai-model-weights"), 0);
```

### TPM 2.0 — `features = ["hardware-tpm"]`

Reads the SHA-256 PCR bank (PCRs 0–7) from a hardware or simulated TPM via
[`tss-esapi`](https://crates.io/crates/tss-esapi) (TCG TSS2 ESAPI). Linux only.

```toml
pqrascv-core = { version = "1.0.0-rc.3", features = ["hardware-tpm"] }
```

```rust
// Set TPM2TOOLS_TCTI=device:/dev/tpm0  or  swtpm:path=/tmp/swtpm.sock
let rot = TpmRoT::new(b"firmware", None, 0);
let m   = rot.measure().expect("TPM read failed");
```

```bash
sudo apt install libtss2-dev tpm2-tools swtpm swtpm-tools
```

### DICE RoT — `features = ["dice"]`

[TCG DICE Architecture §6](https://trustedcomputinggroup.org/resource/dice-layering-architecture/)
CDI derivation in pure Rust — no OS, no heap, bare-metal ready.

```
CDI_attestation = SHA3-256( CDI ‖ "DICE-attest" ‖ SHA3-256(firmware) )
```

```toml
pqrascv-core = { version = "1.0.0-rc.3", features = ["dice"] }
```

```rust
// Two-layer chain: bootloader → application
let m0   = DiceRoT::new(hardware_uds, BOOTLOADER, None, 0).measure().unwrap();
let cdi1 = m0.pcrs.0[0];
let m1   = DiceRoT::new(cdi1, APP_FW, Some(AI_MODEL), 0).measure().unwrap();
```

---

## Bitcoin Anchoring

`pqrascv-bitcoin-anchor` is a **library SDK** for building and verifying Bitcoin OP_RETURN
anchoring payloads. It provides all the cryptographic machinery:

- **OP_RETURN payload encoding/decoding** — 40-byte format: `"PQRASCV" || 0x02 || merkle_root`
- **RFC 6962 Merkle tree** — second-preimage resistant (leaf prefix `0x00`, internal `0x01`)
- **SPV inclusion proof verification** — offline-verifiable without a full node

```
OP_RETURN <magic: 7 bytes "PQRASCV"> <version: 1 byte 0x02> <merkle_root: 32 bytes>
Total payload: 40 bytes (well within the 80-byte OP_RETURN limit)
```

**Integration note:** The SDK constructs and verifies payloads, but broadcasting transactions
and retrieving confirmation proofs requires an operator-provided Bitcoin node or Electrum server.
The `pqrascv verify` CLI confirms ML-DSA-65 signature validity; Bitcoin anchoring verification
is a separate step performed against your node using the SDK.

---

## Cryptographic Primitives

| Role | Algorithm | Standard | Sizes |
|------|-----------|----------|-------|
| Signatures | ML-DSA-65 | FIPS 204 | seed 32 B · vk 1 952 B · sig 3 309 B |
| Key encapsulation | ML-KEM-768 | FIPS 203 | Used in `pqrascv-hardware` PQ transport key type |
| Hashing | SHA3-256 | FIPS 202 | 32 B digest |
| Wire encoding | CBOR | RFC 8949 | ~3.7 KB total quote |

All PQ operations are constant-time (RustCrypto guarantee). `SigningKeySeed` implements
`Zeroize` and is wiped on drop.

Domain separation contexts are used for all ML-DSA-65 signing operations so that signatures
produced in different protocol roles cannot be cross-context replayed.

---

## Performance

| Target | Flash | Stack peak |
|--------|-------|------------|
| Cortex-M4 `thumbv7em-none-eabi` | < 64 KB | ~12 KB |
| RISC-V `riscv32imac-unknown-none-elf` | < 68 KB | ~12 KB |
| Linux x86-64 | — | ~16 KB |

Release profile: `lto = true`, `codegen-units = 1`, `opt-level = 3`.
Measurement latency on Cortex-M4 @ 168 MHz: < 1 ms (Software RoT, 64 KB firmware).

---

## Security Considerations

**Key storage** — `SigningKeySeed` is 32 bytes and zeroizes on drop. On real hardware, store it
in a hardware-protected keystore (TPM NV, TrustZone, eFuse OTP). Never log or transmit the seed.

**Nonce freshness** — reusing a nonce breaks replay protection. Generate a fresh 32-byte nonce
per request and verify it matches the returned quote exactly.

**Trust anchor validity** — always pass the current wall-clock time to `validate_chain` and
`validate_chain_with_store`. If your trust anchor's `not_after` has passed, the function returns
`TrustAnchorExpired` — rotate your root CA before this deadline.

**CA key storage** — the offline root CA private key must never touch a networked machine. Use an
HSM or air-gapped ceremony. A compromised root CA invalidates all device certificates.

**CRL freshness** — always check the certificate revocation list. `VerifiedRevocationList` wraps
a CRL whose signature has been verified; do not accept an unverified `RevocationList` directly.

**Verifying key trust** — when not using PKI, the caller supplies a trusted verifying key.
A compromised key invalidates all quotes signed with it.

**DICE CDI confidentiality** — the `cdi` field in `DiceRoT` is the hardware root secret. It
must never leave the device. Only the one-way `cdi_attestation` appears in quotes.

**Transport layer** — ML-DSA-65 protects the signature. If your transport (TLS 1.2, classical
ECDH) is not post-quantum, a "harvest now, decrypt later" attacker can record and later decrypt
the channel. Pair with a PQ transport (Noise\_PQX, planned).

**SoftwareRoT** — the `software-rot-unsafe` feature must never be compiled into production
firmware. The `PolicyEngineV2` rejects `SoftwareRoT` by default.

**Quote age** — set `PolicyConfig::max_quote_age_secs` to 60–300 s to bound the validity window
of captured quotes.

---

## Status

**v1.0.0-rc.3** — API stabilizing. 382 tests pass.

| Implemented ✅ | Preview / Experimental 🔬 | Planned 🗺 |
|----------------|---------------------------|------------|
| ML-DSA-65 sign / verify | Sigstore bundle verification (`verify_all` conditions 1–5) | Noise\_PQX post-quantum transport |
| ML-KEM-768 encapsulation (PQ transport key type) | Fulcio chain + Rekor inclusion proof parsing | CBOR COSE signatures (RFC 9052) |
| Software / TPM 2.0 / DICE backends | Intel TDX backend (`intel-tdx` feature) | Python SDK (PyO3 bindings) |
| SLSA v1 provenance + SBOM hash | AMD SEV-SNP backend (`amd-sev-snp` feature) | OP-TEE / TrustZone backend |
| CBOR-native PKI (Root CA → Device) | | Stable 1.0 API (pending `ml-dsa` crate GA) |
| CRL revocation (`VerifiedRevocationList`) | | |
| Trust anchor lifecycle (`not_before`/`not_after`) | | |
| `TrustStore` CA rollover | | |
| `PolicyEngineV2` composable rule engine | | |
| Hardware-identity cross-validation (TDX/SEV-SNP → PCR[0]) | | |
| Bitcoin OP_RETURN anchoring SDK (40-byte payload) | | |
| RFC 6962 Merkle tree + SPV proofs | | |
| ML-DSA-65 domain separation contexts | | |
| CLI prover + verifier binary | | |

### Backend Maturity

| Backend | Feature flag | Maturity | Notes |
|---------|-------------|----------|-------|
| `SoftwareRoT` | `software-rot-unsafe` | **Test / demo only** | No hardware boundary; measurements are caller-supplied. Requires `--software-rot-acknowledged` in CLI. |
| TPM 2.0 | `hardware-tpm` | **Production** | Requires `tpm2-tss` system library. |
| DICE CDI | `dice` | **Production** | Pure-Rust; suitable for MCU boot chains. |
| Intel TDX | `intel-tdx` | **Experimental** | Linux kernel ≥ 6.5 with `/dev/tdx_guest`. Community testing welcome. |
| AMD SEV-SNP | `amd-sev-snp` | **Experimental** | Linux kernel ≥ 6.5 with `/dev/sev-guest`. Community testing welcome. |

---

## Contributing

Issues, PRs, and feedback are welcome at
[github.com/comwanga/pqrascv-core](https://github.com/comwanga/pqrascv-core).

```bash
cargo fmt --all
cargo clippy --all --features std,dice -- -D warnings
cargo clippy -p pqrascv-core --no-default-features -- -D warnings
cargo test --all
cargo audit
```

Areas where contributions are especially valuable:

- **Platform backends** — SEV-SNP, TDX, OP-TEE, Apple Secure Enclave
- **Transport** — Noise\_PQX integration, COSE/CBOR signing
- **Provenance** — Sigstore / Rekor / Fulcio client integration
- **Tooling** — Hardware provisioning scripts, key management daemons
- **Verification** — `kani` harnesses for the crypto paths, fuzzing

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full system design.

---

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.

Contributions are dual-licensed under the same terms unless explicitly stated otherwise.
