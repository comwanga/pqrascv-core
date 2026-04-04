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

`pqrascv-core` is a `no_std + alloc` Rust library for issuing and verifying
tamper-evident device attestation quotes. Every quote is signed with
**ML-DSA-65 (FIPS 204)** and carries a **SLSA v1 / in-toto provenance predicate**,
binding a device's firmware identity to its build pipeline in a single, compact
CBOR message — on bare-metal Cortex-M4, RISC-V, WASM, or Linux.

---

## Why PQ-RASCV?

Two converging threats are making classical attestation obsolete in 2026:

**Supply-chain attacks are accelerating.** SolarWinds, XZ Utils, and dozens of
lesser-known incidents show that firmware can be compromised at build time.
Existing attestation stacks (TPM 2.0, DICE, TDX) prove *what* is running —
but carry no cryptographic proof of *how* it was built or *who* signed it off.

**Post-quantum migration is overdue.** RSA and ECDSA underpin today's
attestation chains and are broken by Shor's algorithm. NIST finalised ML-DSA
(FIPS 204) and ML-KEM (FIPS 203) in 2024. Devices deployed today may still be
in service when cryptographically-relevant quantum computers arrive.

PQ-RASCV addresses both in a single embedded-first library. Every attestation
quote is post-quantum signed *and* supply-chain provenance-linked — no
separately bolted-on components.

---

## Features

- **Post-quantum by default** — ML-DSA-65 signatures; no RSA or ECDSA anywhere
- **Supply-chain provenance** — SLSA v1 predicates + SBOM hash inside every signed quote
- **Three measurement backends** — Software SHA3-256, hardware TPM 2.0, DICE CDI derivation
- **`no_std + alloc`** — one API across Cortex-M4, RISC-V, WASM, and Linux
- **Allocation-free measurement path** — `RoT::measure()` never touches the heap
- **Replay protection** — verifier-supplied 32-byte nonce bound inside the signature
- **Constant-time PQ ops** — RustCrypto crates; key material is `Zeroize`-on-drop
- **Compact wire format** — CBOR (RFC 8949), ~3.7 KB total quote including signature

---

## Quick Start

```toml
# std (default)
pqrascv-core = "0.1"

# bare-metal — bring your own allocator
pqrascv-core = { version = "0.1", default-features = false, features = ["alloc"] }
```

### Prover — device side

```rust
use pqrascv_core::{
    crypto::{generate_ml_dsa_keypair, MlDsaBackend},
    measurement::SoftwareRoT,
    provenance::SlsaPredicateBuilder,
    quote::generate_quote,
};

let (signing_seed, verifying_key) = generate_ml_dsa_keypair().unwrap();

let rot = SoftwareRoT::new(b"my-firmware-image", None, 1);

let firmware_digest = [0xabu8; 32]; // SHA3-256(firmware.bin)
let provenance = SlsaPredicateBuilder::new("https://ci.example.com/pipeline/42")
    .add_subject("firmware.bin", &firmware_digest)
    .with_slsa_level(2)
    .build()
    .unwrap();

let nonce = [0x42u8; 32]; // received from verifier's Challenge
let quote = generate_quote(
    &rot, &MlDsaBackend, signing_seed.as_bytes(),
    &verifying_key, &nonce, provenance, 1_700_000_000,
)
.unwrap();

let cbor_bytes = quote.to_cbor().unwrap(); // send to verifier
```

### Verifier — server side

Uses the companion [`pqrascv-verifier`](crates/verifier) crate:

```rust
use pqrascv_verifier::Verifier;
use pqrascv_core::config::PolicyConfig;

let verifier = Verifier::new(PolicyConfig {
    min_slsa_level: 2,
    max_quote_age_secs: 300,
    require_firmware_hash: true,
    ..Default::default()
});

// trusted_vk obtained out-of-band (provisioning DB, PKI, TPM EK cert).
match verifier.verify_cbor(&cbor_bytes, &trusted_vk, &nonce, now_secs) {
    Ok(r)  => println!("Verified — SLSA {}", r.slsa_level),
    Err(e) => eprintln!("Rejected: {e}"),
}
```

---

## How It Works

PQ-RASCV is a **challenge–response** protocol. The verifier drives; the prover
measures, attests, and signs:

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
   └── evaluate PolicyConfig  →  accept / reject
```

**Signed payload fields (`QuoteBody`):**

| Field | Content |
|-------|---------|
| `version` | Protocol version (`1`) |
| `timestamp` | Unix epoch seconds |
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
  │ measure()│   │ ML-DSA-65  │  │ InTotoAttestation     │
  └────┬─────┘   └─────┬──────┘  └───┬──────────────────┘
       │               │              │
  ┌────▼───────────────▼──────────────▼───────────────┐
  │        AttestationQuote  (CBOR · ML-DSA signed)   │
  └───────────────────────────────────────────────────┘
```

| Layer | Module | Heap? |
|-------|--------|-------|
| Measurement (`RoT` trait) | `measurement`, `backends/` | No |
| Cryptography (`CryptoBackend` trait) | `crypto` | No |
| Provenance builder | `provenance` | Yes — `alloc` |
| Quote assembly | `quote` | Yes — `alloc` |
| Policy evaluation | `config` | No |

---

## Supported Backends

### Software RoT *(default — no hardware required)*

Hashes memory regions with SHA3-256. Ideal for development, WASM, and any
platform without a hardware RoT.

```rust
let rot = SoftwareRoT::new(b"firmware", Some(b"ai-model-weights"), 0);
```

### TPM 2.0 — `features = ["hardware-tpm"]`

Reads the SHA-256 PCR bank (PCRs 0–7) from a hardware or simulated TPM via
[`tss-esapi`](https://crates.io/crates/tss-esapi) (TCG TSS2 ESAPI). Linux only.

```toml
pqrascv-core = { version = "0.1", features = ["hardware-tpm"] }
```

```rust
// Set TPM2TOOLS_TCTI=device:/dev/tpm0  or  swtpm:path=/tmp/swtpm.sock
let rot = TpmRoT::new(b"firmware", None, 0);
let m   = rot.measure().expect("TPM read failed");
println!("PCR0: {:02x?}", m.pcrs.0[0]);
```

```bash
# Install system libraries (Ubuntu/Debian)
sudo apt install libtss2-dev tpm2-tools swtpm swtpm-tools
```

### DICE RoT — `features = ["dice"]`

[TCG DICE Architecture §6](https://trustedcomputinggroup.org/resource/dice-layering-architecture/)
CDI derivation in pure Rust — no OS, no heap, bare-metal ready.

```
CDI_attestation = SHA3-256( CDI ‖ "DICE-attest" ‖ SHA3-256(firmware) )
```

```toml
pqrascv-core = { version = "0.1", features = ["dice"] }
```

```rust
// Single layer
let rot = DiceRoT::new(cdi_from_hardware, b"firmware", None, 0);

// Two-layer chain: bootloader → application
let m0   = DiceRoT::new(hardware_uds, BOOTLOADER, None, 0).measure().unwrap();
let cdi1 = m0.pcrs.0[0];                 // CDI_0 derived from UDS
let m1   = DiceRoT::new(cdi1, APP_FW, Some(AI_MODEL), 0).measure().unwrap();
```

---

## Cryptographic Primitives

| Role | Algorithm | Standard | Sizes |
|------|-----------|----------|-------|
| Signatures | ML-DSA-65 | FIPS 204 | seed 32 B · vk 1 952 B · sig 3 309 B |
| Key encapsulation | ML-KEM-768 | FIPS 203 | — |
| Hashing (measurements, fingerprints) | SHA3-256 | FIPS 202 | 32 B digest |
| Wire encoding | CBOR | RFC 8949 | ~3.7 KB total quote |

All PQ operations are constant-time (RustCrypto guarantee).
`SigningKeySeed` implements `Zeroize` and is wiped on drop.

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

## Status & Roadmap

**v0.1.0** is published. The public API is stabilising; expect breaking changes before 1.0.

| Shipped in v0.1.0 ✅ | Planned 🗺 |
|----------------------|------------|
| ML-DSA-65 sign / verify | Noise\_PQX post-quantum transport |
| ML-KEM-768 encapsulation | CBOR COSE signatures (RFC 9052) |
| Software / TPM 2.0 / DICE backends | AMD SEV-SNP & Intel TDX backends |
| SLSA v1 provenance + SBOM hash | `heapless` allocation-free quote assembly |
| Reference verifier (`pqrascv-verifier`) | OP-TEE / TrustZone backend |
| `no_std` on Cortex-M, RISC-V, WASM | CLI prover + verifier binary |
| CI: cross-compile, swtpm, audit, MSRV | Stable 1.0 API |

---

## Security Considerations

**Key storage** — `SigningKeySeed` is 32 bytes and zeroizes on drop. On real hardware,
store it in a hardware-protected keystore (TPM NV, TrustZone, eFuse OTP). Never log
or transmit the seed.

**Nonce freshness** — reusing a nonce breaks replay protection. Generate a fresh
32-byte nonce per request and verify it matches the returned quote exactly.

**Verifying key trust** — [`pqrascv-verifier`](crates/verifier) does not manage a PKI.
The caller supplies a trusted verifying key (provisioning DB, certificate chain, or TPM
EK cert). A compromised key invalidates all quotes signed with it.

**DICE CDI confidentiality** — the `cdi` field in `DiceRoT` is the hardware root secret.
It must never leave the device. Only the one-way `cdi_attestation` appears in quotes.

**Transport layer** — ML-DSA-65 protects the signature. If your transport (TLS 1.2,
classical ECDH) is not post-quantum, a "harvest now, decrypt later" attacker can
record and later decrypt the channel. Pair with a PQ transport (Noise\_PQX, planned).

**Quote age** — set `PolicyConfig::max_quote_age_secs` to 60–300 s to bound the
validity window of captured quotes.

---

## Contributing

Issues, PRs, and feedback are welcome at
[github.com/comwanga/pqrascv-core](https://github.com/comwanga/pqrascv-core).

```bash
cargo fmt --all
cargo clippy --features dice -- -D warnings
cargo test --all
cargo audit
```

Areas where contributions are especially valuable:

- **Platform backends** — SEV-SNP, TDX, OP-TEE, Apple Secure Enclave
- **Transport** — Noise\_PQX integration, COSE/CBOR signing
- **Tooling** — CLI binary, provisioning helpers
- **Verification** — `kani` harnesses for the crypto paths, fuzzing

If you are using `pqrascv-core` in a project — even experimentally — open a
[GitHub Discussion](https://github.com/comwanga/pqrascv-core/discussions).
Feedback at any stage shapes the road to 1.0.

---

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.

Contributions are dual-licensed under the same terms unless explicitly stated otherwise.
