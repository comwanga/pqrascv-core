# pqrascv-core

**Post-Quantum Remote Attestation & Supply-Chain Verification (PQ-RASCV)**

A `no_std + alloc` Rust library for verifiable, post-quantum-secure remote attestation and supply-chain provenance. Drop it into Linux firmware, Zephyr, Tock, bare-metal Cortex-M, RISC-V, or WASM — the same API works everywhere.

[![Crates.io](https://img.shields.io/crates/v/pqrascv-core.svg)](https://crates.io/crates/pqrascv-core)
[![docs.rs](https://docs.rs/pqrascv-core/badge.svg)](https://docs.rs/pqrascv-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![no_std](https://img.shields.io/badge/no__std-compatible-green.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)

## Why PQ-RASCV?

Current attestation protocols (TPM 2.0, DICE, Intel TDX) use classical cryptography that will be broken by sufficiently powerful quantum computers. PQ-RASCV replaces RSA/ECDSA with **ML-DSA-65 (FIPS 204)** and **ML-KEM-768 (FIPS 203)** — both NIST-standardised post-quantum algorithms — while embedding **in-toto/SLSA v1 supply-chain provenance** directly in every signed quote.

Every quote is:
- **Post-quantum signed** — ML-DSA-65, constant-time, zeroize-on-drop key material
- **Provenance-linked** — SLSA v1 build predicates + SBOM hash inside the signed payload
- **Replay-resistant** — verifier-supplied 32-byte nonce bound in the signature
- **Embedded-first** — `no_std + alloc`, compiles to Cortex-M, RISC-V, and WASM

## Quick Start

```toml
[dependencies]
pqrascv-core = "0.1"
```

```rust
use pqrascv_core::{
    crypto::{generate_ml_dsa_keypair, MlDsaBackend},
    measurement::SoftwareRoT,
    provenance::SlsaPredicateBuilder,
    quote::generate_quote,
};

// --- Prover side ---
let (sk, vk) = generate_ml_dsa_keypair().unwrap();

let rot = SoftwareRoT::new(b"my-firmware-image", None, 1);
let provenance = SlsaPredicateBuilder::new("https://ci.example.com")
    .add_subject("firmware.bin", &firmware_sha3_256)
    .with_slsa_level(2)
    .build()
    .unwrap();

let nonce = [0x42u8; 32]; // received from verifier's Challenge
let quote = generate_quote(
    &rot, &MlDsaBackend, sk.as_bytes(), &vk, &nonce, provenance, timestamp,
).unwrap();

let cbor_bytes = quote.to_cbor().unwrap(); // send to verifier
```

```rust
use pqrascv_verifier::Verifier;
use pqrascv_core::config::PolicyConfig;

// --- Verifier side ---
let verifier = Verifier::new(PolicyConfig { min_slsa_level: 2, ..Default::default() });
let result = verifier.verify_cbor(&cbor_bytes, &trusted_vk, &nonce, now_secs);
assert!(result.is_ok());
```

## Protocol Overview

```
Verifier ──── Challenge { nonce: [u8; 32] } ────► Prover
         ◄─── AttestationQuote (CBOR, ML-DSA-65 signed) ──
              │
              ├─ version, timestamp, nonce
              ├─ measurements { PCRs, firmware_hash, ai_model_hash }
              ├─ provenance { SLSA v1 predicate + SBOM hash }
              ├─ pub_key_id (SHA3-256 of verifying key)
              └─ signature (ML-DSA-65, 3309 bytes)
```

## Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `std` | **yes** | Link against std |
| `alloc` | **yes** | Heap allocation (required for quote assembly) |
| `hardware-tpm` | no | TPM 2.0 measurement backend |
| `dice` | no | DICE RoT measurement backend |

For bare-metal use, disable default features and supply an allocator:

```toml
pqrascv-core = { version = "0.1", default-features = false, features = ["alloc"] }
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  generate_quote()  ← public entry point             │
└────────┬──────────┬──────────┬──────────────────────┘
         │          │          │
    ┌────▼────┐ ┌───▼────┐ ┌──▼─────────────────┐
    │ RoT     │ │ Crypto │ │ Provenance          │
    │ (trait) │ │ Backend│ │ SlsaPredicateBuilder│
    │ measure │ │ ML-DSA │ │ InTotoAttestation   │
    └────┬────┘ └───┬────┘ └──┬──────────────────┘
         │          │          │
    ┌────▼──────────▼──────────▼──────────────────┐
    │  AttestationQuote (CBOR-serialised, signed)  │
    └─────────────────────────────────────────────┘
```

## Cryptographic Primitives

| Primitive | Algorithm | Standard |
|-----------|-----------|---------|
| Signatures | ML-DSA-65 | FIPS 204 |
| Key encapsulation | ML-KEM-768 | FIPS 203 |
| Hashing | SHA3-256 | FIPS 202 |
| Wire format | CBOR | RFC 8949 |

All PQ operations are provided by [RustCrypto](https://github.com/RustCrypto/signatures) and are constant-time by construction.

## Status

`pqrascv-core` is under active development. The public API is stabilising; expect breaking changes before 1.0.

- [x] ML-DSA-65 signing/verification
- [x] Software RoT (SHA3-256 PCR banks)
- [x] In-toto / SLSA v1 provenance builder
- [x] CBOR quote serialisation + roundtrip
- [x] Reference verifier (`pqrascv-verifier`)
- [ ] TPM 2.0 backend (`hardware-tpm` feature)
- [ ] DICE RoT backend (`dice` feature)
- [ ] Noise/PQ transport handshake

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.
