<div align="center">

# pqrascv-core

**Post-Quantum Remote Attestation & Supply-Chain Verification**

[![Crates.io](https://img.shields.io/crates/v/pqrascv-core.svg)](https://crates.io/crates/pqrascv-core)
[![docs.rs](https://docs.rs/pqrascv-core/badge.svg)](https://docs.rs/pqrascv-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![no_std](https://img.shields.io/badge/no__std-compatible-green.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)
[![CI](https://github.com/comwanga/pqrascv-core/actions/workflows/ci.yml/badge.svg)](https://github.com/comwanga/pqrascv-core/actions/workflows/ci.yml)

*Prove what you're running. Prove who built it. Survive the quantum era.*

</div>

---

`pqrascv-core` is a `no_std + alloc` Rust library that lets any device — from a bare-metal Cortex-M4 to a cloud VM — issue a cryptographically signed attestation quote that proves its firmware identity and supply-chain provenance, using only post-quantum algorithms standardised by NIST.

---

## Why PQ-RASCV?

Two converging threats are making classical attestation obsolete:

**1. Supply-chain attacks are accelerating.**
SolarWinds, XZ Utils, and dozens of lesser-known incidents demonstrate that firmware and software can be compromised at build time, long before it reaches a device. Existing attestation protocols (TPM 2.0, DICE, TDX) record *what* is running but carry no cryptographic proof of *how* it was built or *who* signed it off.

**2. Post-quantum migration is overdue.**
RSA and ECDSA — the signature algorithms underpinning today's attestation stacks — are vulnerable to Shor's algorithm. NIST finalised ML-DSA (FIPS 204) and ML-KEM (FIPS 203) in 2024. Devices deployed today may still be in service when cryptographically-relevant quantum computers arrive; their attestation chains need to be quantum-resistant now.

**PQ-RASCV (Post-Quantum Remote Attestation & Supply-Chain Verification)** addresses both threats in a single, embedded-first library:

- Every quote is signed with **ML-DSA-65 (FIPS 204)** — a lattice-based signature immune to quantum attacks.
- Every quote carries a **SLSA v1 / in-toto provenance predicate** and SBOM hash, cryptographically binding firmware to its build pipeline.
- The library runs on Linux, bare-metal ARM/RISC-V, WASM, and cloud — one API, every target.

---

## Features

- **Post-quantum by default** — ML-DSA-65 signatures, ML-KEM-768 key encapsulation; no RSA or ECDSA anywhere
- **Supply-chain provenance** — SLSA v1 predicates and SBOM hashes embedded in every signed quote
- **Three measurement backends** — Software (SHA3-256), hardware TPM 2.0, and DICE CDI derivation
- **`no_std + alloc`** — runs on Cortex-M4, RISC-V, WASM, and Linux from the same codebase
- **Replay protection** — 32-byte verifier-supplied nonce bound inside the ML-DSA signature
- **Constant-time** — all PQ operations via RustCrypto crates; key material is zeroize-on-drop
- **CBOR wire format** — compact binary encoding (RFC 8949) for constrained transports
- **Zero heap in the hot path** — traits and measurement structs are fully allocation-free
- **Reference verifier included** — `pqrascv-verifier` crate for server-side quote validation

---

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
pqrascv-core = "0.1"
```

For bare-metal targets (no OS, bring your own allocator):

```toml
[dependencies]
pqrascv-core = { version = "0.1", default-features = false, features = ["alloc"] }
```

### Prover (device side)

```rust
use pqrascv_core::{
    crypto::{generate_ml_dsa_keypair, MlDsaBackend},
    measurement::SoftwareRoT,
    provenance::SlsaPredicateBuilder,
    quote::generate_quote,
};

// Generate (or load from secure storage) the device's signing keypair.
let (signing_seed, verifying_key) = generate_ml_dsa_keypair().unwrap();

// Measure the running firmware.
let rot = SoftwareRoT::new(b"my-firmware-image", None, 1);

// Build SLSA v1 provenance — attach your CI pipeline and firmware digest.
let firmware_digest = [0xabu8; 32]; // SHA3-256 of firmware.bin
let provenance = SlsaPredicateBuilder::new("https://ci.example.com/pipeline/42")
    .add_subject("firmware.bin", &firmware_digest)
    .with_slsa_level(2)
    .build()
    .unwrap();

// nonce is the 32-byte challenge received from the verifier.
let nonce = [0x42u8; 32];
let timestamp = 1_700_000_000u64; // Unix epoch seconds

let quote = generate_quote(
    &rot,
    &MlDsaBackend,
    signing_seed.as_bytes(),
    &verifying_key,
    &nonce,
    provenance,
    timestamp,
)
.unwrap();

// Send to verifier as compact CBOR bytes.
let cbor_bytes = quote.to_cbor().unwrap();
```

### Verifier (server side)

```rust
use pqrascv_verifier::Verifier;
use pqrascv_core::config::PolicyConfig;

let policy = PolicyConfig {
    min_slsa_level: 2,
    max_quote_age_secs: 300,
    require_firmware_hash: true,
    require_event_counter: false,
};

let verifier = Verifier::new(policy);

// trusted_vk: the device's verifying key, obtained out-of-band (PKI, provisioning).
let result = verifier.verify_cbor(&cbor_bytes, &trusted_vk, &nonce, now_secs);

match result {
    Ok(outcome) => println!("Quote verified: SLSA level {}", outcome.slsa_level),
    Err(e)      => eprintln!("Verification failed: {e}"),
}
```

---

## How It Works

PQ-RASCV is a **challenge–response attestation protocol**:

```
┌──────────────────────────────────────────────────────────────────┐
│                     Protocol Flow                                │
│                                                                  │
│   Verifier                              Prover (device)          │
│      │                                      │                    │
│      │  1. Challenge { nonce: [u8;32] }     │                    │
│      │ ──────────────────────────────────► │                    │
│      │                                      │                    │
│      │                         2. measure() → PCRs, fw_hash     │
│      │                         3. build provenance (SLSA v1)    │
│      │                         4. sign body with ML-DSA-65      │
│      │                                      │                    │
│      │  5. AttestationQuote (CBOR)          │                    │
│      │ ◄────────────────────────────────── │                    │
│      │                                      │                    │
│      │  6. verify signature                 │                    │
│      │  7. check nonce + pub_key_id         │                    │
│      │  8. evaluate PolicyConfig            │                    │
│      │                                      │                    │
│    accept / reject                          │                    │
└──────────────────────────────────────────────────────────────────┘
```

**The signed payload (`QuoteBody`) contains:**

| Field | Description |
|-------|-------------|
| `version` | Protocol version (currently `1`) |
| `timestamp` | Unix epoch seconds at quote generation |
| `nonce` | 32-byte verifier-supplied replay-protection token |
| `measurements.pcrs` | 8 × 32-byte PCR-style hash bank |
| `measurements.firmware_hash` | SHA3-256 of the firmware image |
| `measurements.ai_model_hash` | SHA3-256 of the AI model (optional) |
| `provenance` | SLSA v1 predicate: builder ID, subjects, SBOM hash |
| `pub_key_id` | SHA3-256 fingerprint of the signer's ML-DSA-65 verifying key |
| `signature` | 3309-byte ML-DSA-65 signature over the CBOR-encoded body |

---

## Architecture

The library is split into four thin, composable layers:

```
┌──────────────────────────────────────────────────────────────────┐
│              generate_quote()  ← public entry point             │
└────────┬──────────────┬──────────────┬──────────────────────────┘
         │              │              │
    ┌────▼──────┐  ┌────▼──────┐  ┌───▼────────────────────────┐
    │  RoT      │  │  Crypto   │  │  Provenance                │
    │  trait    │  │  Backend  │  │  SlsaPredicateBuilder      │
    │  measure()│  │  ML-DSA-65│  │  InTotoAttestation         │
    └────┬──────┘  └────┬──────┘  └───┬────────────────────────┘
         │              │              │
    ┌────▼──────────────▼──────────────▼──────────────────────┐
    │       AttestationQuote  (CBOR-serialised + signed)      │
    └─────────────────────────────────────────────────────────┘

  RoT backends          Crypto backend       Wire format
  ───────────           ──────────────       ───────────
  SoftwareRoT           MlDsaBackend         ciborium (CBOR)
  TpmRoT                (extensible          + serde
  DiceRoT                via trait)
```

**Layer responsibilities:**

| Layer | Crate module | Allocates? |
|-------|-------------|------------|
| Measurement (`RoT` trait) | `measurement`, `backends/` | No |
| Cryptography (`CryptoBackend` trait) | `crypto` | No (stack-only sig) |
| Provenance builder | `provenance` | Yes (`alloc`) |
| Quote assembly | `quote` | Yes (`alloc`) |
| Policy evaluation | `config` | No |

---

## Supported Backends

### Software RoT (default)

No hardware required. Hashes memory regions with SHA3-256 to populate the PCR bank.
Suitable for development, WASM, and platforms without a hardware RoT.

```rust
use pqrascv_core::measurement::SoftwareRoT;

let rot = SoftwareRoT::new(
    b"firmware-bytes",
    Some(b"ai-model-weights"), // optional
    0,                          // event counter baseline
);
```

### TPM 2.0 (`hardware-tpm` feature)

Reads the SHA-256 PCR bank (PCRs 0–7) from a hardware or simulated TPM via the
TCG TSS2 ESAPI. Requires `libtss2-dev` on Linux and the `TPM2TOOLS_TCTI`
environment variable pointing to the TPM device or simulator.

```toml
pqrascv-core = { version = "0.1", features = ["hardware-tpm"] }
```

```rust
use pqrascv_core::backends::tpm::TpmRoT;
use pqrascv_core::measurement::RoT;

// TPM path set via TPM2TOOLS_TCTI=device:/dev/tpm0
// or TPM2TOOLS_TCTI=swtpm:path=/tmp/swtpm.sock for simulation
let rot = TpmRoT::new(b"firmware-bytes", None, 0);
let measurements = rot.measure().expect("TPM read failed");

println!("PCR0: {:02x?}", measurements.pcrs.0[0]);
```

**System requirements (Linux):**
```bash
sudo apt install libtss2-dev tpm2-tools
# or for simulation:
sudo apt install swtpm swtpm-tools
export TPM2TOOLS_TCTI="swtpm:path=/tmp/swtpm.sock"
```

### DICE RoT (`dice` feature)

Implements the [TCG DICE Architecture §6](https://trustedcomputinggroup.org/resource/dice-layering-architecture/) CDI derivation in pure Rust — no system libraries, no heap, runs on bare-metal.

Derives:
```
CDI_attestation = SHA3-256(CDI ‖ "DICE-attest" ‖ SHA3-256(firmware))
```

The attestation CDI is stored in PCR 0. Nest `DiceRoT` instances to build a multi-layer DICE chain.

```toml
pqrascv-core = { version = "0.1", features = ["dice"] }
```

```rust
use pqrascv_core::backends::dice::DiceRoT;
use pqrascv_core::measurement::RoT;

// cdi: 32-byte Compound Device Identifier from the previous DICE layer
// (or hardware UDS on the first layer)
let cdi = obtain_cdi_from_hardware(); // [u8; 32]

let rot = DiceRoT::new(cdi, b"firmware-bytes", None, 0);
let measurements = rot.measure().unwrap();

// PCR 0 holds the one-way attestation CDI — safe to include in a quote.
assert_ne!(measurements.pcrs.0[0], [0u8; 32]);
```

**DICE chain example (two firmware layers):**

```rust
// Layer 0: hardware UDS → CDI_0
let rot0 = DiceRoT::new(hardware_uds, BOOTLOADER_IMAGE, None, 0);
let m0 = rot0.measure().unwrap();
let cdi_1 = m0.pcrs.0[0]; // CDI_0 becomes input to layer 1

// Layer 1: CDI_0 → CDI_1 (application firmware)
let rot1 = DiceRoT::new(cdi_1, APP_FIRMWARE, Some(AI_MODEL), 0);
let measurements = rot1.measure().unwrap();
```

---

## Cryptographic Primitives

| Primitive | Algorithm | Standard | Provider |
|-----------|-----------|----------|----------|
| Signatures | ML-DSA-65 | FIPS 204 | `ml-dsa` (RustCrypto) |
| Key encapsulation | ML-KEM-768 | FIPS 203 | `ml-kem` (RustCrypto) |
| Hashing | SHA3-256 | FIPS 202 | `sha3` (RustCrypto) |
| Wire format | CBOR | RFC 8949 | `ciborium` |
| Key serialisation | Raw bytes | — | stack-allocated |

**Key sizes:**

| Item | Size |
|------|------|
| Signing seed | 32 bytes |
| Verifying key | 1 952 bytes |
| ML-DSA-65 signature | 3 309 bytes |
| SHA3-256 digest | 32 bytes |
| Nonce | 32 bytes |

All PQ operations are constant-time by construction (guaranteed by the RustCrypto crates).
All signing key material implements `Zeroize` and is wiped on drop.

---

## Performance

| Target | Flash (approx.) | RAM (stack peak) |
|--------|----------------|-----------------|
| Cortex-M4 (`thumbv7em-none-eabi`) | < 64 KB | ~12 KB |
| RISC-V (`riscv32imac-unknown-none-elf`) | < 68 KB | ~12 KB |
| Linux x86-64 (std) | — | ~16 KB |

- **CBOR quote size** (Software RoT, no provenance subjects): ~3 700 bytes (dominated by the 3 309-byte ML-DSA-65 signature).
- **Measurement latency**: < 1 ms on Cortex-M4 @ 168 MHz (Software RoT, 64 KB firmware).
- **No heap in the measurement path** — `RoT::measure()` is allocation-free on all backends.

The library uses `lto = true`, `codegen-units = 1`, and `opt-level = 3` in release builds, producing compact output suitable for resource-constrained targets.

---

## Status & Roadmap

### v0.1.0 (current — published to crates.io)

- [x] ML-DSA-65 signing and verification (`MlDsaBackend`)
- [x] ML-KEM-768 key encapsulation (`ml-kem`)
- [x] Software RoT — SHA3-256 PCR banks, firmware hash, AI model hash
- [x] TPM 2.0 backend — hardware PCR read via `tss-esapi` (`hardware-tpm` feature)
- [x] DICE RoT backend — TCG DICE §6 CDI derivation in pure Rust (`dice` feature)
- [x] In-toto / SLSA v1 provenance builder with SBOM hash
- [x] CBOR quote serialisation and roundtrip (`AttestationQuote`)
- [x] Challenge struct with policy ID attachment
- [x] Reference verifier crate (`pqrascv-verifier`)
- [x] Policy evaluation (`PolicyConfig`: SLSA level, quote age, firmware hash)
- [x] `no_std` compatible — `thumbv7em-none-eabi`, `riscv32imac-unknown-none-elf`, `wasm32`
- [x] CI: cross-compilation, feature matrix, TPM integration (swtpm), security audit, MSRV 1.85

### Coming next

- [ ] **Noise_PQX transport** — post-quantum encrypted channel for delivering challenges and quotes
- [ ] **ML-KEM-768 ephemeral key encapsulation** — encrypted quote delivery
- [ ] **AMD SEV-SNP / Intel TDX backends** — confidential VM measurement
- [ ] **CBOR COSE signatures** (RFC 9052) for interoperability with existing attestation verifiers
- [ ] **`heapless` quote assembly** — allocation-free end-to-end path for deeply embedded systems
- [ ] **Stable 1.0 API**

---

## Security Considerations

- **Key storage**: `SigningKeySeed` is 32 bytes and zeroizes on drop. On real devices, store it in a hardware-protected keystore (TPM NV index, TrustZone secure world, eFuse OTP). Never log or transmit the seed.
- **Nonce freshness**: Reusing a nonce breaks replay protection. The verifier must generate a fresh 32-byte nonce for every attestation request and verify it matches the returned quote exactly.
- **Verifying key trust**: `pqrascv-verifier` does not manage a PKI. The caller is responsible for providing a trusted verifying key (e.g., from a provisioning database, certificate chain, or TPM EK). A compromised verifying key invalidates all quotes.
- **DICE CDI confidentiality**: The `cdi` field in `DiceRoT` is the hardware root secret. It must never leave the device. Only the derived `cdi_attestation` (a one-way SHA3-256 hash) is included in quotes.
- **Side channels**: All cryptographic operations use RustCrypto crates that are designed to be constant-time. Do not use `Debug`-printing of key material in production builds.
- **Quote age**: Set `PolicyConfig::max_quote_age_secs` to a short window (e.g. 60–300 s) to limit the validity of captured quotes.
- **Quantum-safe only where it matters**: ML-DSA-65 protects the quote signature. If your transport layer (TLS 1.2, classical ECDH) is not post-quantum, an attacker who records traffic today can decrypt it later ("harvest now, decrypt later"). Pair with a PQ transport (planned in a future release).

---

## Contributing

Issues, bug reports, and pull requests are welcome at [github.com/comwanga/pqrascv-core](https://github.com/comwanga/pqrascv-core).

Before opening a PR, please:

1. Run `cargo fmt --all` and `cargo clippy --all-features -- -D warnings`
2. Add or update tests for any changed behaviour
3. Run `cargo audit` to confirm no new advisories

Areas where contributions are especially valuable:

- **Platform backends**: AMD SEV-SNP, Intel TDX, OP-TEE, Apple Secure Enclave
- **Transport layer**: Noise_PQX, COSE/CBOR signing
- **Tooling**: CLI prover/verifier binary, provisioning helpers
- **Formal verification**: `kani` harnesses for the crypto paths
- **Documentation**: worked examples for Zephyr, Tock, Embassy

If you are using `pqrascv-core` in a project — even experimentally — we'd love to hear about it. Open a GitHub Discussion or reach out directly.

---

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you shall be dual-licensed as above, without any additional terms or conditions.
