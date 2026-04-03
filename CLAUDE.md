# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**pqrascv-core** — Post-Quantum Remote Attestation & Supply-Chain Verification (PQ-RASCV) protocol implementation in Rust. A `no_std`-first library for verifiable, supply-chain-aware remote attestation on embedded devices, IoT firmware, cloud orchestrators, and AI agents.

Protocol model: verifier sends a nonce challenge → prover returns a CBOR-encoded, ML-DSA-65-signed `AttestationQuote` with embedded in-toto provenance.

## Build Commands

```bash
# Standard build
cargo build

# no_std embedded build (ARM Cortex-M)
cargo build --no-default-features --target thumbv7em-none-eabi -p pqrascv-core

# WebAssembly
cargo build --no-default-features --target wasm32-unknown-unknown -p pqrascv-core

# All features
cargo build --all-features
```

## Test Commands

```bash
# All tests
cargo test

# Single test
cargo test <test_name>

# no_std host tests (no allocator)
cargo test --no-default-features -p pqrascv-core

# All feature combinations
cargo test --all-features

# Miri (UB detection)
cargo miri test --no-default-features -p pqrascv-core

# Fuzzing
cargo fuzz run quote_roundtrip
```

## Lint & Security

```bash
# Clippy (pedantic — zero warnings allowed)
cargo clippy --all-features -- -D warnings

# Dependency audit
cargo audit

# Dependency policy
cargo deny check

# Formal verification (crypto paths)
cargo kani
```

## Workspace Layout

```
pqrascv-core/
├── Cargo.toml                   # workspace root
├── crates/
│   ├── pqrascv-core/            # primary no_std prover crate
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── crypto.rs        # CryptoBackend trait + ML-DSA-65 impl
│   │       ├── measurement.rs   # RoT trait + Measurements struct
│   │       ├── provenance.rs    # InTotoAttestation + SLSA builder
│   │       ├── quote.rs         # AttestationQuote + generate_quote()
│   │       ├── config.rs        # PolicyConfig (const-friendly)
│   │       ├── error.rs         # PqRascvError (no_std)
│   │       └── backends/        # feature-gated: software, tpm, dice
│   └── verifier/                # reference verifier (std-only)
└── .github/workflows/ci.yml
```

## Architecture

### Layered Design

1. **Crypto Layer** (`crypto.rs`): `CryptoBackend` trait abstracting ML-DSA-65 sign/verify and ML-KEM-768 encapsulation. Default impl uses `ml-dsa`/`ml-kem` from RustCrypto. Constant-time guaranteed; all key material is `zeroize`-on-drop.

2. **Measurement Layer** (`measurement.rs`): `RoT` trait — `fn measure(&self) -> Result<Measurements, PqRascvError>`. `Measurements` holds PCR-style hash banks, code hashes, and AI model digests. Backends are feature-gated (`hardware-tpm`, `dice`); default is `SoftwareRoT` (SHA3-256 over memory regions).

3. **Provenance Layer** (`provenance.rs`): Builds SLSA v1 predicates and in-toto link metadata as `InTotoAttestation`. Embeds SBOM hashes. This is our own struct (serialized to CBOR) rather than a heavy external crate.

4. **Quote Assembly** (`quote.rs`): `AttestationQuote` (CBOR-serializable via serde + ciborium). `generate_quote<R: RoT, C: CryptoBackend>()` is the public entry point. Requires `alloc`.

### Feature Flags

| Feature | Default | Purpose |
|---------|---------|---------|
| `std` | yes | Links std, enables `std` I/O |
| `alloc` | yes (with std) | Enables `Vec`/`String`; required for `AttestationQuote` |
| `hardware-tpm` | no | TPM 2.0 backend |
| `dice` | no | DICE RoT backend |

### Key Constraints

- `#![deny(clippy::all, clippy::pedantic)]` — zero lint warnings
- No `unsafe` without block comment justifying it
- All PQ operations must be constant-time (ensured by RustCrypto crates)
- `PqRascvError` must never allocate (no heap in error path)
- Quote target size: <600 bytes on constrained devices (note: ML-DSA-65 sigs are ~3309 bytes; this target applies to non-signature payload only)
