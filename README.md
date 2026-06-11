<div align="center">

# pqrascv-core

**Post-Quantum Remote Attestation & Supply-Chain Verification**

[![Crates.io](https://img.shields.io/crates/v/pqrascv-core.svg)](https://crates.io/crates/pqrascv-core)
[![docs.rs](https://docs.rs/pqrascv-core/badge.svg)](https://docs.rs/pqrascv-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![no\_std](https://img.shields.io/badge/no__std-compatible-green.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)
[![CI](https://github.com/comwanga/pqrascv-core/actions/workflows/ci.yml/badge.svg)](https://github.com/comwanga/pqrascv-core/actions/workflows/ci.yml)

*Hardware-rooted · supply-chain-verified · post-quantum signed — everywhere Rust runs.*

</div>

---

`pqrascv-core` is a `no_std + alloc` Rust library for issuing and verifying tamper-evident device attestation quotes. Every quote is signed with **ML-DSA-65 (FIPS 204)** and carries a **SLSA v1 provenance predicate** binding a device's firmware identity to its build pipeline — on bare-metal Cortex-M4, RISC-V, WASM, or Linux.

## Why PQ-RASCV?

Traditional attestation proves *what* is running but not *how* it was built or *who* signed it off. Classical signatures (RSA, ECDSA) are also broken by Shor's algorithm. PQ-RASCV fixes both:

- **Post-quantum by default** — ML-DSA-65 signatures, no RSA or ECDSA in the protocol
- **Supply-chain provenance** — SLSA v1 predicate + SBOM hash inside every signed quote
- **One API everywhere** — Cortex-M4, RISC-V, WASM, Linux, all using the same code
- **`no_std + alloc`** — works on bare-metal without an OS

---

## Add to your project

```toml
# std (default)
pqrascv-core = "1.0.0-rc.8"

# bare-metal / no_std
pqrascv-core = { version = "1.0.0-rc.8", default-features = false, features = ["alloc"] }
```

---

## CLI — fastest way to try it

```bash
cargo install pqrascv-cli

# Generate a keypair
pqrascv keygen --out-seed seed.bin --out-vk vk.bin

# Generate an attestation quote (prover side)
pqrascv attest \
  --seed seed.bin --vk vk.bin \
  --firmware firmware.bin \
  --slsa-level 2 \
  --out quote.cbor \
  --software-rot-acknowledged

# Verify the quote (verifier side) — use the nonce printed by attest
pqrascv verify \
  --vk vk.bin \
  --quote quote.cbor \
  --nonce <64-HEX-NONCE> \
  --json
```

---

## Library usage

### Prover (device side)

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

let nonce = [0x42u8; 32]; // received from the verifier

let quote = generate_quote(
    &rot, &MlDsaBackend, sk.as_bytes(), &vk,
    &nonce, provenance, QuoteTimestamp::Rtc(1_700_000_000),
).unwrap();

let cbor_bytes = quote.to_cbor().unwrap(); // send to verifier
```

### Verifier (server side)

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

### Python

```bash
# Build the extension
cd crates/pqrascv-python && maturin develop --features extension-module
```

```python
import pqrascv_python

key = pqrascv_python.MlDsaKey.generate()
vk  = key.verifying_key_bytes()           # 1952 bytes
sig = key.sign(b"hello attestation")      # 3309 bytes
assert pqrascv_python.MlDsaKey.verify(vk, b"hello attestation", sig)
```

### C / Embedded

```c
#include "include/pqrascv.h"

unsigned char sk[32], vk[1952], sig[3309];
size_t sk_len = sizeof(sk), vk_len = sizeof(vk), sig_len = sizeof(sig);

pqrascv_generate_keypair(sk, &sk_len, vk, &vk_len);
pqrascv_sign(sk, sk_len, (uint8_t*)"msg", 3, sig, &sig_len);
assert(pqrascv_verify(vk, vk_len, (uint8_t*)"msg", 3, sig, sig_len) == PQRASCV_OK);
```

```bash
cargo build -p pqrascv-ffi   # generates include/pqrascv.h + libpqrascv_ffi.{so,a}
```

---

## How it works

PQ-RASCV is a **challenge–response** protocol. The verifier drives; the prover measures, attests, and signs:

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
   ├── check nonce + pub_key_id fingerprint
   └── evaluate PolicyConfig → accept / reject
```

Each quote carries: protocol version, timestamp, nonce, 8 × SHA3-256 PCRs, firmware hash, SLSA v1 predicate, and a 3 309-byte ML-DSA-65 signature. Wire size: ~3.7 KB CBOR.

---

## Feature flags

| Feature | Default | What it enables |
|---------|---------|-----------------|
| `std` | yes | `std::error::Error` on the error type |
| `alloc` | yes | Quote and provenance assembly |
| `hardware-tpm` | no | TPM 2.0 PCR reads via `tss-esapi` (Linux) |
| `dice` | no | DICE CDI derivation — pure Rust, no OS required |
| `software-rot-unsafe` | no | Software SHA3-256 RoT — **testing only** |

---

## Measurement backends

| Backend | Feature | Status |
|---------|---------|--------|
| `SoftwareRoT` | `software-rot-unsafe` | Testing / demo only — rejected by `PolicyEngineV2::production()` |
| `TpmRoT` | `hardware-tpm` | Production — requires `tpm2-tss` system library (Linux) |
| `DiceRoT` | `dice` | Production — pure Rust, suitable for MCU boot chains |
| `TdxRoT` | `intel-tdx` | Experimental — Linux kernel ≥ 5.19, `/dev/tdx_guest` |
| `SevSnpRoT` | `amd-sev-snp` | Experimental — Linux kernel ≥ 5.19, `/dev/sev-guest` |

---

## Security considerations

- **Keep the seed secret.** Store it in a TPM NV slot, eFuse, or TrustZone keystore — not in flash.
- **Use a fresh nonce every request.** Reusing a nonce breaks replay protection.
- **Set `max_quote_age_secs`** to 60–300 s to bound the validity window of captured quotes.
- **`SoftwareRoT` is test-only.** `PolicyEngineV2::production()` rejects it; the CLI requires `--software-rot-acknowledged`.
- **Post-quantum transport.** ML-DSA-65 protects the signature. Pair with a PQ transport (Noise\_PQX / COSE Sign1) to close the channel against "harvest now, decrypt later".

See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy.

---

## Status — v1.0.0-rc.8

API is stabilizing. The `ml-dsa` crate is pinned to `=0.1.0-rc.8` (FIPS-final algorithm, pre-stable Rust crate). The stable 1.0 release will follow the first stable `ml-dsa` ≥ `0.1.0`.

| Ready | Experimental |
|-------|-------------|
| ML-DSA-65 sign / verify | Intel TDX backend |
| Software / TPM 2.0 / DICE backends | AMD SEV-SNP backend |
| SLSA v1 provenance + SBOM hash | Sigstore `verify_all` (1-hop Fulcio + SET-based Rekor) |
| CBOR-native PKI (Root CA → Device) | OP-TEE, Apple Secure Enclave backends |
| CRL revocation, CA rollover (`TrustStore`) | |
| `PolicyEngineV2` composable rule engine | |
| Bitcoin OP\_RETURN anchoring + Merkle / SPV proofs | |
| COSE Sign1 (RFC 9052) + Noise\_PQX transport | |
| CLI (`pqrascv attest` / `pqrascv verify`) | |
| Python bindings (PyO3 0.24) | |
| C FFI + `include/pqrascv.h` | |
| Kani formal verification (4 harnesses) | |
| Fuzz targets (7) | |

---

## Contributing

```bash
git clone https://github.com/comwanga/pqrascv-core.git && cd pqrascv-core
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for coding standards and the review process.
Issues and PRs are welcome at [github.com/comwanga/pqrascv-core](https://github.com/comwanga/pqrascv-core).

---

## License

MIT OR Apache-2.0 at your option.
