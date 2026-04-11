//! # pqrascv-core
//!
//! A `no_std + alloc` Rust library for issuing post-quantum attestation quotes on embedded
//! devices, IoT firmware, cloud orchestrators, and AI agents.
//!
//! Every quote is signed with **ML-DSA-65 (FIPS 204)** and carries a **SLSA v1 / in-toto
//! provenance predicate** — binding the device's firmware identity to its build pipeline in
//! a single compact CBOR message, on bare-metal Cortex-M4, RISC-V, WASM, or Linux.
//!
//! ## Why PQ-RASCV?
//!
//! Traditional attestation tells you *what* is running. It doesn't tell you *how* the firmware
//! was built, *who* signed it off, or whether the build pipeline was compromised. Classical
//! signatures (RSA, ECDSA) also won't survive a cryptographically-relevant quantum computer.
//!
//! PQ-RASCV fixes both in one library:
//! - **Post-quantum by default** — ML-DSA-65 signatures, no RSA or ECDSA anywhere.
//! - **Supply-chain provenance** — SLSA v1 predicate + SBOM hash inside every signed quote.
//! - **One API everywhere** — Cortex-M4, RISC-V, WASM, Linux, all using the same code.
//!
//! ## How it works
//!
//! The verifier sends a random nonce; the prover measures its firmware, attaches provenance,
//! signs everything, and sends back a CBOR quote:
//!
//! ```text
//! Verifier ───── Challenge { nonce: [u8; 32] } ─────► Prover
//!            ◄────── AttestationQuote (CBOR + ML-DSA-65 signature) ───────
//! ```
//!
//! ## Feature flags
//!
//! | Feature        | Default | What it does                                                   |
//! |----------------|---------|----------------------------------------------------------------|
//! | `std`          | yes     | Enables `std::error::Error` on the error type                  |
//! | `alloc`        | yes     | Required for building quotes and provenance predicates         |
//! | `hardware-tpm` | no      | Reads PCR values from a real TPM 2.0 chip (Linux only)        |
//! | `dice`         | no      | DICE CDI derivation backend — pure Rust, no OS required        |
//!
//! ## Quick start
//!
//! ```rust
//! # #[cfg(all(feature = "std", feature = "alloc"))]
//! # {
//! use pqrascv_core::{
//!     crypto::{generate_ml_dsa_keypair, MlDsaBackend},
//!     measurement::SoftwareRoT,
//!     provenance::SlsaPredicateBuilder,
//!     quote::generate_quote,
//! };
//!
//! // Keep the signing seed secret — store it in a hardware keystore on real devices.
//! let (sk, vk) = generate_ml_dsa_keypair().unwrap();
//!
//! let rot = SoftwareRoT::new(b"my-firmware", None, 1);
//!
//! let provenance = SlsaPredicateBuilder::new("https://ci.example.com/pipeline/42")
//!     .add_subject("firmware.bin", &[0xabu8; 32])
//!     .with_slsa_level(2)
//!     .build()
//!     .unwrap();
//!
//! let nonce = [0x42u8; 32]; // received from the verifier's Challenge
//!
//! let quote = generate_quote(
//!     &rot,
//!     &MlDsaBackend,
//!     sk.as_bytes(),
//!     &vk,
//!     &nonce,
//!     provenance,
//!     0, // Unix timestamp — pass 0 if the device has no real-time clock
//! )
//! .unwrap();
//!
//! let cbor_bytes = quote.to_cbor().unwrap(); // send this to the verifier
//! # }
//! ```
//!
//! Send `cbor_bytes` to a verifier. See [`pqrascv-verifier`](https://crates.io/crates/pqrascv-verifier)
//! for the verification side.
//!
//! ## Modules
//!
//! - [`measurement`] — the `RoT` trait and backends (Software SHA3-256, TPM 2.0, DICE)
//! - [`provenance`] — builds SLSA v1 predicates and in-toto attestations
//! - [`crypto`] — ML-DSA-65 sign and verify, all constant-time via RustCrypto
//! - [`quote`] — assembles and serializes an `AttestationQuote`; `generate_quote` is the main entry point
//! - [`config`] — policy settings: minimum SLSA level, max quote age, firmware hash requirements
//! - [`error`] — the single `PqRascvError` type used throughout the crate
//! - [`backends`] — optional hardware backends gated behind feature flags
//!
//! ## Security notes
//!
//! - **Keep the seed secret.** Store it in a TPM NV slot, eFuse, or TrustZone keystore — not in flash.
//! - **Use a fresh nonce every time.** Reusing a nonce breaks replay protection.
//! - **Use a post-quantum transport.** ML-DSA-65 protects the signature, but classical TLS is
//!   still vulnerable to "harvest now, decrypt later" attacks. Pair with a PQ transport when you can.
//! - See the repository README for the full security considerations.
//!
//! ## Contributing
//!
//! Issues, PRs, and feedback are welcome at <https://github.com/comwanga/pqrascv-core>.
//! Areas where contributions are especially valuable:
//! - **New platform backends** — SEV-SNP, TDX, OP-TEE, Apple Secure Enclave
//! - **Allocation-free quote assembly** — removing the `alloc` requirement entirely
//! - **Post-quantum transport** — Noise\_PQX or COSE/CBOR signing integration
//! - **Formal verification** — Kani harnesses and fuzzing coverage
//!
//! Licensed under either MIT or Apache-2.0 at your option.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// Allow missing_errors_doc and missing_panics_doc at module level — every
// public item in this crate does document errors via `# Errors` sections.
#![allow(clippy::missing_errors_doc)]

pub mod backends;
pub mod config;
pub mod crypto;
pub mod error;
pub mod measurement;
pub mod provenance;
pub mod quote;

// ── Convenience re-exports ───────────────────────────────────────────────────

pub use config::PolicyConfig;
pub use error::PqRascvError;

#[cfg(feature = "alloc")]
pub use quote::{generate_quote, AttestationQuote, Challenge};
