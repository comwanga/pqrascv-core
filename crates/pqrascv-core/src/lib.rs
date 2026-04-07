//! # pqrascv-core
//!
//! **Post-Quantum Remote Attestation & Supply-Chain Verification (PQ-RASCV)** — a `no_std + alloc` Rust library for the prover side.
//!
//! This crate implements the prover side of a challenge-response remote attestation protocol inspired by IETF RATS.
//! It binds firmware/platform measurements to cryptographically verifiable supply-chain provenance (SLSA v1 + in-toto)
//! and signs the entire quote with **ML-DSA-65** (FIPS 204).
//!
//! ## Why PQ-RASCV?
//!
//! Traditional attestation solutions prove *what* is running, but rarely prove *how* the firmware was built or who approved the build.
//! Classical signatures (RSA/ECDSA) are also vulnerable to future quantum computers.
//!
//! PQ-RASCV solves both problems in one compact, embedded-friendly package:
//! - ML-DSA-65 signatures by default (no fallback to RSA/ECDSA)
//! - SLSA v1 + in-toto provenance predicate embedded in every quote
//! - Same API across Cortex-M, RISC-V, WASM, Linux, and other `no_std` targets
//!
//! ## Protocol flow
//!
//! ```text
//! Verifier ───── Challenge { nonce: [u8; 32] } ─────► Prover
//!            ◄────── AttestationQuote (CBOR + ML-DSA-65 signature) ───────
//! ```
//!
//! The prover collects measurements, attaches provenance, assembles the quote, signs it, and returns the CBOR bytes.
//!
//! ## Feature flags
//!
//! | Feature        | Default | Description                                              |
//! |----------------|---------|----------------------------------------------------------|
//! | `std`          | yes     | Enables `std::error::Error` impls                        |
//! | `alloc`        | yes     | Required for quote assembly and provenance               |
//! | `hardware-tpm` | no      | TPM 2.0 measurement backend (Linux only, requires `tss-esapi`) |
//! | `dice`         | no      | TCG DICE `RoT` backend (pure Rust, bare-metal friendly)  |
//!
//! ## Quick start
//!
//! ```rust
//! use pqrascv_core::{
//!     crypto::{generate_ml_dsa_keypair, MlDsaBackend},
//!     measurement::SoftwareRoT,
//!     provenance::SlsaPredicateBuilder,
//!     quote::generate_quote,
//! };
//!
//! // Generate ML-DSA-65 keypair (protect the seed in production!)
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
//! let nonce = [0x42u8; 32]; // supplied by the verifier
//!
//! let quote = generate_quote(
//!     &rot,
//!     &MlDsaBackend,
//!     sk.as_bytes(),
//!     &vk,
//!     &nonce,
//!     provenance,
//!     0, // protocol version
//! )
//! .unwrap();
//!
//! let cbor_bytes = quote.to_cbor().unwrap();
//! ```
//!
//! The resulting `cbor_bytes` can be sent to a verifier. See the companion
//! [`pqrascv-verifier`](https://crates.io/crates/pqrascv-verifier) crate for verification logic.
//!
//! ## Main modules
//!
//! - [`measurement`] — `RoT` trait + backends (Software, TPM 2.0, DICE)
//! - [`provenance`] — SLSA v1 / in-toto predicate builder
//! - [`crypto`] — ML-DSA-65 abstraction (constant-time via `RustCrypto`)
//! - [`quote`] — `AttestationQuote` and the main `generate_quote` entry point
//! - [`config`] — policy configuration (re-exported)
//! - [`error`] — error types
//! - [`backends`] — optional hardware-specific backends
//!
//! ## Security & usage notes
//!
//! - Store the signing seed in a hardware-protected location (TPM NV, eFuse, `TrustZone`, etc.).
//! - Always use a fresh nonce supplied by the verifier for replay protection.
//! - Pair with a post-quantum transport layer when possible (classical TLS is vulnerable to "harvest now, decrypt later").
//! - See the repository for full security considerations.
//!
//! ## Repository & contributing
//!
//! - GitHub: <https://github.com/comwanga/pqrascv-core>
//! - Contributions are welcome! Especially valued:
//!   - Additional platform backends (SEV-SNP, OP-TEE, etc.)
//!   - Heapless / fully allocation-free quote assembly
//!   - Formal verification (Kani, fuzzing) and audits
//!   - `Noise_PQX` or COSE integration
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
