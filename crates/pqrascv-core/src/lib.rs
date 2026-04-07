//! # pqrascv-core
//!
//! Post-Quantum Remote Attestation & Supply-Chain Verification (PQ-RASCV) — a `no_std + alloc` Rust library for the prover side.
//!
//! This crate implements a challenge-response remote attestation protocol (inspired by IETF RATS) that binds **firmware measurements** to **supply-chain provenance** and signs everything with **ML-DSA-65** (FIPS 204).
//!
//! ## Problem it solves
//!
//! Traditional attestation (TPM, DICE, etc.) proves *what* is running, but rarely proves *how* the firmware was built or who signed off on it.
//! Classical signatures are also vulnerable to quantum computers.
//!
//! PQ-RASCV combines both in one compact quote:
//! - ML-DSA-65 signatures by default (no RSA/ECDSA)
//! - SLSA v1 + in-toto provenance predicate inside every quote
//! - Works on Cortex-M, RISC-V, WASM, Linux, and other `no_std` environments
//!
//! ## Protocol flow
//!
//! ```text
//! Verifier ───── Challenge { nonce: [u8; 32] } ─────► Prover
//!            ◄────── AttestationQuote (CBOR + ML-DSA-65) ───────
//! ```
//!
//! The prover measures the platform, attaches provenance, signs, and returns the quote.
//!
//! ## Feature flags
//!
//! | Feature         | Default | Description                                      |
//! |-----------------|---------|--------------------------------------------------|
//! | `std`           | yes     | `std::error::Error` impls                        |
//! | `alloc`         | yes     | Required for quote assembly & provenance         |
//! | `hardware-tpm`  | no      | TPM 2.0 backend (requires `tss-esapi`)           |
//! | `dice`          | no      | TCG DICE RoT backend (bare-metal friendly)       |
//!
//! ## Quick start example
//!
//! ```rust
//! use pqrascv_core::{
//!     crypto::{generate_ml_dsa_keypair, MlDsaBackend},
//!     measurement::SoftwareRoT,
//!     provenance::SlsaPredicateBuilder,
//!     quote::generate_quote,
//! };
//!
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
//! let nonce = [0x42u8; 32]; // from verifier
//!
//! let quote = generate_quote(&rot, &MlDsaBackend, sk.as_bytes(), &vk, &nonce, provenance, 0)
//!     .unwrap();
//!
//! let cbor = quote.to_cbor().unwrap();
//! ```
//!
//! See the companion [`pqrascv-verifier`](https://crates.io/crates/pqrascv-verifier) crate for verification logic.
//!
//! ## Main modules
//!
//! - [`measurement`] — `RoT` trait and backends (Software, TPM 2.0, DICE)
//! - [`provenance`] — SLSA v1 / in-toto predicate builder
//! - [`crypto`] — ML-DSA-65 backend (constant-time)
//! - [`quote`] — `AttestationQuote` and `generate_quote` entry point
//! - [`config`] and [`error`] — policy and error types
//!
//! ## Security & usage notes
//!
//! - Protect the signing seed (use hardware keystore in production).
//! - Always use a fresh nonce from the verifier.
//! - Consider post-quantum transport for the channel (classical TLS is vulnerable to store-now-decrypt-later).
//! - Full security considerations are in the repository.
//!
//! ## Repository
//!
//! - GitHub: <https://github.com/comwanga/pqrascv-core>
//! - Contributions welcome (especially new backends, heapless support, formal verification).
//!
//! Licensed under MIT or Apache-2.0.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// Allow missing_errors_doc and missing_panics_doc at module level — every
// public item in this crate does document errors via `# Errors` sections.
#![allow(clippy::missing_errors_doc)]

#[cfg(feature = "alloc")]
extern crate alloc;

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
