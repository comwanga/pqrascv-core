//! # pqrascv-core
//!
//! **Post-Quantum Remote Attestation & Supply-Chain Verification (PQ-RASCV)**
//! prover core — a `no_std + alloc` Rust library.
//!
//! ## Overview
//!
//! This crate implements the prover side of the PQ-RASCV challenge-response
//! protocol (IETF RATS-inspired):
//!
//! ```text
//! Verifier ──── Challenge { nonce } ────► Prover
//!          ◄─── AttestationQuote (CBOR) ──
//! ```
//!
//! The verifier sends a 32-byte random nonce.  The prover:
//!
//! 1. Collects platform measurements via a [`measurement::RoT`] backend.
//! 2. Attaches in-toto / SLSA provenance via [`provenance::InTotoAttestation`].
//! 3. Assembles and ML-DSA-65 signs a [`quote::AttestationQuote`].
//! 4. Returns the CBOR-encoded quote to the verifier.
//!
//! ## Feature flags
//!
//! | Flag | Default | Purpose |
//! |------|---------|---------|
//! | `std` | **yes** | Link against std, enable `std::error::Error` impls |
//! | `alloc` | **yes** | Heap allocation (required for quote assembly) |
//! | `hardware-tpm` | no | TPM 2.0 measurement backend |
//! | `dice` | no | DICE RoT measurement backend |
//!
//! ## Quick start
//!
//! ```rust,no_run
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
//! let provenance = SlsaPredicateBuilder::new("https://ci.example.com")
//!     .add_subject("fw.bin", &[0xabu8; 32])
//!     .with_slsa_level(2)
//!     .build()
//!     .unwrap();
//!
//! let nonce = [0x42u8; 32]; // from verifier's Challenge
//! let quote = generate_quote(&rot, &MlDsaBackend, sk.as_bytes(), &vk, &nonce, provenance, 0).unwrap();
//! let cbor = quote.to_cbor().unwrap();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
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
