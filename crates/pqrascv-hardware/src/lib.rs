//! # pqrascv-hardware
//!
//! Hardware trust validation layer for PQ-RASCV v2.
//!
//! This crate provides the typed abstractions, verification logic, and policy
//! rules for hardware-rooted attestation. It is the bridge between raw hardware
//! evidence (TPM quotes, DICE CDIs, TDX reports) and the policy engine.
//!
//! ## Module Overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`digest`] | Typed digest model — eliminates SHA-256/SHA3-256 ambiguity |
//! | [`pcr`] | PCR semantic specification — canonical slot meanings |
//! | [`counter`] | Hardware monotonic counter evidence |
//! | [`backend`] | Hardware backend trait and evidence types |
//! | [`tpm_verify`] | TPM 2.0 quote structural verification |
//! | [`policy`] | Hardware-aware policy rules |
//!
//! ## Trust Model
//!
//! ```text
//! Hardware (TPM/DICE/TDX/SEV-SNP)
//!   └── HardwareRootOfTrust::collect_evidence(nonce)
//!         └── HardwareEvidence { backend_type, pcr_bank, counter, ... }
//!               └── TpmQuoteVerifier::verify_structure(...)
//!                     └── HardwarePolicyEngine::evaluate(...)
//!                           └── Ok(()) → evidence is trustworthy
//! ```
//!
//! ## Feature Flags
//!
//! | Feature | Effect |
//! |---------|--------|
//! | `std` (default) | Enables `std::error::Error` on error types |
//! | `unsafe-test-backend` | Enables `HardwareBackendType::TestOnly` — NEVER in production |
//!
//! ## Security Invariants
//!
//! 1. `HardwareBackendType::TestOnly` is only constructible with `unsafe-test-backend`.
//! 2. All PCR digests in `TypedPcrBank` must be SHA3-256 before policy evaluation.
//! 3. `TpmQuoteVerifier` checks nonce binding FIRST, before any other validation.
//! 4. `HardwarePolicyEngine::hardware_production()` rejects non-hardware-rooted backends.
//! 5. `CounterEvidence::HardwareMonotonic` is the only counter variant accepted by
//!    `RequireHardwareMonotonicCounter`.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

extern crate alloc;

pub mod backend;
pub mod counter;
pub mod digest;
pub mod pcr;
pub mod policy;
pub mod tpm_structures;
pub mod tpm_verify;
pub mod ek_framework;
pub mod secure_boot;
pub mod boot_chain;
pub mod runtime_integrity;
pub mod baseline;
pub mod drift;
pub mod platform_profiles;
pub mod profiles;

// ── Convenience re-exports ────────────────────────────────────────────────

pub use backend::{
    BackendSpecificEvidence, DiceEvidence, HardwareBackendType, HardwareCapabilities,
    HardwareError, HardwareEvidence, HardwareRootOfTrust, NitroEnclaveEvidence, SevSnpEvidence,
    TdxEvidence, TpmClockInfo, TpmIdentity, TpmQuoteEvidence,
};
pub use counter::CounterEvidence;
pub use digest::{DigestAlgorithm, TypedDigest};
pub use pcr::{PcrMeasurement, PcrSemantic, SlotSemanticMismatch, TypedPcrBank};
pub use policy::{HardwarePolicyContext, HardwarePolicyEngine, HardwarePolicyError, HardwarePolicyRule};
pub use tpm_verify::{TpmQuoteVerifier, TpmVerifyError};
pub use secure_boot::{SecureBootState, SecureBootEvidence};
pub use boot_chain::BootChainEvidence;
pub use runtime_integrity::RuntimeIntegrityEvidence;
pub use baseline::{PolicyVersion, ExpectedPcr, PcrBaseline};
pub use drift::{DriftSeverity, DriftPolicyMode, DriftReport, DriftDetectionEngine};
pub use platform_profiles::{PlatformClass, PlatformVendor, PlatformProfile, VerificationDecisionReason, PlatformVerificationReport};
pub use profiles::sovereign_bitcoin_node_profile;
