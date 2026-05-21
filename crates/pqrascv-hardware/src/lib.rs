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
pub mod baseline;
pub mod boot_chain;
pub mod continuous_attestation;
pub mod counter;
pub mod digest;
pub mod drift;
pub mod ek_framework;
pub mod ima_integration;
pub mod pcr;
pub mod platform_profiles;
pub mod policy;
pub mod profiles;
pub mod runtime_attestation;
pub mod runtime_drift;
pub mod runtime_integrity;
pub mod secure_boot;
pub mod tpm_structures;
pub mod tpm_verify;
pub mod transparency_log;
pub mod trust_domains;
pub mod verifier_timeline;
pub mod workload_integrity;

// ── Convenience re-exports ────────────────────────────────────────────────

pub use backend::{
    BackendSpecificEvidence, DiceEvidence, HardwareBackendType, HardwareCapabilities,
    HardwareError, HardwareEvidence, HardwareRootOfTrust, NitroEnclaveEvidence, SevSnpEvidence,
    TdxEvidence, TpmClockInfo, TpmIdentity, TpmQuoteEvidence,
};
pub use baseline::{ExpectedPcr, PcrBaseline, PolicyVersion};
pub use boot_chain::BootChainEvidence;
pub use continuous_attestation::{AttestationSession, SessionError};
pub use counter::CounterEvidence;
pub use digest::{DigestAlgorithm, TypedDigest};
pub use drift::{DriftDetectionEngine, DriftPolicyMode, DriftReport, DriftSeverity};
pub use ima_integration::{ImaEvidence, ImaMeasurement, ImaParseError};
pub use pcr::{PcrMeasurement, PcrSemantic, SlotSemanticMismatch, TypedPcrBank};
pub use platform_profiles::{
    PlatformClass, PlatformProfile, PlatformVendor, PlatformVerificationReport,
    RuntimeVerificationReport,
};
pub use policy::{
    HardwarePolicyContext, HardwarePolicyEngine, HardwarePolicyError, HardwarePolicyRule,
};
pub use profiles::sovereign_bitcoin_node_profile;
pub use runtime_attestation::{
    RuntimeAttestationEvidence, RuntimeMeasurement, RuntimeMeasurementDomain, RuntimePolicyEpoch,
};
pub use runtime_drift::{RuntimeDriftEngine, RuntimeDriftReport, RuntimeDriftSeverity};
pub use runtime_integrity::RuntimeIntegrityEvidence;
pub use secure_boot::{SecureBootEvidence, SecureBootState};
pub use tpm_verify::{TpmQuoteVerifier, TpmVerifyError};
pub use transparency_log::TransparencyEvent;
pub use trust_domains::{TrustDomain, TrustEvaluation, VerificationDecisionReason};
pub use verifier_timeline::{AttestationEvent, AttestationTimeline, TimelineValidationError};
pub use workload_integrity::{WorkloadIdentity, WorkloadIntegrityEvidence};
