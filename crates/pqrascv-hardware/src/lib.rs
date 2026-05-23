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
//! | [`audit_trace`] | Cryptographically linked, append-only lineage of evaluation events |
//! | [`invariants`] | System-wide assertions to prevent Byzantine violations and equivocation |
//! | [`consistency_checker`] | Full divergence drift validation for the global audit trace |
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

pub mod attested_node_report;
pub mod audit_trace;
pub mod backend;
pub mod baseline;
pub mod bitcoin_node_identity;
pub mod bitcoin_node_timeline;
pub mod bitcoin_policy_profiles;
pub mod bitcoin_runtime_monitor;
pub mod consistency_checker;
pub mod invariants;

pub mod bitcoin_workload_integrity;
pub mod boot_chain;
pub mod continuous_attestation;
pub mod counter;
pub mod deployment_reference;
pub mod digest;
pub mod distributed_consensus;
pub mod drift;
#[cfg(test)]
mod proptests;

// Phase 3.1 Live Evidence Modules
#[cfg(feature = "live-evidence")]
pub mod attestation_transport;
#[cfg(feature = "live-evidence")]
pub mod bitcoin_process_monitor;
#[cfg(feature = "live-evidence")]
pub mod evidence_cache;
#[cfg(feature = "live-evidence")]
pub mod evidence_pipeline;
#[cfg(feature = "live-evidence")]
pub mod freshness;
#[cfg(feature = "live-evidence")]
pub mod linux_ima_collector;
#[cfg(feature = "live-evidence")]
pub mod live_node_observer;
#[cfg(feature = "live-evidence")]
pub mod live_tpm;
#[cfg(feature = "live-evidence")]
pub mod secure_boot_collector;

// Phase 3.2 Incremental Runtime Integrity & PQ Transport
pub mod checkpointing;
pub mod delta_attestation;
pub mod federation_transport;
pub mod pq_transport;
pub mod retention_policy;
pub mod runtime_stream;
pub mod stream_reconciliation;
pub mod timeline_compaction;

// Phase 3.3 Byzantine Federation Convergence
pub mod byzantine_quorum;
pub mod cross_federation;
pub mod epoch_key_binding;
pub mod equivocation;
pub mod federation_sync;
pub mod federation_time;
pub mod federation_topology;
pub mod governance_continuity;
pub mod retention_governance;
pub mod verifier_revocation;

// Phase 3.5 Infrastructure Resilience
pub mod deterministic_replay;
pub mod disaster_recovery;
pub mod federation_migration;
pub mod federation_snapshot;
pub mod partition_detection;
pub mod partition_healing;
pub mod quorum_reformation;
pub mod recovery_governance;
pub mod recovery_lineage;
pub mod verifier_rejoin;

// Phase 3.6 Adaptive Federation Synchronization
pub mod adaptive_sync;
pub mod canonicalization;
pub mod eclipse_resistance;
pub mod federation_liveness;
pub mod gossip_protocol;
pub mod hashing;

pub mod network_governance;
pub mod peer_reputation;
pub mod snapshot_sync;
pub mod state_reconstruction;

pub mod ima_integration;
pub mod linux_ima_collector;
pub mod node_attestation_session;
pub mod pcr;
pub mod platform_profiles;
pub mod policy;
pub mod policy_federation;

pub mod ek_framework;
pub mod governance;
pub mod profiles;
pub mod reputation;
pub mod runtime_attestation;
pub mod runtime_drift;
pub mod runtime_integrity;
pub mod secure_boot;
pub mod temporal_ambiguity;
pub mod timeline_reconciliation;
pub mod tpm_structures;
pub mod tpm_verify;
pub mod transparency_log;
pub mod trust_domains;
pub mod verifier_federation;
pub mod verifier_identity;
pub mod verifier_orchestrator;
pub mod verifier_timeline;
pub mod verifier_transparency;
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
pub use distributed_consensus::{ConsensusDecision, ConsensusEvaluation, VerifierVote};
pub use drift::{DriftDetectionEngine, DriftPolicyMode, DriftReport, DriftSeverity};
pub use governance::{GovernanceAction, GovernanceError, GovernanceLog, GovernanceRecord};
pub use ima_integration::{ImaEvidence, ImaMeasurement, ImaParseError};
pub use pcr::{PcrMeasurement, PcrSemantic, SlotSemanticMismatch, TypedPcrBank};
pub use platform_profiles::{
    PlatformClass, PlatformProfile, PlatformVendor, PlatformVerificationReport,
    RuntimeVerificationReport,
};
pub use policy::{
    HardwarePolicyContext, HardwarePolicyEngine, HardwarePolicyError, HardwarePolicyRule,
};
pub use policy_federation::{FederatedPolicyEpoch, FederatedPolicyError, FederatedPolicyRegistry};
pub use profiles::sovereign_bitcoin_node_profile;
pub use reputation::VerifierReputation;
pub use runtime_attestation::{
    RuntimeAttestationEvidence, RuntimeMeasurement, RuntimeMeasurementDomain, RuntimePolicyEpoch,
};
pub use runtime_drift::{RuntimeDriftEngine, RuntimeDriftReport, RuntimeDriftSeverity};
pub use runtime_integrity::RuntimeIntegrityEvidence;
pub use secure_boot::{SecureBootEvidence, SecureBootState};
pub use timeline_reconciliation::{
    TimelineConflict, TimelineConflictType, TimelineReconciler, TimelineReconciliationReport,
};
pub use tpm_verify::{TpmQuoteVerifier, TpmVerifyError};
pub use transparency_log::TransparencyEvent;
pub use trust_domains::{TrustDomain, TrustEvaluation, VerificationDecisionReason};
pub use verifier_federation::{FederationError, QuorumPolicy, VerifierFederation};
pub use verifier_identity::{
    CertificateError, IdentityError, VerifierCapability, VerifierCertificate, VerifierIdentity,
};
pub use verifier_timeline::{AttestationEvent, AttestationTimeline, TimelineValidationError};
pub use verifier_transparency::{
    TransparencyLogError, VerifierEventType, VerifierTransparencyEvent, VerifierTransparencyLog,
};
pub use workload_integrity::{WorkloadIdentity, WorkloadIntegrityEvidence};
