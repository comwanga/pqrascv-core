extern crate alloc;
use alloc::vec::Vec;

use crate::{
    backend::HardwareBackendType,
    baseline::PcrBaseline,
    boot_chain::BootChainEvidence,
    continuous_attestation::AttestationSession,
    counter::CounterEvidence,
    digest::TypedDigest,
    distributed_consensus::ConsensusEvaluation,
    drift::DriftPolicyMode,
    ima_integration::ImaEvidence,
    pcr::{PcrSemantic, TypedPcrBank},
    platform_profiles::PlatformProfile,
    policy_federation::FederatedPolicyEpoch,
    runtime_attestation::RuntimeAttestationEvidence,
    secure_boot::{SecureBootEvidence, SecureBootState},
    timeline_reconciliation::TimelineReconciliationReport,
    transparency_log::TransparencyEvent,
    verifier_federation::VerifierFederation,
    verifier_timeline::AttestationTimeline,
};
use pqrascv_bitcoin_anchor::{TimelineInclusionProof, TimelineSpvVerifier};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum HardwarePolicyRule {
    /// Reject evidence from backends that are not hardware-rooted.
    ///
    /// Rejects `TestOnly` unconditionally. Accepts `Tpm2`, `Dice`,
    /// `IntelTdx`, `AmdSevSnp`, `NitroEnclave`.
    RequireHardwareRootedBackend,

    /// Reject evidence from backends other than the specified type.
    ///
    /// Use when a deployment requires a specific hardware technology
    /// (e.g. only TPM 2.0 is accepted).
    RequireBackendType(HardwareBackendType),

    /// Reject evidence where the PCR bank is not fully normalized to SHA3-256.
    ///
    /// This rule catches backends that forgot to normalize TPM SHA-256 PCRs.
    RequireNormalizedPcrs,

    /// Reject evidence where a required PCR semantic is absent.
    ///
    /// Use to enforce that specific boot stages were measured.
    RequirePcrSemantic(PcrSemantic),

    /// Reject evidence where a PCR semantic's value does not match.
    ///
    /// Use to pin a specific firmware or kernel measurement.
    RequirePcrValue {
        semantic: PcrSemantic,
        expected: [u8; 32],
    },

    /// Reject evidence that does not include a Firmware PCR measurement.
    RequireFirmwareMeasurement,

    /// Reject evidence that does not include a Bootloader PCR measurement.
    RequireBootloaderMeasurement,

    /// Reject evidence that does not include a Kernel PCR measurement.
    RequireKernelMeasurement,

    /// Reject evidence that does not include Firmware + Bootloader PCRs.
    ///
    /// This is the minimum requirement for measured boot. A device that
    /// has not measured its firmware and bootloader cannot be trusted.
    RequireMeasuredBoot,

    /// Reject evidence without a hardware-backed monotonic counter.
    ///
    /// Requires `CounterEvidence::HardwareMonotonic`. Rejects
    /// `SoftwareObserved` and `Unsupported`.
    RequireHardwareMonotonicCounter,

    /// Reject evidence where the counter value is below a minimum.
    ///
    /// Use to detect TPM resets (a freshly-cleared TPM has counter = 0).
    RequireMinCounterValue(u64),

    /// Reject evidence from backends that do not support nonce binding.
    ///
    /// Nonce binding is required for replay protection. Backends that
    /// cannot bind a nonce into their evidence cannot provide freshness
    /// guarantees beyond the nonce ledger.
    RequireNonceBinding,

    /// Reject evidence where Secure Boot is not in the required state.
    RequireSecureBootState(SecureBootState),

    /// Reject evidence if the Boot Chain does not match expectations.
    RequireBootChain(BootChainEvidence),

    /// Reject evidence if it does not match the specified Platform Profile.
    RequirePlatformProfile {
        profile: PlatformProfile,
        drift_mode: DriftPolicyMode,
        upgrade_baseline: Option<PcrBaseline>,
    },

    /// Reject evidence if the baseline is invalid or rolled back.
    RequireValidBaselineTransition {
        current: PcrBaseline,
        previous: PcrBaseline,
    },

    /// Reject evidence if the runtime measurements do not match the expected whitelist
    /// or rolling upgrade list.
    RequireRuntimeIntegrity {
        whitelist: Vec<TypedDigest>,
        rolling_upgrades: Vec<TypedDigest>,
    },

    /// Reject evidence if the Linux IMA/Appraisal subsystems are disabled.
    RequireIma,

    /// Reject evidence if the continuous attestation session lease/window has expired.
    RequireContinuousAttestation {
        expiration_window_secs: u64,
        now_secs: u64,
    },

    /// Reject evidence if the continuous attestation sequence is non-monotonic or has gaps.
    RequireSequenceMonotonicity,

    /// Reject evidence if the attestation timeline cannot be verified as anchored in Bitcoin blocks.
    RequireTransparencyAnchoring,

    /// Reject evidence if the policy epoch does not match the expected epoch.
    RequirePolicyEpoch(u64),

    // ── Phase 2.9 Federated Trust Rules ──────────────────────────────────
    /// Reject if no valid [`VerifierFederation`] is present in context.
    ///
    /// Maps to [`TrustDomain::HardwareIdentity`].
    RequireVerifierFederation,

    /// Reject if the consensus evaluation did not reach quorum or was not
    /// found to be [`ConsensusDecision::Trusted`].
    ///
    /// `min_votes` is an additional lower bound on participation count,
    /// independent of the federation's own quorum policy.
    /// Maps to [`TrustDomain::HardwareIdentity`].
    RequireConsensusQuorum {
        /// Minimum number of votes that must have been cast.
        min_votes: usize,
    },

    /// Reject if verifier transparency logs are inconsistent across the
    /// federation (e.g., events are missing or hashes conflict).
    ///
    /// Maps to [`TrustDomain::Transparency`].
    RequireTransparencyConsensus,

    /// Reject if the current federated policy epoch has not been approved
    /// by quorum (i.e., `quorum_reached == false`).
    ///
    /// Maps to [`TrustDomain::ContinuousAttestation`].
    RequireFederatedPolicyApproval,

    /// Reject if the cross-verifier timeline reconciliation report detected
    /// any conflicts or missing events.
    ///
    /// Maps to [`TrustDomain::Transparency`].
    RequireTimelineConsistency,

    // ── Phase 3.0 Sovereign Node Rules ───────────────────────────────────
    /// Reject if the expected Bitcoin node identity is missing or invalid.
    ///
    /// Maps to [`TrustDomain::WorkloadIntegrity`].
    RequireBitcoinNodeIdentity,

    /// Reject if the Bitcoin workload executable or config fails integrity checks.
    ///
    /// Maps to [`TrustDomain::WorkloadIntegrity`].
    RequireBitcoinWorkloadIntegrity,

    /// Reject if the Bitcoin node's runtime state drifts out of expected bounds.
    ///
    /// Maps to [`TrustDomain::WorkloadIntegrity`].
    RequireNodeRuntimeContinuity,

    /// Reject if the Bitcoin node's trust state has not been anchored to transparency logs.
    ///
    /// Maps to [`TrustDomain::Transparency`].
    RequireNodeTransparencyAnchoring,

    /// Reject if the Bitcoin node has not been verified by a distributed federation quorum.
    ///
    /// Maps to [`TrustDomain::ConsensusIntegrity`].
    RequireFederatedNodeVerification,

    /// Reject if the node does not conform to a deterministic policy profile.
    ///
    /// Maps to [`TrustDomain::ContinuousAttestation`].
    RequireDeterministicNodePolicy,

    // ── Phase 3.1 Live Evidence Rules ─────────────────────────────────
    /// Require live TPM acquisition evidence.
    RequireLiveTpmEvidence,
    /// Require live IMA streaming evidence.
    RequireLiveImaEvidence,
    /// Require Secure Boot state dynamically collected from EFI variables.
    RequireSecureBootCollection,
    /// Require runtime evidence to be cryptographically fresh.
    RequireFreshRuntimeEvidence,
    /// Require live observation continuity for nodes.
    RequireRuntimeObservationContinuity,
    /// Require verified Bitcoin process execution state.
    RequireVerifiedBitcoinProcess,

    // ── Phase 3.2 Streaming & PQ Federation Rules ─────────────────────
    /// Require incremental delta attestation instead of full snapshots.
    RequireDeltaAttestation,
    /// Require rolling integrity checkpoints for bounded history.
    RequireCheckpointIntegrity,
    /// Require PQ-secure federation transport (ML-KEM & `ChaCha20Poly1305`).
    RequirePqFederationTransport,
    /// Require mathematically reduced timeline compaction proofs.
    RequireTimelineCompaction,
    /// Require adherence to bounded verifier retention policy.
    RequireRetentionCompliance,
    /// Require valid ML-DSA signatures on federation messages.
    RequireFederationMessageSigning,

    // ── Phase 3.3 Byzantine Federation Convergence Rules ──────────────────
    RequireVerifierRevocationChecks,
    RequireEquivocationDetection,
    RequireByzantineQuorum,
    RequireTopologyValidation,
    RequireRetentionGovernance,
    RequireCrossFederationConsistency,
    RequireGovernanceContinuity,

    // ── Phase 3.4 Federation Time Semantics Rules ────────────────────────
    RequireLogicalClockSynchronization,
    RequireBoundedTimeSkew,
    RequireAnchoredKeyRegistry,
    RequireEpochKeyBinding,

    // ── Phase 3.5 Infrastructure Resilience Rules ────────────────────────
    RequireFederationSnapshots,
    RequireDeterministicReplay,
    RequirePartitionDetection,
    RequirePartitionHealingApproval,
    RequireVerifierRejoinValidation,
    RequireQuorumReformation,
    RequireRecoveryGovernance,
    RequireMigrationContinuity,

    // ── Phase 3.6 Adaptive Federation Synchronization Rules ──────────────
    RequireAdaptiveSynchronization,
    RequireDeterministicSnapshotSync,
    RequireFederationLiveness,
    RequireEclipseResistance,
    RequireOperationalPeerValidation,
    RequireBoundedStateReconstruction,
    RequireSynchronizationGovernance,
}

pub struct HardwarePolicyContext<'a> {
    /// The backend type that produced the evidence.
    pub backend_type: HardwareBackendType,
    /// The PCR bank from the evidence.
    pub pcr_bank: &'a TypedPcrBank,
    /// Counter evidence from the backend.
    pub counter: CounterEvidence,
    /// Whether the backend supports nonce binding.
    pub supports_nonce_binding: bool,
    /// The firmware digest from the evidence.
    pub firmware_digest: &'a TypedDigest,
    /// Optional Secure Boot evidence.
    pub secure_boot: Option<&'a SecureBootEvidence>,
    /// Optional Boot Chain evidence.
    pub boot_chain: Option<&'a BootChainEvidence>,
    /// Legacy static Runtime Integrity evidence.
    pub runtime_integrity: Option<&'a crate::runtime_integrity::RuntimeIntegrityEvidence>,
    /// Optional dynamic Runtime Attestation Evidence.
    pub runtime_attestation: Option<&'a RuntimeAttestationEvidence>,
    /// Optional Linux IMA evidence.
    pub ima_evidence: Option<&'a ImaEvidence>,
    /// Optional stateful attestation session.
    pub session: Option<&'a AttestationSession>,
    /// Optional verifier timeline.
    pub timeline: Option<&'a AttestationTimeline>,
    /// Optional transparency log inclusion proof.
    pub transparency_proof: Option<&'a TimelineInclusionProof>,
    /// Optional SPV verifier for timeline checking.
    pub spv_verifier: Option<&'a TimelineSpvVerifier>,
    /// Optional transparency event for verifying anchoring.
    pub transparency_event: Option<&'a TransparencyEvent>,

    // ── Phase 2.9 Federated Trust Fields ─────────────────────────────────
    /// Optional verifier federation for quorum-based evaluation.
    pub federation: Option<&'a VerifierFederation>,
    /// Optional distributed consensus evaluation result.
    pub consensus_evaluation: Option<&'a ConsensusEvaluation>,
    /// Optional federated policy epoch (for approval checking).
    pub federated_epoch: Option<&'a FederatedPolicyEpoch>,
    /// Optional cross-verifier timeline reconciliation report.
    pub timeline_reconciliation: Option<&'a TimelineReconciliationReport>,

    // ── Phase 3.0 Sovereign Node Fields ──────────────────────────────────
    /// Optional explicitly declared Bitcoin node identity.
    pub bitcoin_node_identity: Option<&'a crate::bitcoin_node_identity::BitcoinNodeIdentity>,
    /// Optional Bitcoin workload integrity evidence.
    pub bitcoin_workload_evidence:
        Option<&'a crate::bitcoin_workload_integrity::BitcoinWorkloadEvidence>,
    /// Optional continuous runtime state of the Bitcoin node.
    pub bitcoin_runtime_state: Option<&'a crate::bitcoin_runtime_monitor::BitcoinRuntimeState>,
    /// Optional active node attestation session.
    pub node_session: Option<&'a crate::node_attestation_session::NodeAttestationSession>,

    // ── Phase 3.1 Live Evidence Fields ─────────────────────────────────
    #[cfg(feature = "live-evidence")]
    /// Optional live evidence payload collected from physical hardware and OS.
    pub live_evidence: Option<&'a crate::evidence_pipeline::LiveAttestationPayload>,
    #[cfg(feature = "live-evidence")]
    pub live_observation: Option<&'a crate::live_node_observer::NodeObservation>,

    // ── Phase 3.2 Streaming & PQ Federation Fields ─────────────────────
    /// Optional runtime integrity stream state.
    pub runtime_stream: Option<&'a crate::runtime_stream::RuntimeIntegrityStream>,
    /// Optional incremental delta attestation.
    pub delta_attestation: Option<&'a crate::delta_attestation::DeltaAttestation>,
    /// Optional compacted checkpoint.
    pub checkpoint: Option<&'a crate::checkpointing::IntegrityCheckpoint>,
    /// Optional PQ-secure transport session.
    pub pq_session: Option<&'a crate::pq_transport::PqTransportSession>,
    /// Optional mathematically compacted timeline.
    pub compacted_timeline: Option<&'a crate::timeline_compaction::CompactedTimeline>,
    /// Optional signed federation envelope.
    pub federation_envelope: Option<&'a crate::federation_transport::SignedFederationEnvelope>,

    // ── Phase 3.3 Byzantine Federation Convergence Fields ─────────────────
    /// Optional verifier revocation list for checking revocation status.
    pub revocation_list: Option<&'a [crate::verifier_revocation::VerifierRevocation]>,

    // ── Phase 3.4 Federation Time Semantics Fields ────────────────────────
    /// Optional logical clock reading.
    pub logical_clock: Option<&'a crate::federation_time::HybridLogicalClock>,
    /// Optional observed temporal ambiguity evidence.
    pub temporal_ambiguity: Option<&'a [crate::temporal_ambiguity::TemporalAmbiguityEvidence]>,
    /// Optional verifier registration status from Bitcoin.
    pub verifier_registration_state:
        Option<&'a pqrascv_bitcoin_anchor::key_registry_anchor::VerifierRegistrationState>,
    /// Optional epoch key binding.
    pub epoch_key_binding: Option<&'a crate::epoch_key_binding::EpochKeyBinding>,
}
