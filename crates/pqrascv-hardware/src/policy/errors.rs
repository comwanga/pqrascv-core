extern crate alloc;
use alloc::string::String;

use crate::{
    backend::HardwareBackendType, counter::CounterEvidence, digest::TypedDigest,
    distributed_consensus::ConsensusDecision, pcr::PcrSemantic, runtime_drift::RuntimeDriftReport,
    secure_boot::SecureBootState, trust_domains::VerificationDecisionReason,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HardwarePolicyError {
    /// The backend is not hardware-rooted (e.g. `TestOnly`).
    BackendNotHardwareRooted(HardwareBackendType),
    /// The backend type does not match the required type.
    WrongBackendType {
        required: HardwareBackendType,
        got: HardwareBackendType,
    },
    /// At least one PCR digest is not normalized to SHA3-256.
    UnnormalizedPcrs,
    /// A required PCR semantic is absent.
    PcrSemanticAbsent(PcrSemantic),
    /// A PCR value does not match the expected digest.
    PcrValueMismatch {
        semantic: PcrSemantic,
        expected: [u8; 32],
        got: [u8; 32],
    },
    /// Measured boot is incomplete (a required PCR semantic is absent).
    MeasuredBootIncomplete(PcrSemantic),
    /// The counter is not hardware-backed.
    CounterNotHardwareBacked(CounterEvidence),
    /// The counter value is below the required minimum.
    CounterTooLow {
        got: u64,
        min: u64,
    },
    /// The backend does not support nonce binding.
    NonceBindingUnsupported,
    /// Secure Boot state mismatch.
    SecureBootStateMismatch {
        expected: SecureBootState,
        got: SecureBootState,
    },
    /// Boot chain firmware digest mismatch.
    BootChainFirmwareMismatch {
        expected: TypedDigest,
        got: TypedDigest,
    },
    /// Boot chain bootloader digest mismatch.
    BootChainBootloaderMismatch {
        expected: TypedDigest,
        got: TypedDigest,
    },
    /// Boot chain kernel digest mismatch.
    BootChainKernelMismatch {
        expected: TypedDigest,
        got: TypedDigest,
    },
    /// Missing Secure Boot evidence when required.
    SecureBootEvidenceMissing,
    /// Missing Boot Chain evidence when required.
    BootChainEvidenceMissing,
    /// Mismatch with Platform Profile.
    PlatformProfileMismatch {
        reason: VerificationDecisionReason,
    },
    /// Baseline version rollback detected.
    BaselineRollbackDetected,
    /// Policy evaluation failed due to conflicts.
    PolicyConflict(PolicyConflictError),
    /// Runtime attestation evidence is missing when required.
    RuntimeAttestationEvidenceMissing,
    /// Critical runtime drift detected.
    CriticalRuntimeDriftDetected(RuntimeDriftReport),
    /// IMA evidence is missing.
    ImaEvidenceMissing,
    /// IMA is disabled.
    ImaDisabled,
    /// IMA appraisal is disabled.
    ImaAppraisalDisabled,
    /// Continuous attestation session is missing.
    ContinuousAttestationSessionMissing,
    /// Continuous attestation session is inactive.
    ContinuousAttestationSessionInactive,
    /// Continuous attestation has expired.
    ContinuousAttestationExpired {
        last_seen: u64,
        now: u64,
        window: u64,
    },
    /// Replay detected during sequence monotonicity check.
    ReplayDetected {
        got: u64,
        expected: u64,
    },
    /// Sequence gap detected during sequence monotonicity check.
    SequenceGapDetected {
        got: u64,
        expected: u64,
    },
    /// Transparency proof is missing.
    TransparencyProofMissing,
    /// SPV verifier is missing.
    SpvVerifierMissing,
    /// Transparency event is missing.
    TransparencyEventMissing,
    /// Serialization of transparency event failed.
    TransparencySerializationFailed,
    /// SPV verification failed.
    SpvVerificationFailed(pqrascv_bitcoin_anchor::proof::SpvError),
    /// Policy epoch mismatch.
    PolicyEpochMismatch {
        expected: u64,
        got: u64,
    },

    // ── Phase 2.9 Federated Trust Errors ─────────────────────────────────
    /// No verifier federation was provided in the policy context.
    VerifierFederationMissing,
    /// The consensus evaluation did not reach quorum or was not Trusted.
    ConsensusQuorumFailed {
        decision: ConsensusDecision,
    },
    /// Verifier transparency logs are inconsistent; consensus failed.
    TransparencyConsensusFailed,
    /// The federated policy epoch context is missing.
    FederatedPolicyApprovalMissing,
    /// The federated policy epoch has not been approved by quorum.
    FederatedEpochQuorumNotReached {
        epoch_id: u64,
    },
    /// Cross-verifier timeline reconciliation detected conflicts.
    TimelineConflictDetected,

    // ── Phase 3.0 Sovereign Node Errors ──────────────────────────────────
    /// The expected Bitcoin node identity is missing.
    BitcoinNodeIdentityMissing,
    /// The Bitcoin workload evidence is missing.
    BitcoinWorkloadEvidenceMissing,
    /// The running Bitcoin Core binary does not match the expected identity.
    BitcoinBinaryMismatch {
        expected: TypedDigest,
        got: TypedDigest,
    },
    /// An unauthorized mutation to the Bitcoin node configuration was detected.
    UnauthorizedConfigMutation {
        expected: TypedDigest,
        got: TypedDigest,
    },
    /// The Bitcoin runtime state is missing.
    BitcoinRuntimeStateMissing,
    /// The Bitcoin node's runtime behavior deviated from permitted parameters.
    RuntimeNodeDrift,
    /// The Bitcoin node attestation session is missing.
    NodeAttestationSessionMissing,
    /// The Bitcoin node attestation session is inactive or replayed.
    NodeAttestationSessionInvalid,
    /// Required transparency anchoring for the node was withheld or missing.
    NodeTransparencyWithholding,
    /// The specified deterministic policy profile is missing or corrupted.
    DeterministicPolicyMissing,

    // ── Phase 3.1 Live Evidence Errors ──────────────────────────────────
    /// Live TPM acquisition evidence is missing.
    LiveTpmEvidenceMissing,
    /// Live IMA streaming evidence is missing.
    LiveImaEvidenceMissing,
    /// Secure Boot state could not be dynamically collected.
    SecureBootCollectionMissing,
    /// Runtime evidence is stale or suspected of being replayed.
    FreshRuntimeEvidenceMissing,
    /// Node observation stream lacks continuity.
    RuntimeObservationContinuityBroken,
    /// Verified Bitcoin process state is absent.
    VerifiedBitcoinProcessMissing,

    // ── Phase 3.2 Streaming & PQ Federation Errors ───────────────────────
    /// Delta attestation evidence is missing.
    DeltaAttestationMissing,
    /// Rolling integrity checkpoint is missing or invalid.
    CheckpointIntegrityMissing,
    /// Post-Quantum federation transport session is missing.
    PqFederationTransportMissing,
    /// Mathematically compacted timeline proofs are missing.
    TimelineCompactionMissing,
    /// Verifier bounds on storage/history retention have been violated.
    RetentionComplianceViolated,
    /// Federation message signature is missing or cryptographically invalid.
    FederationMessageSigningInvalid,

    // ── Phase 3.3 Byzantine Federation Convergence Errors ─────────────────
    VerifierRevoked(String),
    EquivocationDetected(String),
    ByzantinePartitionDetected,
    ByzantineIntersectionFailure,
    TopologyValidationFailed,
    RetentionGovernanceFailed,
    CrossFederationConflictDetected,
    /// Governance continuity chain is broken or missing.
    GovernanceContinuityBroken,

    // ── Phase 3.4 Federation Time Semantics Errors ────────────────────────
    /// Physical time drift exceeds bounded skew limits.
    TimeSkewExceeded,
    /// Logical clock synchronization failed or non-monotonic.
    LogicalClockFailed,
    /// Epoch-key binding validation failed.
    EpochKeyBindingInvalid,
    /// Verifier key registration is not yet anchored.
    VerifierNotAnchored,

    // ── Phase 3.6 Adaptive Federation Synchronization Errors ──────────────
    SynchronizationCollapse,
    EclipseRiskDetected,
    InvalidSnapshotProof,
    ReconstructionFailure,
    FederationLivenessFailure,
}

impl HardwarePolicyError {
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn decision_reason(&self) -> VerificationDecisionReason {
        match self {
            Self::BackendNotHardwareRooted(_) | Self::WrongBackendType { .. } => {
                VerificationDecisionReason::UnsupportedVendor
            }
            Self::UnnormalizedPcrs
            | Self::PcrSemanticAbsent(_)
            | Self::PcrValueMismatch { .. }
            | Self::MeasuredBootIncomplete(_)
            | Self::BootChainFirmwareMismatch { .. }
            | Self::BootChainBootloaderMismatch { .. }
            | Self::BootChainKernelMismatch { .. }
            | Self::BootChainEvidenceMissing => VerificationDecisionReason::CriticalDriftDetected,
            Self::CounterNotHardwareBacked(_)
            | Self::CounterTooLow { .. }
            | Self::NonceBindingUnsupported => VerificationDecisionReason::UnsupportedVendor,
            Self::SecureBootStateMismatch { .. } | Self::SecureBootEvidenceMissing => {
                VerificationDecisionReason::SecureBootDisabled
            }
            Self::PlatformProfileMismatch { reason } => *reason,
            Self::BaselineRollbackDetected => VerificationDecisionReason::BaselineRollbackDetected,
            Self::PolicyConflict(_) => VerificationDecisionReason::InvalidPlatformProfile,
            Self::RuntimeAttestationEvidenceMissing
            | Self::ImaEvidenceMissing
            | Self::ImaDisabled
            | Self::ImaAppraisalDisabled => VerificationDecisionReason::RuntimeIntegrityUnavailable,
            Self::CriticalRuntimeDriftDetected(_) => {
                VerificationDecisionReason::CriticalRuntimeDrift
            }
            // Merged: Phase 3.1 continuous attestation + Phase 3.2 streaming errors
            // all map to ContinuousAttestationExpired.
            Self::ContinuousAttestationSessionMissing
            | Self::ContinuousAttestationSessionInactive
            | Self::ContinuousAttestationExpired { .. }
            | Self::DeltaAttestationMissing
            | Self::CheckpointIntegrityMissing
            | Self::TimelineCompactionMissing
            | Self::RetentionComplianceViolated => {
                VerificationDecisionReason::ContinuousAttestationExpired
            }
            Self::ReplayDetected { .. }
            | Self::SequenceGapDetected { .. }
            | Self::FreshRuntimeEvidenceMissing
            | Self::RuntimeObservationContinuityBroken => {
                VerificationDecisionReason::InvalidAttestationSequence
            }
            Self::TransparencyProofMissing
            | Self::SpvVerifierMissing
            | Self::TransparencyEventMissing
            | Self::TransparencySerializationFailed
            | Self::SpvVerificationFailed(_) => VerificationDecisionReason::RuntimeMeasurementGap,
            Self::PolicyEpochMismatch { .. } => VerificationDecisionReason::PolicyEpochMismatch,
            Self::VerifierFederationMissing
            | Self::ConsensusQuorumFailed { .. }
            | Self::FederatedPolicyApprovalMissing
            | Self::FederatedEpochQuorumNotReached { .. }
            | Self::PqFederationTransportMissing
            | Self::FederationMessageSigningInvalid => {
                VerificationDecisionReason::VerifierFederationAbsent
            }
            Self::TransparencyConsensusFailed | Self::TimelineConflictDetected => {
                VerificationDecisionReason::TimelineInconsistencyDetected
            }
            Self::BitcoinNodeIdentityMissing => VerificationDecisionReason::InvalidNodeIdentity,
            Self::BitcoinWorkloadEvidenceMissing
            | Self::LiveTpmEvidenceMissing
            | Self::LiveImaEvidenceMissing
            | Self::SecureBootCollectionMissing
            | Self::VerifiedBitcoinProcessMissing => {
                VerificationDecisionReason::MissingKernelMeasurement
            }
            Self::BitcoinBinaryMismatch { .. } => VerificationDecisionReason::BitcoinBinaryMismatch,
            Self::UnauthorizedConfigMutation { .. } => {
                VerificationDecisionReason::UnauthorizedConfigMutation
            }
            Self::BitcoinRuntimeStateMissing | Self::RuntimeNodeDrift => {
                VerificationDecisionReason::RuntimeNodeDrift
            }
            Self::NodeAttestationSessionMissing | Self::NodeAttestationSessionInvalid => {
                VerificationDecisionReason::ReplayedNodeSession
            }
            Self::NodeTransparencyWithholding => {
                VerificationDecisionReason::TransparencyWithholding
            }
            Self::DeterministicPolicyMissing | Self::RetentionGovernanceFailed => {
                VerificationDecisionReason::PolicyProfileCorruption
            }

            // ── Phase 3.3 Byzantine Federation Convergence Errors ─────────────────
            Self::VerifierRevoked(_) => VerificationDecisionReason::VerifierRevoked,
            Self::EquivocationDetected(_) => VerificationDecisionReason::EquivocationDetected,
            Self::ByzantinePartitionDetected | Self::ByzantineIntersectionFailure => {
                VerificationDecisionReason::ByzantinePartitionDetected
            }
            Self::TopologyValidationFailed => VerificationDecisionReason::TopologyAuthorityExceeded,
            Self::CrossFederationConflictDetected => {
                VerificationDecisionReason::CrossFederationConflict
            }
            Self::GovernanceContinuityBroken => {
                VerificationDecisionReason::GovernanceContinuityBroken
            }

            // ── Phase 3.4 Federation Time Semantics Errors ────────────────
            Self::TimeSkewExceeded => VerificationDecisionReason::TimeSkewExceeded,
            Self::LogicalClockFailed => VerificationDecisionReason::LogicalClockFailed,
            Self::EpochKeyBindingInvalid => VerificationDecisionReason::EpochKeyBindingInvalid,
            Self::VerifierNotAnchored => VerificationDecisionReason::VerifierNotAnchored,

            // ── Phase 3.6 Adaptive Federation Synchronization Errors ───────
            Self::SynchronizationCollapse => VerificationDecisionReason::SynchronizationCollapse,
            Self::EclipseRiskDetected => VerificationDecisionReason::EclipseRiskDetected,
            Self::InvalidSnapshotProof => VerificationDecisionReason::InvalidSnapshotProof,
            Self::ReconstructionFailure => VerificationDecisionReason::ReconstructionFailure,
            Self::FederationLivenessFailure => {
                VerificationDecisionReason::FederationLivenessFailure
            }
        }
    }
}

impl core::fmt::Display for HardwarePolicyError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BackendNotHardwareRooted(t) => {
                write!(f, "backend {} is not hardware-rooted", t.name())
            }
            Self::WrongBackendType { required, got } => write!(
                f,
                "wrong backend type: required {}, got {}",
                required.name(),
                got.name()
            ),
            Self::UnnormalizedPcrs => f.write_str("PCR digests are not normalized to SHA3-256"),
            Self::PcrSemanticAbsent(s) => write!(f, "PCR semantic {s:?} is absent"),
            Self::PcrValueMismatch { semantic, .. } => {
                write!(f, "PCR value mismatch for semantic {semantic:?}")
            }
            Self::MeasuredBootIncomplete(s) => {
                write!(f, "measured boot incomplete: {s:?} PCR absent")
            }
            Self::CounterNotHardwareBacked(c) => {
                write!(f, "counter is not hardware-backed: {c:?}")
            }
            Self::CounterTooLow { got, min } => {
                write!(f, "counter {got} is below minimum {min}")
            }
            Self::NonceBindingUnsupported => f.write_str("backend does not support nonce binding"),
            Self::SecureBootStateMismatch { expected, got } => {
                write!(
                    f,
                    "Secure Boot state mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::BootChainFirmwareMismatch { expected, got } => {
                write!(
                    f,
                    "Boot Chain firmware mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::BootChainBootloaderMismatch { expected, got } => {
                write!(
                    f,
                    "Boot Chain bootloader mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::BootChainKernelMismatch { expected, got } => {
                write!(
                    f,
                    "Boot Chain kernel mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::SecureBootEvidenceMissing => f.write_str("Secure Boot evidence is missing"),
            Self::BootChainEvidenceMissing => f.write_str("Boot Chain evidence is missing"),
            Self::PlatformProfileMismatch { reason } => {
                write!(f, "platform profile mismatch: {reason:?}")
            }
            Self::BaselineRollbackDetected => f.write_str("baseline rollback detected"),
            Self::PolicyConflict(err) => write!(f, "policy conflict: {err}"),
            Self::RuntimeAttestationEvidenceMissing => {
                f.write_str("runtime attestation evidence is missing")
            }
            Self::CriticalRuntimeDriftDetected(report) => {
                write!(
                    f,
                    "critical runtime drift detected: actual digest {:x?} does not match whitelist for workload {}",
                    report.actual, report.workload
                )
            }
            Self::ImaEvidenceMissing => f.write_str("IMA evidence is missing"),
            Self::ImaDisabled => f.write_str("IMA is disabled"),
            Self::ImaAppraisalDisabled => f.write_str("IMA appraisal is disabled"),
            Self::ContinuousAttestationSessionMissing => {
                f.write_str("continuous attestation session is missing")
            }
            Self::ContinuousAttestationSessionInactive => {
                f.write_str("continuous attestation session is inactive")
            }
            Self::ContinuousAttestationExpired {
                last_seen,
                now,
                window,
            } => {
                write!(
                    f,
                    "continuous attestation session expired: last seen at {last_seen}, now {now}, window {window}s"
                )
            }
            Self::ReplayDetected { got, expected } => {
                write!(
                    f,
                    "replay detected: sequence number got {got}, expected {expected}"
                )
            }
            Self::SequenceGapDetected { got, expected } => {
                write!(
                    f,
                    "sequence gap detected: sequence number got {got}, expected {expected}"
                )
            }
            Self::TransparencyProofMissing => f.write_str("transparency proof is missing"),
            Self::SpvVerifierMissing => f.write_str("SPV verifier is missing"),
            Self::TransparencyEventMissing => f.write_str("transparency event is missing"),
            Self::TransparencySerializationFailed => {
                f.write_str("transparency event serialization failed")
            }
            Self::SpvVerificationFailed(err) => {
                write!(f, "SPV verification failed: {err:?}")
            }
            Self::PolicyEpochMismatch { expected, got } => {
                write!(f, "policy epoch mismatch: expected {expected}, got {got}")
            }
            // Phase 2.9
            Self::VerifierFederationMissing => {
                f.write_str("verifier federation is missing from context")
            }
            Self::ConsensusQuorumFailed { decision } => {
                write!(f, "consensus quorum failed: decision={decision:?}")
            }
            Self::TransparencyConsensusFailed => {
                f.write_str("verifier transparency logs are inconsistent")
            }
            Self::FederatedPolicyApprovalMissing => {
                f.write_str("federated policy epoch context is missing")
            }
            Self::FederatedEpochQuorumNotReached { epoch_id } => {
                write!(
                    f,
                    "federated policy epoch {epoch_id} has not reached quorum"
                )
            }
            Self::TimelineConflictDetected => {
                f.write_str("cross-verifier timeline conflict detected")
            }
            // ── Phase 3.0 Sovereign Node Errors ──────────────────────────────
            Self::BitcoinNodeIdentityMissing => {
                f.write_str("bitcoin node identity missing from context")
            }
            Self::BitcoinWorkloadEvidenceMissing => {
                f.write_str("bitcoin workload evidence missing from context")
            }
            Self::BitcoinBinaryMismatch { expected, got } => {
                write!(
                    f,
                    "bitcoin core binary mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::UnauthorizedConfigMutation { expected, got } => {
                write!(
                    f,
                    "unauthorized bitcoin.conf mutation: expected {expected:?}, got {got:?}"
                )
            }
            Self::BitcoinRuntimeStateMissing => {
                f.write_str("bitcoin runtime state missing from context")
            }
            Self::RuntimeNodeDrift => f.write_str("bitcoin node runtime drift detected"),
            Self::NodeAttestationSessionMissing => {
                f.write_str("node attestation session missing from context")
            }
            Self::NodeAttestationSessionInvalid => {
                f.write_str("node attestation session is inactive or replayed")
            }
            Self::NodeTransparencyWithholding => {
                f.write_str("node transparency anchoring is missing or withheld")
            }
            Self::DeterministicPolicyMissing => {
                write!(
                    f,
                    "Node deterministic policy is missing or missing from evaluation context"
                )
            }

            // ── Phase 3.1 Live Evidence Errors ──────────────────────────────
            Self::LiveTpmEvidenceMissing => f.write_str("live TPM acquisition evidence missing"),
            Self::LiveImaEvidenceMissing => f.write_str("live IMA streaming evidence missing"),
            Self::SecureBootCollectionMissing => {
                f.write_str("dynamic Secure Boot state collection missing")
            }
            Self::FreshRuntimeEvidenceMissing => {
                f.write_str("runtime evidence is stale or suspected of being replayed")
            }
            Self::RuntimeObservationContinuityBroken => {
                f.write_str("node observation stream lacks continuity")
            }
            Self::VerifiedBitcoinProcessMissing => {
                f.write_str("verified Bitcoin process state is absent")
            }

            // ── Phase 3.2 Streaming & PQ Federation Errors ────────────────────────
            Self::DeltaAttestationMissing => {
                f.write_str("incremental delta attestation missing from context")
            }
            Self::CheckpointIntegrityMissing => {
                f.write_str("rolling integrity checkpoint missing or invalid")
            }
            Self::PqFederationTransportMissing => {
                f.write_str("post-quantum federation transport session is missing")
            }
            Self::TimelineCompactionMissing => {
                f.write_str("mathematically compacted timeline proofs are missing")
            }
            Self::RetentionComplianceViolated => {
                f.write_str("verifier bounds on storage/history retention have been violated")
            }
            Self::FederationMessageSigningInvalid => {
                f.write_str("federation message signature is missing or invalid")
            }

            // ── Phase 3.3 Byzantine Federation Convergence Errors ─────────────────
            Self::VerifierRevoked(id) => write!(f, "Verifier '{id}' has been formally revoked"),
            Self::EquivocationDetected(id) => {
                write!(f, "Equivocation detected from verifier '{id}'")
            }
            Self::ByzantinePartitionDetected => {
                write!(f, "Byzantine partition detected (conflicting sub-quorums)")
            }
            Self::ByzantineIntersectionFailure => {
                write!(f, "Byzantine intersection failure (quorum impossible)")
            }
            Self::TopologyValidationFailed => write!(f, "Topology authority scope exceeded"),
            Self::RetentionGovernanceFailed => write!(f, "Retention governance policy violation"),
            Self::CrossFederationConflictDetected => {
                write!(f, "Cross-federation conflict or divergence detected")
            }
            Self::GovernanceContinuityBroken => write!(f, "Governance epoch continuity is broken"),

            // ── Phase 3.4 Federation Time Semantics Errors ────────────────
            Self::TimeSkewExceeded => write!(f, "Physical time drift exceeds bounded skew limits"),
            Self::LogicalClockFailed => {
                write!(f, "Logical clock synchronization failed or non-monotonic")
            }
            Self::EpochKeyBindingInvalid => write!(f, "Epoch-key binding validation failed"),
            Self::VerifierNotAnchored => write!(f, "Verifier key registration is not yet anchored"),

            // ── Phase 3.6 Adaptive Federation Synchronization Errors ───────
            Self::SynchronizationCollapse => {
                write!(f, "Synchronization collapse detected across peers")
            }
            Self::EclipseRiskDetected => {
                write!(f, "Eclipse risk detected due to concentrated topology")
            }
            Self::InvalidSnapshotProof => write!(f, "Snapshot proof failed Merkle validation"),
            Self::ReconstructionFailure => write!(
                f,
                "State reconstruction failed due to invalid lineage or ordering"
            ),
            Self::FederationLivenessFailure => {
                write!(f, "Quorum liveness and convergence properties failed")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PolicyConflictError {
    /// Two or more rules require conflicting hardware backend types.
    ConflictingBackendTypes {
        type_a: HardwareBackendType,
        type_b: HardwareBackendType,
    },
    /// Two or more rules require conflicting Secure Boot states.
    ConflictingSecureBootStates {
        state_a: SecureBootState,
        state_b: SecureBootState,
    },
    /// Two or more rules require conflicting expected PCR digests.
    ConflictingPcrValues {
        semantic: PcrSemantic,
        val_a: [u8; 32],
        val_b: [u8; 32],
    },
    /// Two or more rules require conflicting platform profiles.
    ConflictingPlatformProfiles {
        profile_a: String,
        profile_b: String,
    },
    /// Two or more rules require conflicting policy epochs.
    ConflictingPolicyEpochs { epoch_a: u64, epoch_b: u64 },
}

impl core::fmt::Display for PolicyConflictError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ConflictingBackendTypes { type_a, type_b } => write!(
                f,
                "conflicting backend types required: {} vs {}",
                type_a.name(),
                type_b.name()
            ),
            Self::ConflictingSecureBootStates { state_a, state_b } => write!(
                f,
                "conflicting Secure Boot states required: {state_a:?} vs {state_b:?}"
            ),
            Self::ConflictingPcrValues {
                semantic,
                val_a,
                val_b,
            } => write!(
                f,
                "conflicting PCR value digests for {semantic:?}: {val_a:x?} vs {val_b:x?}"
            ),
            Self::ConflictingPlatformProfiles {
                profile_a,
                profile_b,
            } => write!(
                f,
                "conflicting platform profiles required: {profile_a} vs {profile_b}"
            ),
            Self::ConflictingPolicyEpochs { epoch_a, epoch_b } => write!(
                f,
                "conflicting policy epochs required: {epoch_a} vs {epoch_b}"
            ),
        }
    }
}
