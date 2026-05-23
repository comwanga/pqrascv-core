//! Trust Domains Modeling
//!
//! Provides explicit separation of concerns for various facets of platform
//! and runtime trust, preventing semantic leakage between domains.

use alloc::string::String;
use alloc::vec::Vec;

/// Explicit classification of distinct trust domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TrustDomain {
    HardwareIdentity,
    MeasuredBoot,
    SecureBoot,
    RuntimeIntegrity,
    SupplyChain,
    Provenance,
    Transparency,
    ContinuousAttestation,
    // --- Phase 3.0 Sovereign Node Additions ---
    WorkloadIntegrity,
    ConsensusIntegrity,
    // --- Phase 3.3 Byzantine Federation Convergence ---
    DistributedGovernance,
    // --- Phase 3.4 Federation Time Semantics ---
    TemporalTimekeeping,
    // --- Phase 3.5 Infrastructure Resilience ---
    RecoveryIntegrity,
}

/// Explicit reasons why a verification decision succeeded or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum VerificationDecisionReason {
    /// Verification passed all checks.
    Success,
    /// Secure Boot is required but was disabled or in setup mode.
    SecureBootDisabled,
    /// An unauthorized firmware or policy rollback was detected.
    BaselineRollbackDetected,
    /// The firmware generation reported is completely unknown.
    UnknownFirmwareGeneration,
    /// Measurement drift exceeding permissible bounds was detected.
    CriticalDriftDetected,
    /// An expected OS Kernel measurement was missing from the evidence.
    MissingKernelMeasurement,
    /// The supplied Platform Profile is malformed or invalid.
    InvalidPlatformProfile,
    /// The hardware vendor is not supported by the current policy.
    UnsupportedVendor,
    // --- Phase 2.8 Continuous & Runtime Integrity Additions ---
    /// Runtime integrity subsystem is disabled or unavailable.
    RuntimeIntegrityUnavailable,
    /// IMA log entry did not match expected database or whitelist digest.
    ImaMeasurementMismatch,
    /// Kernel measurement is missing in the runtime log.
    KernelMeasurementMissing,
    /// Unauthorized changes or deviations detected in running executables/libs.
    CriticalRuntimeDrift,
    /// Continuous attestation lease/session duration has expired.
    ContinuousAttestationExpired,
    /// Current policy does not support the requested runtime configuration.
    UnsupportedRuntimePolicy,
    /// The sequence number in the attestation stream is invalid or non-monotonic.
    InvalidAttestationSequence,
    /// A sequence gap was detected indicating potential missed measurements.
    RuntimeMeasurementGap,
    /// The policy epoch sent by the prover does not match the verifier epoch.
    PolicyEpochMismatch,
    // --- Phase 2.9 Federated Trust Additions ---
    /// No valid verifier federation is present in the evaluation context.
    VerifierFederationAbsent,
    /// The distributed consensus vote did not reach the required quorum.
    ConsensusQuorumFailed,
    /// The federated policy epoch has not been approved by quorum.
    FederatedPolicyNotApproved,
    /// Cross-verifier timeline reconciliation detected inconsistencies.
    TimelineInconsistencyDetected,
    // --- Phase 3.0 Sovereign Node Additions ---
    /// The running Bitcoin Core binary does not match the expected identity.
    BitcoinBinaryMismatch,
    /// An unauthorized mutation to the Bitcoin node configuration was detected.
    UnauthorizedConfigMutation,
    /// The node's event timeline diverged from the canonical history.
    NodeTimelineDivergence,
    /// The node identity presented is invalid or unregistered.
    InvalidNodeIdentity,
    /// The Bitcoin node's runtime behavior deviated from permitted parameters.
    RuntimeNodeDrift,
    /// The Bitcoin node attestation session has been replayed.
    ReplayedNodeSession,
    /// Required transparency anchoring for the node was withheld or missing.
    TransparencyWithholding,
    /// The specified policy profile is missing or corrupted.
    PolicyProfileCorruption,
    /// A policy rollback attack against the Bitcoin node was rejected.
    PolicyRollbackRejected,
    // --- Phase 3.3 Byzantine Federation Convergence Additions ---
    /// Verifier identity has been formally revoked.
    VerifierRevoked,
    /// Verifier equivocation (contradictory state commitments) was detected.
    EquivocationDetected,
    /// Byzantine partition detected (multiple conflicting sub-quorums).
    ByzantinePartitionDetected,
    /// Verifier lacks topological authority for this domain.
    TopologyAuthorityExceeded,
    /// Cross-federation conflict or irreconcilable divergence detected.
    CrossFederationConflict,
    /// Governance continuity chain is broken or missing.
    GovernanceContinuityBroken,
    // --- Phase 3.4 Federation Time Semantics Additions ---
    /// Physical time drift exceeds bounded skew limits.
    TimeSkewExceeded,
    /// Logical clock synchronization failed or non-monotonic.
    LogicalClockFailed,
    /// Epoch-key binding validation failed.
    EpochKeyBindingInvalid,
    /// Verifier key registration is not yet anchored.
    VerifierNotAnchored,
    // --- Phase 3.5 Infrastructure Resilience ---
    /// Recovery procedure violated (e.g., partition detected, invalid snapshot, missing lineage).
    RecoveryIntegrityFailure,
}

/// Structured outcome of evaluation for a single trust domain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustEvaluation {
    /// The trust domain being evaluated.
    pub domain: TrustDomain,
    /// True if the domain is fully trusted according to policy rules.
    pub trusted: bool,
    /// Reasons for failures or confirmations of trust.
    pub reasons: Vec<VerificationDecisionReason>,
    /// Non-fatal warnings observed during evaluation.
    pub warnings: Vec<String>,
}

impl TrustEvaluation {
    /// Creates a trusted evaluation for a given domain.
    #[must_use]
    pub fn trusted(domain: TrustDomain) -> Self {
        Self {
            domain,
            trusted: true,
            reasons: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Creates an untrusted evaluation for a given domain.
    #[must_use]
    pub fn untrusted(domain: TrustDomain, reasons: Vec<VerificationDecisionReason>) -> Self {
        Self {
            domain,
            trusted: false,
            reasons,
            warnings: Vec::new(),
        }
    }
}
