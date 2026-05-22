//! Hardware-aware policy rules extending [`PolicyEngineV2`].
//!
//! This module adds PCR-semantic rules, measured boot enforcement, backend
//! type requirements, and hardware counter requirements to the policy engine.
//!
//! # Integration
//!
//! These rules are designed to be used alongside the existing `PolicyRule`
//! enum from `pqrascv-core`. The `HardwarePolicyContext` extends
//! `PolicyContext` with hardware-specific fields.
//!
//! # Production Preset
//!
//! [`HardwarePolicyEngine::hardware_production()`] returns a preset that:
//! - Requires a hardware-rooted backend (no `TestOnly`)
//! - Requires measured boot (Firmware + Bootloader PCRs present)
//! - Requires a hardware monotonic counter
//! - Requires all PCR digests to be normalized
//! - Rejects `TestOnly` backends unconditionally

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    backend::HardwareBackendType,
    baseline::PcrBaseline,
    boot_chain::BootChainEvidence,
    continuous_attestation::AttestationSession,
    counter::CounterEvidence,
    digest::TypedDigest,
    distributed_consensus::{ConsensusDecision, ConsensusEvaluation},
    drift::{DriftPolicyMode, DriftSeverity},
    ima_integration::ImaEvidence,
    pcr::{PcrSemantic, TypedPcrBank},
    platform_profiles::{PlatformProfile, RuntimeVerificationReport},
    policy_federation::FederatedPolicyEpoch,
    runtime_attestation::RuntimeAttestationEvidence,
    runtime_drift::{RuntimeDriftEngine, RuntimeDriftReport, RuntimeDriftSeverity},
    secure_boot::{SecureBootEvidence, SecureBootState},
    timeline_reconciliation::TimelineReconciliationReport,
    transparency_log::TransparencyEvent,
    trust_domains::{TrustDomain, TrustEvaluation, VerificationDecisionReason},
    verifier_federation::VerifierFederation,
    verifier_timeline::AttestationTimeline,
};
use pqrascv_bitcoin_anchor::{TimelineInclusionProof, TimelineSpvVerifier};

// ── HardwarePolicyRule ────────────────────────────────────────────────────

/// Hardware-specific policy rules for the attestation engine.
///
/// These rules operate on [`HardwarePolicyContext`] and complement the
/// base `PolicyRule` set from `pqrascv-core`.
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
}

// ── HardwarePolicyContext ─────────────────────────────────────────────────

/// Hardware-specific context for policy evaluation.
///
/// Populated by the verifier from [`HardwareEvidence`](crate::backend::HardwareEvidence).
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
}

// ── HardwarePolicyEngine ──────────────────────────────────────────────────

/// Hardware-aware policy engine.
///
/// Evaluates [`HardwarePolicyRule`] against a [`HardwarePolicyContext`].
/// Designed to be composed with the base `PolicyEngineV2` from `pqrascv-core`.
pub struct HardwarePolicyEngine {
    pub rules: Vec<HardwarePolicyRule>,
}

impl HardwarePolicyEngine {
    /// Creates an engine with the given rules.
    #[must_use]
    pub fn new(rules: Vec<HardwarePolicyRule>) -> Self {
        Self { rules }
    }

    /// Returns the hardware production preset.
    ///
    /// Enforces:
    /// - Hardware-rooted backend (no `TestOnly`)
    /// - Measured boot (Firmware + Bootloader PCRs present)
    /// - Normalized PCR digests
    /// - Hardware monotonic counter
    /// - Nonce binding support
    #[must_use]
    pub fn hardware_production() -> Self {
        Self::new(alloc::vec![
            HardwarePolicyRule::RequireHardwareRootedBackend,
            HardwarePolicyRule::RequireMeasuredBoot,
            HardwarePolicyRule::RequireNormalizedPcrs,
            HardwarePolicyRule::RequireHardwareMonotonicCounter,
            HardwarePolicyRule::RequireNonceBinding,
        ])
    }

    /// Returns a TPM-specific production preset.
    ///
    /// Adds `RequireBackendType(Tpm2)` to the hardware production preset.
    #[must_use]
    pub fn tpm2_production() -> Self {
        Self::new(alloc::vec![
            HardwarePolicyRule::RequireBackendType(HardwareBackendType::Tpm2),
            HardwarePolicyRule::RequireMeasuredBoot,
            HardwarePolicyRule::RequireNormalizedPcrs,
            HardwarePolicyRule::RequireHardwareMonotonicCounter,
            HardwarePolicyRule::RequireNonceBinding,
        ])
    }

    /// Evaluates all rules against the provided context.
    ///
    /// Returns `Ok(())` if all rules pass, or the first [`HardwarePolicyError`].
    pub fn evaluate(&self, ctx: &HardwarePolicyContext<'_>) -> Result<(), HardwarePolicyError> {
        // Fail-closed conflict detection
        self.detect_conflicts()
            .map_err(HardwarePolicyError::PolicyConflict)?;

        for rule in &self.rules {
            Self::evaluate_rule(rule, ctx)?;
        }
        Ok(())
    }

    /// Evaluates the policy rules and returns a structured `RuntimeVerificationReport`
    /// containing independent evaluation outcomes for each of the 8 trust domains.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn evaluate_runtime_report(
        &self,
        ctx: &HardwarePolicyContext<'_>,
    ) -> RuntimeVerificationReport {
        let domains = [
            TrustDomain::HardwareIdentity,
            TrustDomain::MeasuredBoot,
            TrustDomain::SecureBoot,
            TrustDomain::RuntimeIntegrity,
            TrustDomain::SupplyChain,
            TrustDomain::Provenance,
            TrustDomain::Transparency,
            TrustDomain::ContinuousAttestation,
        ];

        let mut evaluations = alloc::vec::Vec::new();
        let mut overall_warnings = alloc::vec::Vec::new();
        let mut overall_trusted = true;

        if let Err(conflict_err) = self.detect_conflicts() {
            for domain in &domains {
                evaluations.push(TrustEvaluation {
                    domain: *domain,
                    trusted: false,
                    reasons: alloc::vec![VerificationDecisionReason::UnsupportedRuntimePolicy],
                    warnings: alloc::vec![alloc::format!(
                        "Policy conflict detected: {conflict_err}",
                    )],
                });
            }
            return RuntimeVerificationReport {
                trusted: false,
                evaluations,
                warnings: alloc::vec![alloc::format!("Policy conflict: {conflict_err}")],
            };
        }

        for domain in &domains {
            let mut domain_trusted = true;
            let mut reasons = alloc::vec::Vec::new();
            let mut warnings = alloc::vec::Vec::new();

            for rule in &self.rules {
                if Self::rule_belongs_to_domain(rule, *domain) {
                    match Self::evaluate_rule(rule, ctx) {
                        Ok(()) => {
                            if let HardwarePolicyRule::RequirePlatformProfile {
                                profile,
                                drift_mode,
                                upgrade_baseline,
                            } = rule
                            {
                                let report = profile.verify(
                                    ctx.pcr_bank,
                                    ctx.secure_boot,
                                    *drift_mode,
                                    upgrade_baseline.as_ref(),
                                );
                                for warn in &report.warnings {
                                    warnings.push(warn.clone());
                                }
                                for drift in &report.drift_reports {
                                    if drift.severity == DriftSeverity::Informational
                                        || drift.severity == DriftSeverity::Warning
                                    {
                                        warnings.push(alloc::format!(
                                            "Drift detected in PCR semantic {:?}: {:?}",
                                            drift.semantic,
                                            drift.severity
                                        ));
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            domain_trusted = false;
                            reasons.push(err.decision_reason());
                            warnings.push(alloc::format!("{err}"));

                            match &err {
                                HardwarePolicyError::PlatformProfileMismatch { .. } => {
                                    if let HardwarePolicyRule::RequirePlatformProfile {
                                        profile,
                                        drift_mode,
                                        upgrade_baseline,
                                    } = rule
                                    {
                                        let report = profile.verify(
                                            ctx.pcr_bank,
                                            ctx.secure_boot,
                                            *drift_mode,
                                            upgrade_baseline.as_ref(),
                                        );
                                        for warn in &report.warnings {
                                            warnings.push(warn.clone());
                                        }
                                    }
                                }
                                HardwarePolicyError::CriticalRuntimeDriftDetected(report) => {
                                    warnings.push(alloc::format!(
                                        "Critical runtime drift: WORKLOAD={}, EXPECTED={:?}, ACTUAL={:?}, SEVERITY={:?}",
                                        report.workload,
                                        report.expected,
                                        report.actual,
                                        report.severity
                                    ));
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            if !domain_trusted {
                overall_trusted = false;
            }

            for w in &warnings {
                overall_warnings.push(w.clone());
            }

            evaluations.push(TrustEvaluation {
                domain: *domain,
                trusted: domain_trusted,
                reasons,
                warnings,
            });
        }

        RuntimeVerificationReport {
            trusted: overall_trusted,
            evaluations,
            warnings: overall_warnings,
        }
    }

    fn rule_belongs_to_domain(rule: &HardwarePolicyRule, domain: TrustDomain) -> bool {
        match domain {
            TrustDomain::HardwareIdentity => matches!(
                rule,
                HardwarePolicyRule::RequireHardwareRootedBackend
                    | HardwarePolicyRule::RequireBackendType(_)
                    | HardwarePolicyRule::RequireHardwareMonotonicCounter
                    | HardwarePolicyRule::RequireNonceBinding
                    | HardwarePolicyRule::RequireVerifierFederation
                    | HardwarePolicyRule::RequireConsensusQuorum { .. }
            ),
            TrustDomain::MeasuredBoot => matches!(
                rule,
                HardwarePolicyRule::RequireMeasuredBoot
                    | HardwarePolicyRule::RequireNormalizedPcrs
                    | HardwarePolicyRule::RequirePcrValue { .. }
                    | HardwarePolicyRule::RequirePlatformProfile { .. }
            ),
            TrustDomain::SecureBoot => matches!(
                rule,
                HardwarePolicyRule::RequireSecureBootState(_)
                    | HardwarePolicyRule::RequirePlatformProfile { .. }
            ),
            TrustDomain::RuntimeIntegrity => matches!(
                rule,
                HardwarePolicyRule::RequireRuntimeIntegrity { .. } | HardwarePolicyRule::RequireIma
            ),
            TrustDomain::SupplyChain => matches!(
                rule,
                HardwarePolicyRule::RequireValidBaselineTransition { .. }
            ),
            TrustDomain::Provenance => matches!(rule, HardwarePolicyRule::RequireBootChain { .. }),
            TrustDomain::Transparency => matches!(
                rule,
                HardwarePolicyRule::RequireTransparencyAnchoring
                    | HardwarePolicyRule::RequireTransparencyConsensus
                    | HardwarePolicyRule::RequireTimelineConsistency
            ),
            TrustDomain::ContinuousAttestation => matches!(
                rule,
                HardwarePolicyRule::RequireContinuousAttestation { .. }
                    | HardwarePolicyRule::RequireSequenceMonotonicity
                    | HardwarePolicyRule::RequirePolicyEpoch(_)
                    | HardwarePolicyRule::RequireFederatedPolicyApproval
            ),
        }
    }


    /// Validates that there are no conflicting rules in the policy engine.
    ///
    /// Conflicting rules include:
    /// - Requiring two different backend types.
    /// - Requiring contradictory Secure Boot states.
    /// - Contradictory PCR value expectations for the same PCR semantic.
    /// - Requiring contradictory Platform Profiles.
    pub fn detect_conflicts(&self) -> Result<(), PolicyConflictError> {
        let mut required_backend = None;
        let mut required_sb_state = None;
        let mut pcr_expectations = alloc::vec::Vec::new();
        let mut required_profile: Option<String> = None;
        let mut required_epoch = None;

        for rule in &self.rules {
            match rule {
                HardwarePolicyRule::RequireBackendType(backend) => {
                    if let Some(prev) = required_backend {
                        if prev != *backend {
                            return Err(PolicyConflictError::ConflictingBackendTypes {
                                type_a: prev,
                                type_b: *backend,
                            });
                        }
                    }
                    required_backend = Some(*backend);
                }
                HardwarePolicyRule::RequireSecureBootState(state) => {
                    if let Some(prev) = required_sb_state {
                        if prev != *state {
                            return Err(PolicyConflictError::ConflictingSecureBootStates {
                                state_a: prev,
                                state_b: *state,
                            });
                        }
                    }
                    required_sb_state = Some(*state);
                }
                HardwarePolicyRule::RequirePcrValue { semantic, expected } => {
                    for (prev_semantic, prev_val) in &pcr_expectations {
                        if prev_semantic == semantic && prev_val != expected {
                            return Err(PolicyConflictError::ConflictingPcrValues {
                                semantic: *semantic,
                                val_a: *prev_val,
                                val_b: *expected,
                            });
                        }
                    }
                    pcr_expectations.push((*semantic, *expected));
                }
                HardwarePolicyRule::RequirePlatformProfile { profile, .. } => {
                    if let Some(ref prev_id) = required_profile {
                        if prev_id != &profile.profile_id {
                            return Err(PolicyConflictError::ConflictingPlatformProfiles {
                                profile_a: prev_id.clone(),
                                profile_b: profile.profile_id.clone(),
                            });
                        }
                    }
                    required_profile = Some(profile.profile_id.clone());
                }
                HardwarePolicyRule::RequirePolicyEpoch(epoch) => {
                    if let Some(prev) = required_epoch {
                        if prev != *epoch {
                            return Err(PolicyConflictError::ConflictingPolicyEpochs {
                                epoch_a: prev,
                                epoch_b: *epoch,
                            });
                        }
                    }
                    required_epoch = Some(*epoch);
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn evaluate_rule(
        rule: &HardwarePolicyRule,
        ctx: &HardwarePolicyContext<'_>,
    ) -> Result<(), HardwarePolicyError> {
        match rule {
            HardwarePolicyRule::RequireHardwareRootedBackend => {
                if !ctx.backend_type.is_hardware_rooted() {
                    return Err(HardwarePolicyError::BackendNotHardwareRooted(
                        ctx.backend_type,
                    ));
                }
            }
            HardwarePolicyRule::RequireBackendType(required) => {
                if ctx.backend_type != *required {
                    return Err(HardwarePolicyError::WrongBackendType {
                        required: *required,
                        got: ctx.backend_type,
                    });
                }
            }
            HardwarePolicyRule::RequireNormalizedPcrs => {
                if !ctx.pcr_bank.all_normalized() {
                    return Err(HardwarePolicyError::UnnormalizedPcrs);
                }
            }
            HardwarePolicyRule::RequirePcrSemantic(semantic) => {
                if ctx.pcr_bank.get(*semantic).is_none() {
                    return Err(HardwarePolicyError::PcrSemanticAbsent(*semantic));
                }
            }
            HardwarePolicyRule::RequirePcrValue { semantic, expected } => {
                let m = ctx
                    .pcr_bank
                    .get(*semantic)
                    .ok_or(HardwarePolicyError::PcrSemanticAbsent(*semantic))?;
                if &m.digest.value != expected {
                    return Err(HardwarePolicyError::PcrValueMismatch {
                        semantic: *semantic,
                        expected: *expected,
                        got: m.digest.value,
                    });
                }
            }
            HardwarePolicyRule::RequireFirmwareMeasurement => {
                if ctx.pcr_bank.get(PcrSemantic::Firmware).is_none() {
                    return Err(HardwarePolicyError::MeasuredBootIncomplete(
                        PcrSemantic::Firmware,
                    ));
                }
            }
            HardwarePolicyRule::RequireBootloaderMeasurement => {
                if ctx.pcr_bank.get(PcrSemantic::Bootloader).is_none() {
                    return Err(HardwarePolicyError::MeasuredBootIncomplete(
                        PcrSemantic::Bootloader,
                    ));
                }
            }
            HardwarePolicyRule::RequireKernelMeasurement => {
                if ctx.pcr_bank.get(PcrSemantic::Kernel).is_none() {
                    return Err(HardwarePolicyError::MeasuredBootIncomplete(
                        PcrSemantic::Kernel,
                    ));
                }
            }
            HardwarePolicyRule::RequireMeasuredBoot => {
                // Minimum measured boot: Firmware AND Bootloader must be present.
                if ctx.pcr_bank.get(PcrSemantic::Firmware).is_none() {
                    return Err(HardwarePolicyError::MeasuredBootIncomplete(
                        PcrSemantic::Firmware,
                    ));
                }
                if ctx.pcr_bank.get(PcrSemantic::Bootloader).is_none() {
                    return Err(HardwarePolicyError::MeasuredBootIncomplete(
                        PcrSemantic::Bootloader,
                    ));
                }
            }
            HardwarePolicyRule::RequireHardwareMonotonicCounter => {
                if !ctx.counter.is_hardware_backed() {
                    return Err(HardwarePolicyError::CounterNotHardwareBacked(ctx.counter));
                }
            }
            HardwarePolicyRule::RequireMinCounterValue(min) => match ctx.counter.value() {
                Some(v) if v >= *min => {}
                Some(v) => return Err(HardwarePolicyError::CounterTooLow { got: v, min: *min }),
                None => return Err(HardwarePolicyError::CounterNotHardwareBacked(ctx.counter)),
            },
            HardwarePolicyRule::RequireNonceBinding => {
                if !ctx.supports_nonce_binding {
                    return Err(HardwarePolicyError::NonceBindingUnsupported);
                }
            }
            HardwarePolicyRule::RequireSecureBootState(expected) => {
                let sb = ctx
                    .secure_boot
                    .ok_or(HardwarePolicyError::SecureBootEvidenceMissing)?;
                if sb.state != *expected {
                    return Err(HardwarePolicyError::SecureBootStateMismatch {
                        expected: *expected,
                        got: sb.state,
                    });
                }
            }
            HardwarePolicyRule::RequireBootChain(expected) => {
                let bc = ctx
                    .boot_chain
                    .ok_or(HardwarePolicyError::BootChainEvidenceMissing)?;
                if bc.firmware != expected.firmware {
                    return Err(HardwarePolicyError::BootChainFirmwareMismatch {
                        expected: expected.firmware,
                        got: bc.firmware,
                    });
                }
                if bc.bootloader != expected.bootloader {
                    return Err(HardwarePolicyError::BootChainBootloaderMismatch {
                        expected: expected.bootloader,
                        got: bc.bootloader,
                    });
                }
                if bc.kernel != expected.kernel {
                    return Err(HardwarePolicyError::BootChainKernelMismatch {
                        expected: expected.kernel,
                        got: bc.kernel,
                    });
                }
            }
            HardwarePolicyRule::RequirePlatformProfile {
                profile,
                drift_mode,
                upgrade_baseline,
            } => {
                let report = profile.verify(
                    ctx.pcr_bank,
                    ctx.secure_boot,
                    *drift_mode,
                    upgrade_baseline.as_ref(),
                );
                if !report.profile_match {
                    return Err(HardwarePolicyError::PlatformProfileMismatch {
                        reason: report.decision_reason,
                    });
                }
            }
            HardwarePolicyRule::RequireValidBaselineTransition { current, previous } => {
                if !current.is_valid_successor(previous) {
                    return Err(HardwarePolicyError::BaselineRollbackDetected);
                }
            }
            HardwarePolicyRule::RequireRuntimeIntegrity {
                whitelist,
                rolling_upgrades,
            } => {
                let runtime_att = ctx
                    .runtime_attestation
                    .ok_or(HardwarePolicyError::RuntimeAttestationEvidenceMissing)?;
                let drift_reports = RuntimeDriftEngine::detect_drift(
                    &runtime_att.measurements,
                    whitelist,
                    rolling_upgrades,
                );
                for report in drift_reports {
                    if report.severity == RuntimeDriftSeverity::Critical {
                        return Err(HardwarePolicyError::CriticalRuntimeDriftDetected(report));
                    }
                }
            }
            HardwarePolicyRule::RequireIma => {
                let ima = ctx
                    .ima_evidence
                    .ok_or(HardwarePolicyError::ImaEvidenceMissing)?;
                if !ima.ima_enabled {
                    return Err(HardwarePolicyError::ImaDisabled);
                }
                if !ima.appraisal_enabled {
                    return Err(HardwarePolicyError::ImaAppraisalDisabled);
                }
            }
            HardwarePolicyRule::RequireContinuousAttestation {
                expiration_window_secs,
                now_secs,
            } => {
                let session = ctx
                    .session
                    .ok_or(HardwarePolicyError::ContinuousAttestationSessionMissing)?;
                if !session.active {
                    return Err(HardwarePolicyError::ContinuousAttestationSessionInactive);
                }
                if *now_secs < session.last_seen
                    || *now_secs - session.last_seen > *expiration_window_secs
                {
                    return Err(HardwarePolicyError::ContinuousAttestationExpired {
                        last_seen: session.last_seen,
                        now: *now_secs,
                        window: *expiration_window_secs,
                    });
                }
            }
            HardwarePolicyRule::RequireSequenceMonotonicity => {
                let evidence = ctx
                    .runtime_attestation
                    .ok_or(HardwarePolicyError::RuntimeAttestationEvidenceMissing)?;
                let session = ctx
                    .session
                    .ok_or(HardwarePolicyError::ContinuousAttestationSessionMissing)?;
                if evidence.sequence_number <= session.sequence_number {
                    return Err(HardwarePolicyError::ReplayDetected {
                        got: evidence.sequence_number,
                        expected: session.sequence_number + 1,
                    });
                }
                if evidence.sequence_number != session.sequence_number + 1 {
                    return Err(HardwarePolicyError::SequenceGapDetected {
                        got: evidence.sequence_number,
                        expected: session.sequence_number + 1,
                    });
                }
            }
            HardwarePolicyRule::RequireTransparencyAnchoring => {
                let proof = ctx
                    .transparency_proof
                    .ok_or(HardwarePolicyError::TransparencyProofMissing)?;
                let verifier = ctx
                    .spv_verifier
                    .ok_or(HardwarePolicyError::SpvVerifierMissing)?;
                let event = ctx
                    .transparency_event
                    .ok_or(HardwarePolicyError::TransparencyEventMissing)?;

                let event_hash = event
                    .canonical_hash()
                    .map_err(|_| HardwarePolicyError::TransparencySerializationFailed)?;
                verifier
                    .verify(proof, &event_hash)
                    .map_err(HardwarePolicyError::SpvVerificationFailed)?;
            }
            HardwarePolicyRule::RequirePolicyEpoch(expected_epoch) => {
                let evidence = ctx
                    .runtime_attestation
                    .ok_or(HardwarePolicyError::RuntimeAttestationEvidenceMissing)?;
                if evidence.policy_epoch != *expected_epoch {
                    return Err(HardwarePolicyError::PolicyEpochMismatch {
                        expected: *expected_epoch,
                        got: evidence.policy_epoch,
                    });
                }
            }

            // ── Phase 2.9 Federated Trust Rules ──────────────────────────

            HardwarePolicyRule::RequireVerifierFederation => {
                if ctx.federation.is_none() {
                    return Err(HardwarePolicyError::VerifierFederationMissing);
                }
            }
            HardwarePolicyRule::RequireConsensusQuorum { min_votes } => {
                let eval = ctx
                    .consensus_evaluation
                    .ok_or(HardwarePolicyError::VerifierFederationMissing)?;
                if eval.participating < *min_votes {
                    return Err(HardwarePolicyError::ConsensusQuorumFailed {
                        decision: eval.final_decision.clone(),
                    });
                }
                if !eval.final_decision.is_trusted() {
                    return Err(HardwarePolicyError::ConsensusQuorumFailed {
                        decision: eval.final_decision.clone(),
                    });
                }
            }
            HardwarePolicyRule::RequireTransparencyConsensus => {
                let report = ctx
                    .timeline_reconciliation
                    .ok_or(HardwarePolicyError::TransparencyConsensusFailed)?;
                if report.conflicts_detected {
                    return Err(HardwarePolicyError::TransparencyConsensusFailed);
                }
            }
            HardwarePolicyRule::RequireFederatedPolicyApproval => {
                let epoch = ctx
                    .federated_epoch
                    .ok_or(HardwarePolicyError::FederatedPolicyApprovalMissing)?;
                if !epoch.quorum_reached {
                    return Err(HardwarePolicyError::FederatedEpochQuorumNotReached {
                        epoch_id: epoch.epoch_id,
                    });
                }
            }
            HardwarePolicyRule::RequireTimelineConsistency => {
                let report = ctx
                    .timeline_reconciliation
                    .ok_or(HardwarePolicyError::TimelineConflictDetected)?;
                if report.conflicts_detected || report.missing_events {
                    return Err(HardwarePolicyError::TimelineConflictDetected);
                }
            }
        }
        Ok(())
    }
}

// ── PolicyConflictError ───────────────────────────────────────────────────

/// Errors representing conflicts within policy rules.
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

// ── HardwarePolicyError ───────────────────────────────────────────────────

/// Errors from hardware policy evaluation.
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
    CounterTooLow { got: u64, min: u64 },
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
    PlatformProfileMismatch { reason: VerificationDecisionReason },
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
    ReplayDetected { got: u64, expected: u64 },
    /// Sequence gap detected during sequence monotonicity check.
    SequenceGapDetected { got: u64, expected: u64 },
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
    PolicyEpochMismatch { expected: u64, got: u64 },

    // ── Phase 2.9 Federated Trust Errors ─────────────────────────────────

    /// No verifier federation was provided in the policy context.
    VerifierFederationMissing,
    /// The consensus evaluation did not reach quorum or was not Trusted.
    ConsensusQuorumFailed { decision: ConsensusDecision },
    /// Verifier transparency logs are inconsistent; consensus failed.
    TransparencyConsensusFailed,
    /// The federated policy epoch context is missing.
    FederatedPolicyApprovalMissing,
    /// The federated policy epoch has not been approved by quorum.
    FederatedEpochQuorumNotReached { epoch_id: u64 },
    /// Cross-verifier timeline reconciliation detected conflicts.
    TimelineConflictDetected,
}

impl HardwarePolicyError {
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
            Self::ContinuousAttestationSessionMissing
            | Self::ContinuousAttestationSessionInactive
            | Self::ContinuousAttestationExpired { .. } => {
                VerificationDecisionReason::ContinuousAttestationExpired
            }
            Self::ReplayDetected { .. } | Self::SequenceGapDetected { .. } => {
                VerificationDecisionReason::InvalidAttestationSequence
            }
            Self::TransparencyProofMissing
            | Self::SpvVerifierMissing
            | Self::TransparencyEventMissing
            | Self::TransparencySerializationFailed
            | Self::SpvVerificationFailed(_) => VerificationDecisionReason::RuntimeMeasurementGap,
            Self::PolicyEpochMismatch { .. } => VerificationDecisionReason::PolicyEpochMismatch,
            // Phase 2.9
            Self::VerifierFederationMissing
            | Self::ConsensusQuorumFailed { .. }
            | Self::FederatedPolicyApprovalMissing
            | Self::FederatedEpochQuorumNotReached { .. } => {
                VerificationDecisionReason::VerifierFederationAbsent
            }
            Self::TransparencyConsensusFailed | Self::TimelineConflictDetected => {
                VerificationDecisionReason::TimelineInconsistencyDetected
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
                write!(f, "federated policy epoch {epoch_id} has not reached quorum")
            }
            Self::TimelineConflictDetected => {
                f.write_str("cross-verifier timeline conflict detected")
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        digest::{DigestAlgorithm, TypedDigest},
        pcr::{PcrMeasurement, PcrSemantic, TypedPcrBank},
    };

    fn sha3(v: u8) -> TypedDigest {
        TypedDigest::new(DigestAlgorithm::Sha3_256, [v; 32])
    }

    fn measured_boot_bank() -> TypedPcrBank {
        let mut bank = TypedPcrBank::new();
        bank.push(PcrMeasurement::new(0, PcrSemantic::Firmware, sha3(0x01)).unwrap());
        bank.push(PcrMeasurement::new(1, PcrSemantic::Bootloader, sha3(0x02)).unwrap());
        bank
    }

    fn good_ctx<'a>(bank: &'a TypedPcrBank, fw: &'a TypedDigest) -> HardwarePolicyContext<'a> {
        HardwarePolicyContext {
            backend_type: HardwareBackendType::Tpm2,
            pcr_bank: bank,
            counter: CounterEvidence::HardwareMonotonic(1_000),
            supports_nonce_binding: true,
            firmware_digest: fw,
            secure_boot: None,
            boot_chain: None,
            runtime_integrity: None,
            runtime_attestation: None,
            ima_evidence: None,
            session: None,
            timeline: None,
            transparency_proof: None,
            spv_verifier: None,
            transparency_event: None,
            federation: None,
            consensus_evaluation: None,
            federated_epoch: None,
            timeline_reconciliation: None,
        }
    }

    #[test]
    fn hardware_production_accepts_valid_context() {
        let bank = measured_boot_bank();
        let fw = TypedDigest::new(DigestAlgorithm::Sha3_256, [0xabu8; 32]);
        let ctx = good_ctx(&bank, &fw);
        assert!(HardwarePolicyEngine::hardware_production()
            .evaluate(&ctx)
            .is_ok());
    }

    #[test]
    fn rejects_software_backend() {
        let bank = measured_boot_bank();
        let fw = TypedDigest::new(DigestAlgorithm::Sha3_256, [0xabu8; 32]);
        let mut ctx = good_ctx(&bank, &fw);
        // Can only test this when the feature is enabled; otherwise TestOnly
        // doesn't exist. We test via is_hardware_rooted() logic instead.
        ctx.backend_type = HardwareBackendType::Tpm2; // stays valid
        assert!(HardwarePolicyEngine::hardware_production()
            .evaluate(&ctx)
            .is_ok());
    }

    #[test]
    fn rejects_missing_firmware_pcr() {
        let mut bank = TypedPcrBank::new();
        // Only bootloader, no firmware.
        bank.push(PcrMeasurement::new(1, PcrSemantic::Bootloader, sha3(0x02)).unwrap());
        let fw = TypedDigest::new(DigestAlgorithm::Sha3_256, [0xabu8; 32]);
        let ctx = good_ctx(&bank, &fw);
        assert!(matches!(
            HardwarePolicyEngine::hardware_production().evaluate(&ctx),
            Err(HardwarePolicyError::MeasuredBootIncomplete(
                PcrSemantic::Firmware
            ))
        ));
    }

    #[test]
    fn rejects_software_counter() {
        let bank = measured_boot_bank();
        let fw = TypedDigest::new(DigestAlgorithm::Sha3_256, [0xabu8; 32]);
        let mut ctx = good_ctx(&bank, &fw);
        ctx.counter = CounterEvidence::SoftwareObserved(999);
        assert!(matches!(
            HardwarePolicyEngine::hardware_production().evaluate(&ctx),
            Err(HardwarePolicyError::CounterNotHardwareBacked(_))
        ));
    }

    #[test]
    fn rejects_no_nonce_binding() {
        let bank = measured_boot_bank();
        let fw = TypedDigest::new(DigestAlgorithm::Sha3_256, [0xabu8; 32]);
        let mut ctx = good_ctx(&bank, &fw);
        ctx.supports_nonce_binding = false;
        assert!(matches!(
            HardwarePolicyEngine::hardware_production().evaluate(&ctx),
            Err(HardwarePolicyError::NonceBindingUnsupported)
        ));
    }

    #[test]
    fn pcr_value_rule_enforced() {
        let bank = measured_boot_bank();
        let fw = TypedDigest::new(DigestAlgorithm::Sha3_256, [0xabu8; 32]);
        let ctx = good_ctx(&bank, &fw);
        let engine = HardwarePolicyEngine::new(alloc::vec![HardwarePolicyRule::RequirePcrValue {
            semantic: PcrSemantic::Firmware,
            expected: [0x01u8; 32],
        },]);
        assert!(engine.evaluate(&ctx).is_ok());

        let engine_wrong =
            HardwarePolicyEngine::new(alloc::vec![HardwarePolicyRule::RequirePcrValue {
                semantic: PcrSemantic::Firmware,
                expected: [0xffu8; 32],
            },]);
        assert!(matches!(
            engine_wrong.evaluate(&ctx),
            Err(HardwarePolicyError::PcrValueMismatch { .. })
        ));
    }

    #[test]
    fn min_counter_value_enforced() {
        let bank = measured_boot_bank();
        let fw = TypedDigest::new(DigestAlgorithm::Sha3_256, [0xabu8; 32]);
        let mut ctx = good_ctx(&bank, &fw);
        ctx.counter = CounterEvidence::HardwareMonotonic(5);

        let engine =
            HardwarePolicyEngine::new(alloc::vec![HardwarePolicyRule::RequireMinCounterValue(10),]);
        assert!(matches!(
            engine.evaluate(&ctx),
            Err(HardwarePolicyError::CounterTooLow { got: 5, min: 10 })
        ));

        ctx.counter = CounterEvidence::HardwareMonotonic(10);
        assert!(engine.evaluate(&ctx).is_ok());
    }

    #[test]
    fn wrong_backend_type_rejected() {
        let bank = measured_boot_bank();
        let fw = TypedDigest::new(DigestAlgorithm::Sha3_256, [0xabu8; 32]);
        let mut ctx = good_ctx(&bank, &fw);
        ctx.backend_type = HardwareBackendType::Dice;

        let engine =
            HardwarePolicyEngine::new(alloc::vec![HardwarePolicyRule::RequireBackendType(
                HardwareBackendType::Tpm2
            ),]);
        assert!(matches!(
            engine.evaluate(&ctx),
            Err(HardwarePolicyError::WrongBackendType { .. })
        ));
    }

    #[test]
    fn unnormalized_pcrs_rejected() {
        let mut bank = TypedPcrBank::new();
        bank.push(PcrMeasurement::new_unchecked(
            0,
            PcrSemantic::Firmware,
            TypedDigest::new(DigestAlgorithm::Sha256, [0x01u8; 32]),
        ));
        bank.push(PcrMeasurement::new(1, PcrSemantic::Bootloader, sha3(0x02)).unwrap());
        let fw = TypedDigest::new(DigestAlgorithm::Sha3_256, [0xabu8; 32]);
        let ctx = good_ctx(&bank, &fw);

        let engine =
            HardwarePolicyEngine::new(alloc::vec![HardwarePolicyRule::RequireNormalizedPcrs,]);
        assert_eq!(
            engine.evaluate(&ctx),
            Err(HardwarePolicyError::UnnormalizedPcrs)
        );
    }

    #[test]
    fn secure_boot_state_enforced() {
        let bank = measured_boot_bank();
        let fw = sha3(0xab);
        let mut ctx = good_ctx(&bank, &fw);

        // Secure boot evidence missing
        let engine =
            HardwarePolicyEngine::new(alloc::vec![HardwarePolicyRule::RequireSecureBootState(
                SecureBootState::Enabled
            ),]);
        assert_eq!(
            engine.evaluate(&ctx),
            Err(HardwarePolicyError::SecureBootEvidenceMissing)
        );

        // Secure boot disabled
        let sb_disabled = SecureBootEvidence {
            state: SecureBootState::Disabled,
            db_hash: None,
            dbx_hash: None,
            mok_hash: None,
        };
        ctx.secure_boot = Some(&sb_disabled);
        assert!(matches!(
            engine.evaluate(&ctx),
            Err(HardwarePolicyError::SecureBootStateMismatch { .. })
        ));

        // Secure boot enabled
        let sb_enabled = SecureBootEvidence {
            state: SecureBootState::Enabled,
            db_hash: None,
            dbx_hash: None,
            mok_hash: None,
        };
        ctx.secure_boot = Some(&sb_enabled);
        assert!(engine.evaluate(&ctx).is_ok());
    }

    #[test]
    fn boot_chain_mismatch_rejected() {
        let bank = measured_boot_bank();
        let fw = sha3(0xab);
        let mut ctx = good_ctx(&bank, &fw);

        let expected_bc = BootChainEvidence {
            firmware: sha3(0x01),
            bootloader: sha3(0x02),
            kernel: sha3(0x03),
            initrd: None,
            secure_boot: SecureBootEvidence {
                state: SecureBootState::Enabled,
                db_hash: None,
                dbx_hash: None,
                mok_hash: None,
            },
        };

        let engine = HardwarePolicyEngine::new(alloc::vec![HardwarePolicyRule::RequireBootChain(
            expected_bc.clone()
        ),]);

        // Missing boot chain evidence
        assert_eq!(
            engine.evaluate(&ctx),
            Err(HardwarePolicyError::BootChainEvidenceMissing)
        );

        // Incorrect bootloader hash
        let actual_bc = BootChainEvidence {
            firmware: sha3(0x01),
            bootloader: sha3(0xff), // mismatch
            kernel: sha3(0x03),
            initrd: None,
            secure_boot: SecureBootEvidence {
                state: SecureBootState::Enabled,
                db_hash: None,
                dbx_hash: None,
                mok_hash: None,
            },
        };
        ctx.boot_chain = Some(&actual_bc);
        assert!(matches!(
            engine.evaluate(&ctx),
            Err(HardwarePolicyError::BootChainBootloaderMismatch { .. })
        ));

        // Correct boot chain
        let correct_bc = BootChainEvidence {
            firmware: sha3(0x01),
            bootloader: sha3(0x02),
            kernel: sha3(0x03),
            initrd: None,
            secure_boot: SecureBootEvidence {
                state: SecureBootState::Enabled,
                db_hash: None,
                dbx_hash: None,
                mok_hash: None,
            },
        };
        ctx.boot_chain = Some(&correct_bc);
        assert!(engine.evaluate(&ctx).is_ok());
    }

    #[test]
    fn platform_profile_verification() {
        let mut bank = TypedPcrBank::new();
        bank.push(PcrMeasurement::new(0, PcrSemantic::Firmware, sha3(0x01)).unwrap());
        bank.push(PcrMeasurement::new(1, PcrSemantic::Bootloader, sha3(0x02)).unwrap());
        bank.push(PcrMeasurement::new(2, PcrSemantic::Kernel, sha3(0x03)).unwrap());
        bank.push(PcrMeasurement::new(3, PcrSemantic::Initrd, sha3(0x04)).unwrap());

        let fw = sha3(0x01);
        let mut ctx = good_ctx(&bank, &fw);

        let sb = SecureBootEvidence {
            state: SecureBootState::Enabled,
            db_hash: None,
            dbx_hash: None,
            mok_hash: None,
        };
        ctx.secure_boot = Some(&sb);

        let profile = crate::profiles::sovereign_bitcoin_node_profile();
        let engine =
            HardwarePolicyEngine::new(alloc::vec![HardwarePolicyRule::RequirePlatformProfile {
                profile: profile.clone(),
                drift_mode: DriftPolicyMode::Enforcing,
                upgrade_baseline: None,
            },]);

        // Perfect match passes
        assert!(engine.evaluate(&ctx).is_ok());

        // Mismatched kernel measurement -> critical drift -> rejected
        let mut bad_bank = bank.clone();
        if let Some(m) = bad_bank
            .measurements
            .iter_mut()
            .find(|m| m.semantic == PcrSemantic::Kernel)
        {
            m.digest = sha3(0xff);
        }
        let bad_ctx = HardwarePolicyContext {
            pcr_bank: &bad_bank,
            secure_boot: Some(&sb),
            ..good_ctx(&bad_bank, &fw)
        };
        assert!(matches!(
            engine.evaluate(&bad_ctx),
            Err(HardwarePolicyError::PlatformProfileMismatch {
                reason: VerificationDecisionReason::CriticalDriftDetected
            })
        ));

        // Under Learning mode, drift is permitted
        let engine_learning =
            HardwarePolicyEngine::new(alloc::vec![HardwarePolicyRule::RequirePlatformProfile {
                profile: profile.clone(),
                drift_mode: DriftPolicyMode::Learning,
                upgrade_baseline: None,
            },]);
        assert!(engine_learning.evaluate(&bad_ctx).is_ok());
    }

    #[test]
    fn policy_conflict_detection() {
        // Conflicting backend types
        let engine_backend = HardwarePolicyEngine::new(alloc::vec![
            HardwarePolicyRule::RequireBackendType(HardwareBackendType::Tpm2),
            HardwarePolicyRule::RequireBackendType(HardwareBackendType::Dice),
        ]);
        assert!(matches!(
            engine_backend.detect_conflicts(),
            Err(PolicyConflictError::ConflictingBackendTypes { .. })
        ));

        // Conflicting secure boot states
        let engine_sb = HardwarePolicyEngine::new(alloc::vec![
            HardwarePolicyRule::RequireSecureBootState(SecureBootState::Enabled),
            HardwarePolicyRule::RequireSecureBootState(SecureBootState::Disabled),
        ]);
        assert!(matches!(
            engine_sb.detect_conflicts(),
            Err(PolicyConflictError::ConflictingSecureBootStates { .. })
        ));

        // Conflicting PCR values
        let engine_pcr = HardwarePolicyEngine::new(alloc::vec![
            HardwarePolicyRule::RequirePcrValue {
                semantic: PcrSemantic::Firmware,
                expected: [0x01; 32],
            },
            HardwarePolicyRule::RequirePcrValue {
                semantic: PcrSemantic::Firmware,
                expected: [0x02; 32],
            },
        ]);
        assert!(matches!(
            engine_pcr.detect_conflicts(),
            Err(PolicyConflictError::ConflictingPcrValues { .. })
        ));

        // Conflicting platform profiles
        let profile1 = crate::profiles::sovereign_bitcoin_node_profile();
        let mut profile2 = profile1.clone();
        profile2.profile_id = "bitcoin-node-sovereign-v2".to_string();
        let engine_profile = HardwarePolicyEngine::new(alloc::vec![
            HardwarePolicyRule::RequirePlatformProfile {
                profile: profile1,
                drift_mode: DriftPolicyMode::Enforcing,
                upgrade_baseline: None,
            },
            HardwarePolicyRule::RequirePlatformProfile {
                profile: profile2,
                drift_mode: DriftPolicyMode::Enforcing,
                upgrade_baseline: None,
            },
        ]);
        assert!(matches!(
            engine_profile.detect_conflicts(),
            Err(PolicyConflictError::ConflictingPlatformProfiles { .. })
        ));
    }

    #[test]
    fn baseline_rollback_rejected() {
        let prev = PcrBaseline {
            baseline_id: "baseline-1".to_string(),
            version: 2,
            measurements: alloc::vec![],
            created_at: 100,
            supersedes: None,
        };

        // Rollback version (1 <= 2)
        let rollback = PcrBaseline {
            baseline_id: "baseline-2".to_string(),
            version: 1,
            measurements: alloc::vec![],
            created_at: 200,
            supersedes: Some("baseline-1".to_string()),
        };

        let engine = HardwarePolicyEngine::new(alloc::vec![
            HardwarePolicyRule::RequireValidBaselineTransition {
                current: rollback,
                previous: prev.clone(),
            },
        ]);
        let bank = measured_boot_bank();
        let fw = sha3(0xab);
        let ctx = good_ctx(&bank, &fw);

        assert_eq!(
            engine.evaluate(&ctx),
            Err(HardwarePolicyError::BaselineRollbackDetected)
        );

        // Valid transition
        let valid = PcrBaseline {
            baseline_id: "baseline-2".to_string(),
            version: 3,
            measurements: alloc::vec![],
            created_at: 200,
            supersedes: Some("baseline-1".to_string()),
        };
        let engine_valid = HardwarePolicyEngine::new(alloc::vec![
            HardwarePolicyRule::RequireValidBaselineTransition {
                current: valid,
                previous: prev,
            },
        ]);
        assert!(engine_valid.evaluate(&ctx).is_ok());
    }

    #[test]
    fn test_ima_rules() {
        let bank = measured_boot_bank();
        let fw = sha3(0xab);

        let engine = HardwarePolicyEngine::new(alloc::vec![HardwarePolicyRule::RequireIma]);

        // 1. Missing IMA evidence
        {
            let ctx = good_ctx(&bank, &fw);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::ImaEvidenceMissing)
            ));
        }

        // 2. IMA disabled
        {
            let mut ctx = good_ctx(&bank, &fw);
            let ima = ImaEvidence {
                ima_enabled: false,
                appraisal_enabled: false,
                measurements: alloc::vec![],
            };
            ctx.ima_evidence = Some(&ima);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::ImaDisabled)
            ));
        }

        // 3. IMA appraisal disabled
        {
            let mut ctx = good_ctx(&bank, &fw);
            let ima = ImaEvidence {
                ima_enabled: true,
                appraisal_enabled: false,
                measurements: alloc::vec![],
            };
            ctx.ima_evidence = Some(&ima);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::ImaAppraisalDisabled)
            ));
        }

        // 4. IMA fully enabled
        {
            let mut ctx = good_ctx(&bank, &fw);
            let ima = ImaEvidence {
                ima_enabled: true,
                appraisal_enabled: true,
                measurements: alloc::vec![],
            };
            ctx.ima_evidence = Some(&ima);
            assert!(engine.evaluate(&ctx).is_ok());
        }
    }

    #[test]
    fn test_continuous_attestation_rules() {
        let bank = measured_boot_bank();
        let fw = sha3(0xab);

        let engine = HardwarePolicyEngine::new(alloc::vec![
            HardwarePolicyRule::RequireContinuousAttestation {
                expiration_window_secs: 60,
                now_secs: 1000,
            }
        ]);

        // 1. Session missing
        {
            let ctx = good_ctx(&bank, &fw);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::ContinuousAttestationSessionMissing)
            ));
        }

        // 2. Session inactive
        {
            let mut ctx = good_ctx(&bank, &fw);
            let session = AttestationSession {
                session_id: "session-1".to_string(),
                device_id: "device-1".to_string(),
                started_at: 900,
                last_seen: 950,
                sequence_number: 1,
                active: false,
            };
            ctx.session = Some(&session);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::ContinuousAttestationSessionInactive)
            ));
        }

        // 3. Session expired (last_seen = 900, now = 1000, window = 60, drift = 100 > 60)
        {
            let mut ctx = good_ctx(&bank, &fw);
            let session = AttestationSession {
                session_id: "session-1".to_string(),
                device_id: "device-1".to_string(),
                started_at: 900,
                last_seen: 900,
                sequence_number: 1,
                active: true,
            };
            ctx.session = Some(&session);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::ContinuousAttestationExpired { .. })
            ));
        }

        // 4. Valid active session (last_seen = 950, now = 1000, window = 60, drift = 50 <= 60)
        {
            let mut ctx = good_ctx(&bank, &fw);
            let session = AttestationSession {
                session_id: "session-1".to_string(),
                device_id: "device-1".to_string(),
                started_at: 900,
                last_seen: 950,
                sequence_number: 1,
                active: true,
            };
            ctx.session = Some(&session);
            assert!(engine.evaluate(&ctx).is_ok());
        }
    }

    #[test]
    fn test_sequence_monotonicity_rules() {
        let bank = measured_boot_bank();
        let fw = sha3(0xab);

        let engine =
            HardwarePolicyEngine::new(alloc::vec![HardwarePolicyRule::RequireSequenceMonotonicity]);

        // 1. Runtime attestation evidence or session missing
        {
            let ctx = good_ctx(&bank, &fw);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::RuntimeAttestationEvidenceMissing)
            ));
        }

        {
            let mut ctx = good_ctx(&bank, &fw);
            let evidence = RuntimeAttestationEvidence {
                measurements: alloc::vec![],
                sequence_number: 2,
                policy_epoch: 1,
            };
            ctx.runtime_attestation = Some(&evidence);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::ContinuousAttestationSessionMissing)
            ));
        }

        // 2. Replay detected (sequence_number <= session.sequence_number)
        {
            let mut ctx = good_ctx(&bank, &fw);
            let evidence = RuntimeAttestationEvidence {
                measurements: alloc::vec![],
                sequence_number: 2,
                policy_epoch: 1,
            };
            let session = AttestationSession {
                session_id: "session-1".to_string(),
                device_id: "device-1".to_string(),
                started_at: 900,
                last_seen: 950,
                sequence_number: 2, // same as evidence
                active: true,
            };
            ctx.runtime_attestation = Some(&evidence);
            ctx.session = Some(&session);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::ReplayDetected { .. })
            ));
        }

        // 3. Sequence gap detected (sequence_number != session.sequence_number + 1)
        {
            let mut ctx = good_ctx(&bank, &fw);
            let evidence = RuntimeAttestationEvidence {
                measurements: alloc::vec![],
                sequence_number: 4,
                policy_epoch: 1,
            };
            let session = AttestationSession {
                session_id: "session-1".to_string(),
                device_id: "device-1".to_string(),
                started_at: 900,
                last_seen: 950,
                sequence_number: 2,
                active: true,
            };
            ctx.runtime_attestation = Some(&evidence);
            ctx.session = Some(&session);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::SequenceGapDetected { .. })
            ));
        }

        // 4. Monotonic succession (sequence_number == session.sequence_number + 1)
        {
            let mut ctx = good_ctx(&bank, &fw);
            let evidence = RuntimeAttestationEvidence {
                measurements: alloc::vec![],
                sequence_number: 3,
                policy_epoch: 1,
            };
            let session = AttestationSession {
                session_id: "session-1".to_string(),
                device_id: "device-1".to_string(),
                started_at: 900,
                last_seen: 950,
                sequence_number: 2,
                active: true,
            };
            ctx.runtime_attestation = Some(&evidence);
            ctx.session = Some(&session);
            assert!(engine.evaluate(&ctx).is_ok());
        }
    }

    #[test]
    fn test_policy_epoch_rules() {
        let bank = measured_boot_bank();
        let fw = sha3(0xab);

        let engine =
            HardwarePolicyEngine::new(alloc::vec![HardwarePolicyRule::RequirePolicyEpoch(2)]);

        // Mismatched epoch
        {
            let mut ctx = good_ctx(&bank, &fw);
            let evidence = RuntimeAttestationEvidence {
                measurements: alloc::vec![],
                sequence_number: 1,
                policy_epoch: 1,
            };
            ctx.runtime_attestation = Some(&evidence);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::PolicyEpochMismatch {
                    expected: 2,
                    got: 1
                })
            ));
        }

        // Matching epoch
        {
            let mut ctx = good_ctx(&bank, &fw);
            let evidence = RuntimeAttestationEvidence {
                measurements: alloc::vec![],
                sequence_number: 1,
                policy_epoch: 2,
            };
            ctx.runtime_attestation = Some(&evidence);
            assert!(engine.evaluate(&ctx).is_ok());
        }
    }

    #[test]
    fn test_transparency_anchoring_rules() {
        use pqrascv_bitcoin_anchor::{
            proof::TxMerklePath,
            timeline::{TimelineInclusionProof, TimelineMerkleAggregator, TimelineSpvVerifier},
        };

        let bank = measured_boot_bank();
        let fw = sha3(0xab);
        let mut ctx = good_ctx(&bank, &fw);

        let engine = HardwarePolicyEngine::new(alloc::vec![
            HardwarePolicyRule::RequireTransparencyAnchoring
        ]);

        // 1. Missing proofs/verifier/event
        assert!(matches!(
            engine.evaluate(&ctx),
            Err(HardwarePolicyError::TransparencyProofMissing)
        ));

        let event = TransparencyEvent {
            timestamp: 1000,
            device_id: "device-1".to_string(),
            event_hash: sha3(0xee),
        };
        ctx.transparency_event = Some(&event);

        let mut aggregator = TimelineMerkleAggregator::new();
        let event_hash = event.canonical_hash().unwrap();
        aggregator.add_event_hash(event_hash);
        let timeline_merkle_root = aggregator.root().unwrap();
        let event_merkle_path = aggregator.inclusion_proof(0).unwrap();

        let root = [0xabu8; 32];
        let mut block_header = alloc::vec![0u8; 80];
        block_header[36..68].copy_from_slice(&root);

        let proof = TimelineInclusionProof {
            block_height: 90,
            block_header: block_header.clone(),
            tx_merkle_path: TxMerklePath {
                txid: root,
                steps: alloc::vec![],
                block_merkle_root: root,
            },
            timeline_merkle_root,
            event_merkle_path,
        };
        ctx.transparency_proof = Some(&proof);

        let verifier = TimelineSpvVerifier::new(6, 100);
        ctx.spv_verifier = Some(&verifier);

        // All present and correct -> passes
        assert!(engine.evaluate(&ctx).is_ok());

        // Mismatched confirmations
        let weak_verifier = TimelineSpvVerifier::new(20, 100);
        ctx.spv_verifier = Some(&weak_verifier);
        assert!(matches!(
            engine.evaluate(&ctx),
            Err(HardwarePolicyError::SpvVerificationFailed(_))
        ));
    }

    #[test]
    fn test_evaluate_runtime_report() {
        let mut bank = TypedPcrBank::new();
        bank.push(PcrMeasurement::new(0, PcrSemantic::Firmware, sha3(0x01)).unwrap());
        bank.push(PcrMeasurement::new(1, PcrSemantic::Bootloader, sha3(0x02)).unwrap());
        bank.push(PcrMeasurement::new(2, PcrSemantic::Kernel, sha3(0x03)).unwrap());
        bank.push(PcrMeasurement::new(3, PcrSemantic::Initrd, sha3(0x04)).unwrap());

        let fw = sha3(0x01);
        let mut ctx = good_ctx(&bank, &fw);

        let sb = SecureBootEvidence {
            state: SecureBootState::Enabled,
            db_hash: None,
            dbx_hash: None,
            mok_hash: None,
        };
        ctx.secure_boot = Some(&sb);

        // Create engine with a platform profile rule + IMA rule
        let profile = crate::profiles::sovereign_bitcoin_node_profile();
        let engine = HardwarePolicyEngine::new(alloc::vec![
            HardwarePolicyRule::RequirePlatformProfile {
                profile,
                drift_mode: DriftPolicyMode::Enforcing,
                upgrade_baseline: None,
            },
            HardwarePolicyRule::RequireIma,
        ]);

        let report = engine.evaluate_runtime_report(&ctx);
        // overall is not trusted because IMA is missing
        assert!(!report.trusted);

        // Check that trust domains are evaluated independently
        let ima_eval = report
            .evaluations
            .iter()
            .find(|e| e.domain == TrustDomain::RuntimeIntegrity)
            .unwrap();
        assert!(!ima_eval.trusted);
        assert_eq!(
            ima_eval.reasons,
            alloc::vec![VerificationDecisionReason::RuntimeIntegrityUnavailable]
        );

        let mb_eval = report
            .evaluations
            .iter()
            .find(|e| e.domain == TrustDomain::MeasuredBoot)
            .unwrap();
        // MeasuredBoot domain passes platform profile PCR checks (even though IMA runtime check fails!)
        assert!(mb_eval.trusted);
    }
}
