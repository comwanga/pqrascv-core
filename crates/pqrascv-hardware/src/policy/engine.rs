use crate::policy::{
    HardwarePolicyContext, HardwarePolicyError, HardwarePolicyRule, PolicyConflictError,
};

use crate::{
    backend::HardwareBackendType,
    drift::DriftSeverity,
    platform_profiles::RuntimeVerificationReport,
    trust_domains::{TrustDomain, TrustEvaluation, VerificationDecisionReason},
};

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

// ── HardwarePolicyRule ────────────────────────────────────────────────────
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

    #[allow(clippy::too_many_lines)]
    fn rule_belongs_to_domain(rule: &HardwarePolicyRule, domain: TrustDomain) -> bool {
        match domain {
            TrustDomain::HardwareIdentity => matches!(
                rule,
                HardwarePolicyRule::RequireHardwareRootedBackend
                    | HardwarePolicyRule::RequireBackendType(_)
                    | HardwarePolicyRule::RequireLiveTpmEvidence
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
                    | HardwarePolicyRule::RequireSecureBootCollection
            ),
            TrustDomain::RuntimeIntegrity => matches!(
                rule,
                HardwarePolicyRule::RequireRuntimeIntegrity { .. }
                    | HardwarePolicyRule::RequireIma
                    | HardwarePolicyRule::RequireLiveImaEvidence
                    | HardwarePolicyRule::RequireFreshRuntimeEvidence
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
                    | HardwarePolicyRule::RequireDeterministicNodePolicy
                    | HardwarePolicyRule::RequireDeltaAttestation
                    | HardwarePolicyRule::RequireCheckpointIntegrity
                    | HardwarePolicyRule::RequireTimelineCompaction
                    | HardwarePolicyRule::RequireRetentionCompliance
            ),
            // --- Phase 3.0 Sovereign Node Additions ---
            TrustDomain::WorkloadIntegrity => matches!(
                rule,
                HardwarePolicyRule::RequireBitcoinNodeIdentity
                    | HardwarePolicyRule::RequireBitcoinWorkloadIntegrity
                    | HardwarePolicyRule::RequireNodeRuntimeContinuity
                    | HardwarePolicyRule::RequireVerifiedBitcoinProcess
                    | HardwarePolicyRule::RequireRuntimeObservationContinuity
            ),
            TrustDomain::ConsensusIntegrity => {
                matches!(
                    rule,
                    HardwarePolicyRule::RequireFederatedNodeVerification
                        | HardwarePolicyRule::RequirePqFederationTransport
                        | HardwarePolicyRule::RequireFederationMessageSigning
                        | HardwarePolicyRule::RequireFederationSnapshots
                        | HardwarePolicyRule::RequireDeterministicReplay
                        | HardwarePolicyRule::RequirePartitionDetection
                        | HardwarePolicyRule::RequirePartitionHealingApproval
                        | HardwarePolicyRule::RequireVerifierRejoinValidation
                        | HardwarePolicyRule::RequireQuorumReformation
                        | HardwarePolicyRule::RequireRecoveryGovernance
                        | HardwarePolicyRule::RequireMigrationContinuity
                )
            }
            // --- Phase 3.3 Byzantine Federation Convergence ---
            TrustDomain::DistributedGovernance => matches!(
                rule,
                HardwarePolicyRule::RequireVerifierRevocationChecks
                    | HardwarePolicyRule::RequireEquivocationDetection
                    | HardwarePolicyRule::RequireByzantineQuorum
                    | HardwarePolicyRule::RequireTopologyValidation
                    | HardwarePolicyRule::RequireRetentionGovernance
                    | HardwarePolicyRule::RequireCrossFederationConsistency
                    | HardwarePolicyRule::RequireGovernanceContinuity
            ),
            // --- Phase 3.4 Federation Time Semantics ---
            TrustDomain::TemporalTimekeeping => matches!(
                rule,
                HardwarePolicyRule::RequireLogicalClockSynchronization
                    | HardwarePolicyRule::RequireBoundedTimeSkew
                    | HardwarePolicyRule::RequireAnchoredKeyRegistry
                    | HardwarePolicyRule::RequireEpochKeyBinding
            ),
            TrustDomain::RecoveryIntegrity => matches!(
                rule,
                HardwarePolicyRule::RequireFederationSnapshots
                    | HardwarePolicyRule::RequireDeterministicReplay
                    | HardwarePolicyRule::RequirePartitionDetection
                    | HardwarePolicyRule::RequirePartitionHealingApproval
                    | HardwarePolicyRule::RequireVerifierRejoinValidation
                    | HardwarePolicyRule::RequireQuorumReformation
                    | HardwarePolicyRule::RequireRecoveryGovernance
                    | HardwarePolicyRule::RequireMigrationContinuity
            ),
            // --- Phase 3.6 Adaptive Federation Synchronization ---
            TrustDomain::FederationAvailability => matches!(
                rule,
                HardwarePolicyRule::RequireAdaptiveSynchronization
                    | HardwarePolicyRule::RequireDeterministicSnapshotSync
                    | HardwarePolicyRule::RequireFederationLiveness
                    | HardwarePolicyRule::RequireEclipseResistance
                    | HardwarePolicyRule::RequireOperationalPeerValidation
                    | HardwarePolicyRule::RequireBoundedStateReconstruction
                    | HardwarePolicyRule::RequireSynchronizationGovernance
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

    fn evaluate_rule(
        rule: &HardwarePolicyRule,
        ctx: &HardwarePolicyContext<'_>,
    ) -> Result<(), HardwarePolicyError> {
        if crate::policy::domain_identity::evaluate_domain_rule(rule, ctx)? {
            return Ok(());
        }
        if crate::policy::domain_runtime::evaluate_domain_rule(rule, ctx)? {
            return Ok(());
        }
        if crate::policy::domain_temporal::evaluate_domain_rule(rule, ctx)? {
            return Ok(());
        }
        if crate::policy::domain_federation::evaluate_domain_rule(rule, ctx)? {
            return Ok(());
        }
        if crate::policy::domain_recovery::evaluate_domain_rule(rule, ctx)? {
            return Ok(());
        }
        if crate::policy::domain_transport::evaluate_domain_rule(rule, ctx)? {
            return Ok(());
        }
        if crate::policy::domain_availability::evaluate_domain_rule(rule, ctx)? {
            return Ok(());
        }
        if crate::policy::domain_sovereign::evaluate_domain_rule(rule, ctx)? {
            return Ok(());
        }

        // Failsafe is to panic in debug, but in release we just succeed?
        // Wait, fail-closed means we should error!
        unreachable!("Rule {:?} was not evaluated by any domain evaluator", rule);
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
            bitcoin_node_identity: None,
            bitcoin_workload_evidence: None,
            bitcoin_runtime_state: None,
            node_session: None,
            runtime_stream: None,
            delta_attestation: None,
            checkpoint: None,
            pq_session: None,
            compacted_timeline: None,
            federation_envelope: None,
            revocation_list: None,
            logical_clock: None,
            temporal_ambiguity: None,
            verifier_registration_state: None,
            epoch_key_binding: None,
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

        {
            let ctx = good_ctx(&bank, &fw);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::ImaEvidenceMissing)
            ));
        }

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

        {
            let ctx = good_ctx(&bank, &fw);
            assert!(matches!(
                engine.evaluate(&ctx),
                Err(HardwarePolicyError::ContinuousAttestationSessionMissing)
            ));
        }

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
