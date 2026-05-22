//! Fuzz target: Hardware policy evaluation and conflict detection.
//!
//! The goal is to make sure no inputs or combinations of rules/context can cause
//! a panic or undefined behavior in the policy engine.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqrascv_hardware::{
    backend::HardwareBackendType,
    counter::CounterEvidence,
    digest::{DigestAlgorithm, TypedDigest},
    drift::DriftPolicyMode,
    pcr::{PcrMeasurement, PcrSemantic, TypedPcrBank},
    policy::{HardwarePolicyContext, HardwarePolicyEngine, HardwarePolicyRule},
    secure_boot::{SecureBootEvidence, SecureBootState},
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }

    // Split the data to construct rule parameters and context values
    let backend_byte = data[0];
    let sb_byte = data[1];
    let drift_byte = data[2];
    let counter_val = u64::from(data[3]);

    let backend_type = match backend_byte % 6 {
        0 => HardwareBackendType::Tpm2,
        1 => HardwareBackendType::Dice,
        2 => HardwareBackendType::IntelTdx,
        3 => HardwareBackendType::AmdSevSnp,
        4 => HardwareBackendType::NitroEnclave,
        _ => HardwareBackendType::TestOnly,
    };

    let secure_boot_state = match sb_byte % 4 {
        0 => SecureBootState::Enabled,
        1 => SecureBootState::Disabled,
        2 => SecureBootState::SetupMode,
        _ => SecureBootState::Unknown,
    };

    let _drift_mode = match drift_byte % 3 {
        0 => DriftPolicyMode::Learning,
        1 => DriftPolicyMode::Audit,
        _ => DriftPolicyMode::Enforcing,
    };

    // Construct a random PCR bank
    let mut bank = TypedPcrBank::new();
    let mut offset = 4;
    while offset + 34 <= data.len() {
        let semantic_byte = data[offset];
        let semantic = match semantic_byte % 9 {
            0 => PcrSemantic::Firmware,
            1 => PcrSemantic::Bootloader,
            2 => PcrSemantic::Kernel,
            3 => PcrSemantic::Initrd,
            4 => PcrSemantic::Config,
            5 => PcrSemantic::SecureWorld,
            6 => PcrSemantic::Application,
            _ => PcrSemantic::Policy,
        };
        let mut digest_val = [0u8; 32];
        digest_val.copy_from_slice(&data[offset + 1..offset + 33]);

        let pcr_index = semantic.canonical_slot() as u8;
        if let Ok(m) = PcrMeasurement::new(
            pcr_index,
            semantic,
            TypedDigest::new(DigestAlgorithm::Sha3_256, digest_val),
        ) {
            bank.push(m);
        }
        offset += 34;
    }

    let firmware_digest = TypedDigest::new(DigestAlgorithm::Sha3_256, [0xab; 32]);
    let secure_boot = SecureBootEvidence {
        state: secure_boot_state,
        db_hash: None,
        dbx_hash: None,
        mok_hash: None,
    };

    let ctx = HardwarePolicyContext {
        backend_type,
        pcr_bank: &bank,
        counter: CounterEvidence::HardwareMonotonic(counter_val),
        supports_nonce_binding: true,
        firmware_digest: &firmware_digest,
        secure_boot: Some(&secure_boot),
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
    };

    // Build some rules using the input bytes
    let rules = vec![
        HardwarePolicyRule::RequireHardwareRootedBackend,
        HardwarePolicyRule::RequireBackendType(backend_type),
        HardwarePolicyRule::RequireSecureBootState(secure_boot_state),
        HardwarePolicyRule::RequireNormalizedPcrs,
        HardwarePolicyRule::RequireMeasuredBoot,
    ];

    let engine = HardwarePolicyEngine::new(rules);

    // Check conflicts - must not panic
    let _ = engine.detect_conflicts();

    // Evaluate policy - must not panic
    let _ = engine.evaluate(&ctx);
});
