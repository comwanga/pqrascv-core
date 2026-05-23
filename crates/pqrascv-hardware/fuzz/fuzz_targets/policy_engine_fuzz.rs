#![no_main]

use libfuzzer_sys::fuzz_target;
use pqrascv_hardware::policy::engine::{HardwarePolicyEngine, HardwareEvidence};

fuzz_target!(|data: &[u8]| {
    // Attempt to parse random data into hardware evidence
    if let Ok(evidence) = serde_json::from_slice::<HardwareEvidence>(data) {
        let engine = HardwarePolicyEngine::hardware_production();
        let _ = engine.evaluate_evidence(&evidence);
    }
});
