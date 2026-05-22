#![no_main]

use libfuzzer_sys::fuzz_target;
use pqrascv_hardware::bitcoin_workload_integrity::BitcoinWorkloadEvidence;
use pqrascv_hardware::bitcoin_node_identity::BitcoinNodeIdentity;
use pqrascv_hardware::policy::{HardwarePolicyEngine, HardwarePolicyContext, HardwarePolicyError};
use pqrascv_hardware::bitcoin_policy_profiles::BitcoinNodeProfile;

fuzz_target!(|data: &[u8]| {
    // Just simple structure fuzzing as a placeholder
    let _ = serde_json::from_slice::<BitcoinWorkloadEvidence>(data);
    let _ = serde_json::from_slice::<BitcoinNodeIdentity>(data);
});
