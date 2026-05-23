#![no_main]

use libfuzzer_sys::fuzz_target;
use pqrascv_bitcoin_anchor::finality_anchor::FinalityCommitment;

fuzz_target!(|data: &[u8]| {
    if let Ok(commitment) = serde_json::from_slice::<FinalityCommitment>(data) {
        let _ = commitment.is_structurally_valid();
    }
});
