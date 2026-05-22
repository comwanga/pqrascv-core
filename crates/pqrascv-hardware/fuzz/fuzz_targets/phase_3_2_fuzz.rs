#![no_main]
use libfuzzer_sys::fuzz_target;
use pqrascv_hardware::pq_transport::PqTransportSession;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    
    // Fuzz PQ transport session parsing and decryption robustness
    let mut session = PqTransportSession::establish(
        "verifier_A".into(),
        "verifier_B".into(),
        1000,
        2000,
    ).unwrap();
    
    // Simulate some expected sequences and mutations
    let mut expected_seq = 1;
    let _ = session.open_message(data, expected_seq);
});
