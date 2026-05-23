#![no_main]
use libfuzzer_sys::fuzz_target;
use pqrascv_hardware::deterministic_replay::{ReplayWindow, ReplayedEvent};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    
    // Create a dummy replay window
    let mut window = ReplayWindow::new(data[0] as u64, 100);
    
    // Attempt to add a dummy event based on fuzzed data
    if data.len() >= 32 {
        let mut event_hash = [0u8; 32];
        event_hash.copy_from_slice(&data[0..32]);
        
        let event = ReplayedEvent {
            event_hash,
            sequence_number: data[0] as u64,
            timestamp: 0,
        };
        
        // Ensure adding the event doesn't panic
        let _ = window.record_event(event);
    }
});
