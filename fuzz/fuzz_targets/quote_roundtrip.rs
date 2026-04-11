//! Fuzz target: CBOR deserialization of `AttestationQuote`.
//!
//! Run with:
//!   cargo fuzz run quote_roundtrip
//!
//! The goal is to make sure no arbitrary byte sequence can cause a panic
//! or undefined behaviour in the deserialization or re-serialization path.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqrascv_core::quote::AttestationQuote;

fuzz_target!(|data: &[u8]| {
    // Must never panic regardless of what bytes are fed in.
    let Ok(quote) = AttestationQuote::from_cbor(data) else {
        return;
    };

    // If we decoded something, re-encoding must also not panic.
    let _ = quote.to_cbor();

    // Field access must be safe.
    let _ = quote.body.version;
    let _ = quote.body.nonce;
    let _ = quote.body.timestamp;
    let _ = &quote.body.measurements.firmware_hash;
    let _ = &quote.body.measurements.ai_model_hash;
    let _ = quote.body.measurements.event_counter;
    let _ = quote.body.provenance.slsa_level();
    let _ = quote.signature.len();
});
