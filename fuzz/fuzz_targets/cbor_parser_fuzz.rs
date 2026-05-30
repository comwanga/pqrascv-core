//! Fuzz target: CBOR wire-type parsing breadth.
//!
//! Exercises two independent CBOR decode paths:
//!   1. `AttestationQuote::from_cbor` + re-encode (existing domain type).
//!   2. Bare `ciborium::value::Value` decode + deep traversal (generic path).
//!
//! Neither path may panic for any byte sequence.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqrascv_core::quote::AttestationQuote;

fuzz_target!(|data: &[u8]| {
    // AttestationQuote roundtrip — must never panic.
    if let Ok(quote) = AttestationQuote::from_cbor(data) {
        let _ = quote.to_cbor();
        let _ = quote.body.version;
        let _ = &quote.body.measurements.firmware_hash;
        let _ = quote.signature.len();
    }

    // Bare ciborium Value decode — must never panic.
    if let Ok(val) = ciborium::from_reader::<ciborium::value::Value, _>(data) {
        traverse_value(&val, 0);
    }
});

fn traverse_value(val: &ciborium::value::Value, depth: u8) {
    if depth > 32 {
        return;
    }
    match val {
        ciborium::value::Value::Array(items) => {
            for item in items {
                traverse_value(item, depth + 1);
            }
        }
        ciborium::value::Value::Map(pairs) => {
            for (k, v) in pairs {
                traverse_value(k, depth + 1);
                traverse_value(v, depth + 1);
            }
        }
        ciborium::value::Value::Tag(_, inner) => {
            traverse_value(inner, depth + 1);
        }
        _ => {}
    }
}
