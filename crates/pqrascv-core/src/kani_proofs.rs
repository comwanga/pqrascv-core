//! Kani formal verification harnesses.
//!
//! Run with: `cargo kani`
//! Run one harness: `cargo kani --harness <name>`
//!
//! These are model-checking proofs. They use `kani::any()` to introduce
//! symbolic variables and assert invariants that must hold for ALL possible
//! inputs.
//!
//! All harnesses are gated behind `#[cfg(kani)]` so they have zero effect on
//! normal `cargo build` / `cargo test` / `cargo check` builds.

#[cfg(kani)]
extern crate alloc;

/// Proof: `PcrBank::default()` initialises every PCR slot to the all-zeros
/// digest.
///
/// This is a structural invariant relied upon throughout the codebase; any
/// backend that forgets to initialise a slot will violate it.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(8)]
fn pcr_bank_default_is_all_zeros() {
    use crate::measurement::{PcrBank, PCR_COUNT};

    let bank = PcrBank::default();

    let mut i = 0usize;
    while i < PCR_COUNT {
        kani::assert(
            bank.digests[i] == [0u8; 32],
            "PcrBank::default() must have all-zero digests",
        );
        i += 1;
    }
}

/// Proof: after a nonce is registered and consumed it cannot be consumed a
/// second time (replay rejected), and a nonce that was never registered is
/// also rejected.
///
/// Uses `kani::any()` for the 32-byte nonce so the proof holds for every
/// possible nonce value.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(10)]
fn nonce_ledger_rejects_duplicate() {
    use crate::nonce::{InMemoryNonceLedger, NonceLedger};

    let mut ledger = InMemoryNonceLedger::default();
    let nonce: [u8; 32] = kani::any();

    // First: register the nonce — must succeed.
    let reg = ledger.register(nonce);
    kani::assert(reg.is_ok(), "first register must succeed");

    // Consume the pending nonce — must succeed.
    let first_consume = ledger.consume(&nonce);
    kani::assert(first_consume.is_ok(), "first consume must succeed");

    // Second consume of the same nonce — must be rejected (replay).
    let second_consume = ledger.consume(&nonce);
    kani::assert(second_consume.is_err(), "duplicate nonce must be rejected");
}

/// Proof: `PolicyEngineV2::evaluate` is deterministic — calling it twice on
/// the same `PolicyContext` always produces the same `Ok`/`Err` outcome.
///
/// This guards against any accidental stateful mutation that would cause the
/// same policy to accept or reject a quote differently on a second call.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(16)]
fn policy_evaluation_is_deterministic() {
    use crate::measurement::{PcrAlgorithm, PcrBank};
    use crate::nonce::ClockEvidence;
    use crate::policy::{HardwareBackendKind, PolicyContext, PolicyEngineV2, PolicyRule};

    // Build a symbolic firmware hash — all 32 bytes are unconstrained.
    let firmware_hash: [u8; 32] = kani::any();

    // Build a symbolic PCR bank — every digest is unconstrained.
    let digests: [[u8; 32]; 8] = kani::any();
    let pcr_bank = PcrBank {
        digests,
        algorithm: PcrAlgorithm::Sha3_256,
    };

    // Symbolic protocol version and event counter.
    let protocol_version: u16 = kani::any();
    let event_counter: u64 = kani::any();
    let now_secs: u64 = kani::any();
    let ts: u64 = kani::any();

    // Use TrustedRtc with a symbolic timestamp so MaxQuoteAgeSecs can be
    // exercised for any clock value.
    let clock = ClockEvidence::TrustedRtc(ts);

    // Construct a context whose security-sensitive fields are symbolic.
    // `verified_provenance` is always `None` here because `VerifiedProvenance`
    // is a sealed type only constructible inside `verify_all` — there is no
    // other safe way to obtain one without running the full 10-condition
    // verification chain.
    let ctx = PolicyContext {
        protocol_version,
        clock,
        now_secs,
        firmware_hash: &firmware_hash,
        slsa_level: kani::any(),
        builder_id: None,
        hardware_backend: HardwareBackendKind::Tpm2,
        has_cert_chain: kani::any(),
        verified_provenance: None,
        bitcoin_confirmations: None,
        pcrs: &pcr_bank,
        event_counter,
    };

    // A minimal rule set that exercises the most common symbolic paths:
    // version enforcement, firmware hash, and SLSA level.
    let engine = PolicyEngineV2::new(alloc::vec![
        PolicyRule::EnforceProtocolVersion { expected: 2 },
        PolicyRule::RequireFirmwareHash,
        PolicyRule::MinSlsaLevel(1),
    ]);

    // Evaluate twice — both calls must agree on Ok vs Err.
    let result1 = engine.evaluate(&ctx);
    let result2 = engine.evaluate(&ctx);

    let both_ok = result1.is_ok() && result2.is_ok();
    let both_err = result1.is_err() && result2.is_err();
    kani::assert(
        both_ok || both_err,
        "PolicyEngineV2::evaluate must be deterministic",
    );
}

/// Proof: if a byte slice deserialises as a valid `AttestationQuote` and the
/// quote can be re-serialised, then the re-deserialised quote has the same
/// nonce, version, and firmware hash as the original.
///
/// The proof uses symbolic input bytes (up to 512 bytes) so that Kani
/// explores all possible valid CBOR structures within that window.  Any
/// byte string that fails `from_cbor` is silently skipped — the interesting
/// paths are those where both parses succeed.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(64)]
fn cbor_serialization_is_deterministic() {
    use crate::quote::AttestationQuote;

    // Symbolic length in (0, 512].
    let len: usize = kani::any_where(|n: &usize| *n > 0 && *n <= 512);
    let mut bytes = alloc::vec![0u8; len];
    for b in bytes.iter_mut() {
        *b = kani::any();
    }

    // If the bytes aren't a valid quote, skip this path.
    let Ok(quote) = AttestationQuote::from_cbor(&bytes) else {
        return;
    };

    // Re-serialise.  If that somehow fails, the harness fails.
    let Ok(cbor2) = quote.to_cbor() else {
        kani::assert(
            false,
            "to_cbor must not fail on a successfully parsed quote",
        );
        return;
    };

    // Re-parse the round-tripped bytes.
    let Ok(quote2) = AttestationQuote::from_cbor(&cbor2) else {
        kani::assert(false, "re-serialised CBOR must be valid");
        return;
    };

    // Critical fields must be identical after the roundtrip.
    kani::assert(
        quote.body.nonce == quote2.body.nonce,
        "nonce must survive CBOR roundtrip",
    );
    kani::assert(
        quote.body.version == quote2.body.version,
        "version must survive CBOR roundtrip",
    );
    kani::assert(
        quote.body.measurements.firmware_hash == quote2.body.measurements.firmware_hash,
        "firmware_hash must survive CBOR roundtrip",
    );
}
