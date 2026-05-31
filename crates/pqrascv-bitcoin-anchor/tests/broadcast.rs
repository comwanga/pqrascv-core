//! Phase 7B — Broadcaster contract tests against the always-on mock.

use std::cell::Cell;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness};

use pqrascv_bitcoin_broadcast::broadcast::{retry_broadcast, BroadcastError, RetryConfig};
use pqrascv_bitcoin_broadcast::builder::AnchorBuilder;
use pqrascv_bitcoin_broadcast::{AnchorCommitment, Broadcaster, FeeRate, MockBroadcaster};

fn sample_tx(seed: u8) -> bitcoin::Transaction {
    let input = TxIn {
        previous_output: OutPoint {
            txid: Txid::all_zeros(),
            vout: u32::from(seed),
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };
    let change = TxOut {
        value: Amount::from_sat(1234),
        script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14, seed, seed, seed]),
    };
    AnchorBuilder::new()
        .build_unsigned(&AnchorCommitment::new([seed; 32]), vec![input], vec![change])
        .unwrap()
        .tx
}

#[test]
fn first_broadcast_returns_txid() {
    let mock = MockBroadcaster::new();
    let tx = sample_tx(1);
    let txid = mock.broadcast(&tx).expect("broadcast ok");
    assert_eq!(txid, tx.compute_txid());
    assert_eq!(mock.accepted_count(), 1);
    assert!(mock.contains(&txid));
}

#[test]
fn duplicate_broadcast_is_idempotent() {
    let mock = MockBroadcaster::new();
    let tx = sample_tx(2);
    let first = mock.broadcast(&tx).unwrap();
    let second = mock.broadcast(&tx).unwrap(); // re-broadcast already-known
    assert_eq!(first, second, "idempotent: same txid");
    assert_eq!(mock.accepted_count(), 1, "no duplicate mempool entry");
    assert_eq!(mock.attempt_count(), 2, "both attempts observed");
}

#[test]
fn retry_succeeds_after_n_transient_failures() {
    let mock = MockBroadcaster::failing(2); // fail twice, then accept
    let tx = sample_tx(3);
    let cfg = RetryConfig {
        max_attempts: 3,
        base_backoff_ms: 0,
    };
    let txid = retry_broadcast(cfg, || mock.broadcast(&tx), |_ms| {}).expect("eventually ok");
    assert_eq!(txid, tx.compute_txid());
    assert_eq!(mock.attempt_count(), 3, "2 failures + 1 success");
    assert_eq!(mock.accepted_count(), 1);
}

#[test]
fn retry_exhausts_and_returns_error() {
    let mock = MockBroadcaster::failing(5); // more failures than attempts
    let tx = sample_tx(4);
    let cfg = RetryConfig {
        max_attempts: 3,
        base_backoff_ms: 0,
    };
    let err = retry_broadcast(cfg, || mock.broadcast(&tx), |_ms| {}).unwrap_err();
    assert!(err.is_transient());
    assert_eq!(mock.attempt_count(), 3, "bounded at max_attempts");
    assert_eq!(mock.accepted_count(), 0);
}

#[test]
fn retry_does_not_retry_rejected() {
    let cfg = RetryConfig {
        max_attempts: 5,
        base_backoff_ms: 0,
    };
    let calls = Cell::new(0u32);
    let err = retry_broadcast(
        cfg,
        || {
            calls.set(calls.get() + 1);
            Err(BroadcastError::Rejected("bad-txns".into()))
        },
        |_ms| {},
    )
    .unwrap_err();
    assert!(matches!(err, BroadcastError::Rejected(_)));
    assert_eq!(calls.get(), 1, "rejected errors are not retried");
}

#[test]
fn backoff_schedule_is_linear_and_bounded() {
    let mock = MockBroadcaster::failing(2);
    let tx = sample_tx(5);
    let cfg = RetryConfig {
        max_attempts: 3,
        base_backoff_ms: 100,
    };
    let sleeps = std::cell::RefCell::new(Vec::new());
    let _ = retry_broadcast(
        cfg,
        || mock.broadcast(&tx),
        |ms| sleeps.borrow_mut().push(ms),
    )
    .unwrap();
    // Two failures => two backoffs of 100*1 and 100*2; success has no sleep.
    assert_eq!(*sleeps.borrow(), vec![100, 200]);
}

#[test]
fn fee_estimate_returns_a_rate() {
    let mock = MockBroadcaster::new();
    let rate = mock.estimate_fee(6).expect("fee");
    assert_eq!(rate, FeeRate::from_sat_per_vb(1));
    assert_eq!(rate.sat_per_vb(), 1);
}

#[test]
fn fee_estimate_unavailable_is_an_error() {
    let mock = MockBroadcaster::new().with_fee(None);
    let err = mock.estimate_fee(6).unwrap_err();
    assert!(matches!(err, BroadcastError::FeeEstimationUnavailable));
}

#[test]
fn no_retry_config_makes_exactly_one_attempt() {
    let mock = MockBroadcaster::failing(1);
    let tx = sample_tx(6);
    let err = retry_broadcast(RetryConfig::no_retry(), || mock.broadcast(&tx), |_ms| {})
        .unwrap_err();
    assert!(err.is_transient());
    assert_eq!(mock.attempt_count(), 1);
}
