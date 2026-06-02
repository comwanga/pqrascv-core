//! Phase 7A — `AnchorBuilder` contract and adversarial tests.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use pqrascv_bitcoin_broadcast::builder::{
    AnchorBuilder, BuildError, ANCHOR_TX_LOCKTIME, ANCHOR_TX_VERSION,
};
use pqrascv_bitcoin_broadcast::{AnchorCommitment, ANCHOR_PAYLOAD_SIZE};

fn dummy_input(vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint {
            txid: Txid::all_zeros(),
            vout,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    }
}

fn change_output(sats: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(sats),
        // arbitrary p2wpkh-shaped 22-byte script; content is irrelevant here.
        script_pubkey: ScriptBuf::from_bytes(vec![
            0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ]),
    }
}

#[test]
fn op_return_payload_is_exactly_40_bytes_and_op_return_shaped() {
    let commitment = AnchorCommitment::new([0x11; 32]);
    let script = AnchorBuilder::op_return_script(&commitment);
    assert!(script.is_op_return(), "script must be OP_RETURN-shaped");

    // OP_RETURN (1) + pushdata length prefix (1, since 40 < 76) + 40 payload.
    let bytes = script.as_bytes();
    assert_eq!(bytes[0], 0x6a, "first byte is OP_RETURN");
    assert_eq!(bytes[1] as usize, ANCHOR_PAYLOAD_SIZE, "push length is 40");
    assert_eq!(bytes.len(), 2 + ANCHOR_PAYLOAD_SIZE);
    assert_eq!(&bytes[2..9], b"PQRASCV");
    assert_eq!(bytes[9], 0x02);
}

#[test]
fn op_return_output_is_zero_value() {
    let out = AnchorBuilder::op_return_output(&AnchorCommitment::new([0xaa; 32]));
    assert_eq!(out.value, Amount::ZERO);
    assert!(out.script_pubkey.is_op_return());
}

#[test]
fn build_unsigned_appends_op_return_last() {
    let builder = AnchorBuilder::new();
    let anchor = builder
        .build_unsigned(
            &AnchorCommitment::new([0x22; 32]),
            vec![dummy_input(0)],
            vec![change_output(50_000)],
        )
        .expect("build");
    assert_eq!(anchor.tx.output.len(), 2);
    assert_eq!(anchor.op_return_vout, 1);
    assert!(anchor.tx.output[1].script_pubkey.is_op_return());
    assert_eq!(anchor.tx.version, ANCHOR_TX_VERSION);
    assert_eq!(anchor.tx.lock_time, ANCHOR_TX_LOCKTIME);
}

#[test]
fn build_unsigned_with_no_change_output_still_anchors() {
    let builder = AnchorBuilder::new();
    let anchor = builder
        .build_unsigned(
            &AnchorCommitment::new([0x33; 32]),
            vec![dummy_input(0)],
            vec![],
        )
        .expect("build");
    assert_eq!(anchor.tx.output.len(), 1);
    assert_eq!(anchor.op_return_vout, 0);
}

#[test]
fn no_inputs_rejected() {
    let builder = AnchorBuilder::new();
    let err = builder
        .build_unsigned(&AnchorCommitment::new([0x44; 32]), vec![], vec![])
        .unwrap_err();
    assert_eq!(err, BuildError::NoInputs);
}

#[test]
fn caller_supplied_op_return_rejected() {
    let builder = AnchorBuilder::new();
    // A second, caller-provided OP_RETURN must be refused.
    let rogue = AnchorBuilder::op_return_output(&AnchorCommitment::new([0x55; 32]));
    let err = builder
        .build_unsigned(
            &AnchorCommitment::new([0x66; 32]),
            vec![dummy_input(0)],
            vec![rogue],
        )
        .unwrap_err();
    assert_eq!(err, BuildError::CallerSuppliedOpReturn);
}

#[test]
fn deterministic_txid_for_identical_inputs() {
    let builder = AnchorBuilder::new();
    let commitment = AnchorCommitment::new([0x77; 32]);
    let a = builder
        .build_unsigned(
            &commitment,
            vec![dummy_input(3)],
            vec![change_output(10_000)],
        )
        .unwrap();
    let b = builder
        .build_unsigned(
            &commitment,
            vec![dummy_input(3)],
            vec![change_output(10_000)],
        )
        .unwrap();
    assert_eq!(a.txid(), b.txid());
    assert_eq!(
        bitcoin::consensus::encode::serialize(&a.tx),
        bitcoin::consensus::encode::serialize(&b.tx),
        "identical inputs must produce byte-identical tx"
    );
}

#[test]
fn tampering_commitment_changes_txid() {
    let builder = AnchorBuilder::new();
    let a = builder
        .build_unsigned(
            &AnchorCommitment::new([0x01; 32]),
            vec![dummy_input(0)],
            vec![],
        )
        .unwrap();
    let mut tampered = [0x01; 32];
    tampered[31] = 0x02; // flip one byte
    let b = builder
        .build_unsigned(
            &AnchorCommitment::new(tampered),
            vec![dummy_input(0)],
            vec![],
        )
        .unwrap();
    assert_ne!(a.txid(), b.txid(), "tampered commitment must change txid");
}

#[test]
fn different_inputs_change_txid() {
    let builder = AnchorBuilder::new();
    let commitment = AnchorCommitment::new([0x88; 32]);
    let a = builder
        .build_unsigned(&commitment, vec![dummy_input(0)], vec![])
        .unwrap();
    let b = builder
        .build_unsigned(&commitment, vec![dummy_input(1)], vec![])
        .unwrap();
    assert_ne!(a.txid(), b.txid());
}

#[test]
fn artifact_helpers_all_reduce_to_same_tx_for_same_root() {
    let builder = AnchorBuilder::new();
    let root = [0x99; 32];
    let inputs = || vec![dummy_input(0)];

    let base = builder
        .build_unsigned_from_root(root, inputs(), vec![])
        .unwrap();
    let attest = builder
        .anchor_attestation_batch(root, inputs(), vec![])
        .unwrap();
    let prov = builder.anchor_provenance(root, inputs(), vec![]).unwrap();
    let fed = builder
        .anchor_federation_checkpoint(root, inputs(), vec![])
        .unwrap();
    let roll = builder
        .anchor_trust_anchor_rollover(root, inputs(), vec![])
        .unwrap();

    for other in [&attest, &prov, &fed, &roll] {
        assert_eq!(base.txid(), other.txid());
    }
}

#[test]
fn op_return_roundtrips_through_core_parser() {
    // The OP_RETURN we emit must be parseable by the reused core's parser,
    // proving we did not fork the format.
    let root = [0x5a; 32];
    let commitment = AnchorCommitment::new(root);
    let script = AnchorBuilder::op_return_script(&commitment);
    // strip OP_RETURN opcode (1) + push-length (1) => 40-byte payload.
    let payload = &script.as_bytes()[2..];
    let parsed = AnchorCommitment::from_op_return_payload(payload).expect("core parses payload");
    assert_eq!(parsed.merkle_root, root);
}

#[test]
fn txid_stable_across_segwit_signing() {
    // For SegWit inputs the legacy txid is computed over non-witness bytes,
    // so adding a witness must NOT change the txid. This is the property that
    // lets a non-custodial caller learn the txid before signing.
    let builder = AnchorBuilder::new();
    let anchor = builder
        .build_unsigned(
            &AnchorCommitment::new([0x7c; 32]),
            vec![dummy_input(0)],
            vec![],
        )
        .unwrap();
    let before = anchor.txid();

    let mut signed: Transaction = anchor.tx.clone();
    let mut w = Witness::new();
    w.push(vec![0xde, 0xad, 0xbe, 0xef]); // fake signature element
    signed.input[0].witness = w;

    assert_eq!(
        before,
        signed.compute_txid(),
        "witness must not change txid"
    );
}
