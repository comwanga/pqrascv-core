//! Non-custodial anchor transaction builder.
//!
//! [`AnchorBuilder`] turns a 32-byte commitment root (from any PQ-RASCV
//! artifact aggregator) into a Bitcoin `OP_RETURN` output and assembles an
//! **unsigned** transaction template from caller-supplied inputs and change
//! outputs. We never manage keys, fund, or sign — the caller's external wallet
//! does that.
//!
//! # Determinism
//!
//! Given identical inputs (same `TxIn` list, same change outputs, same
//! commitment, same version/locktime) `build_unsigned` produces byte-identical
//! transactions and therefore an identical [`Txid`]. We rely on rust-bitcoin's
//! consensus encoding for this guarantee. The OP_RETURN output is always the
//! **last** output so its position is stable and predictable.

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::blockdata::script::{Builder as ScriptBuilder, PushBytesBuf};
use bitcoin::transaction::Version;
use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Txid};

use pqrascv_bitcoin_anchor::AnchorCommitment;

/// Transaction version used for all anchor transactions.
///
/// Version 2 enables relative-locktime (BIP-68) semantics and is the modern
/// default. The value is fixed so transactions are deterministic; callers who
/// need a different version can post-process the returned `Transaction`.
pub const ANCHOR_TX_VERSION: Version = Version::TWO;

/// Absolute locktime used for all anchor transactions: `0` (no timelock).
///
/// Fixed for determinism. The OP_RETURN anchor carries no spending policy, so a
/// timelock would add nothing but non-determinism.
pub const ANCHOR_TX_LOCKTIME: LockTime = LockTime::ZERO;

/// Errors returned while building an anchor transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// No inputs were supplied. A spendable input is required to fund the
    /// transaction (the OP_RETURN output itself is unspendable and 0-value).
    NoInputs,
    /// More than one OP_RETURN output would be present. Standardness rules
    /// reject transactions with multiple OP_RETURN outputs, so the builder
    /// refuses to assemble one.
    MultipleOpReturn,
    /// A caller-supplied output already looked like an OP_RETURN data carrier.
    /// The builder adds exactly one OP_RETURN (the anchor); callers must not
    /// pre-add their own.
    CallerSuppliedOpReturn,
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoInputs => f.write_str("anchor transaction requires at least one input"),
            Self::MultipleOpReturn => {
                f.write_str("anchor transaction would contain multiple OP_RETURN outputs")
            }
            Self::CallerSuppliedOpReturn => {
                f.write_str("caller-supplied outputs must not contain an OP_RETURN output")
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// A built, **unsigned** anchor transaction plus its committed metadata.
#[derive(Debug, Clone)]
pub struct AnchorTx {
    /// The unsigned transaction template. The caller's wallet funds (if needed),
    /// signs the inputs, and broadcasts it.
    pub tx: Transaction,
    /// The commitment embedded in the OP_RETURN output.
    pub commitment: AnchorCommitment,
    /// Index of the OP_RETURN output within `tx.output` (always the last index).
    pub op_return_vout: u32,
}

impl AnchorTx {
    /// The transaction id (double-SHA256 of the consensus-encoded tx).
    ///
    /// For an unsigned transaction this is **not** the wtxid and will change
    /// once witnesses/scriptSigs are added if the inputs are SegWit — but the
    /// legacy txid of a SegWit spend is computed over the non-witness bytes, so
    /// for SegWit inputs the txid is stable across signing. See module note.
    #[must_use]
    pub fn txid(&self) -> Txid {
        self.tx.compute_txid()
    }

    /// The raw OP_RETURN `script_pubkey`.
    #[must_use]
    pub fn op_return_script(&self) -> &ScriptBuf {
        &self.tx.output[self.op_return_vout as usize].script_pubkey
    }
}

/// Builds non-custodial anchor transactions.
///
/// The builder is artifact-agnostic: every PQ-RASCV artifact (attestation
/// batches, provenance records, federation checkpoints, trust-anchor rollovers)
/// reduces to a 32-byte root. The thin `anchor_*` helpers document intent but
/// all funnel through [`AnchorBuilder::build_unsigned`].
#[derive(Debug, Default, Clone, Copy)]
pub struct AnchorBuilder;

impl AnchorBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Constructs the OP_RETURN `script_pubkey` for a commitment.
    ///
    /// Shape: `OP_RETURN <40-byte payload>`. The payload is exactly
    /// [`ANCHOR_PAYLOAD_SIZE`](pqrascv_bitcoin_anchor::ANCHOR_PAYLOAD_SIZE)
    /// bytes (`"PQRASCV" || 0x02 || root[32]`), produced
    /// by the reused core `AnchorCommitment::to_op_return_payload`.
    ///
    /// # Panics
    ///
    /// Never in practice: the 40-byte payload always fits an `OP_RETURN`
    /// pushdata, so the internal conversion cannot fail.
    #[must_use]
    pub fn op_return_script(commitment: &AnchorCommitment) -> ScriptBuf {
        let payload = commitment.to_op_return_payload();
        // 40 bytes always fits a PushBytesBuf; the conversion cannot fail.
        let mut push = PushBytesBuf::new();
        push.extend_from_slice(&payload)
            .expect("40-byte anchor payload always fits OP_RETURN push");
        ScriptBuilder::new()
            .push_opcode(OP_RETURN)
            .push_slice(push)
            .into_script()
    }

    /// The OP_RETURN `TxOut` (value 0) for a commitment.
    #[must_use]
    pub fn op_return_output(commitment: &AnchorCommitment) -> TxOut {
        TxOut {
            value: Amount::ZERO,
            script_pubkey: Self::op_return_script(commitment),
        }
    }

    /// Builds an unsigned anchor transaction.
    ///
    /// Layout: caller `change_outputs` first (stable order), then exactly one
    /// OP_RETURN output appended last. Version/locktime are fixed
    /// ([`ANCHOR_TX_VERSION`] / [`ANCHOR_TX_LOCKTIME`]) for determinism.
    ///
    /// # Errors
    ///
    /// - [`BuildError::NoInputs`] if `inputs` is empty.
    /// - [`BuildError::CallerSuppliedOpReturn`] if any change output is itself
    ///   an OP_RETURN (would create a second data carrier).
    ///
    /// # Panics
    ///
    /// Never in practice: only if the output count exceeds `u32::MAX`, which
    /// Bitcoin consensus limits make impossible.
    pub fn build_unsigned(
        &self,
        commitment: &AnchorCommitment,
        inputs: Vec<TxIn>,
        change_outputs: Vec<TxOut>,
    ) -> Result<AnchorTx, BuildError> {
        if inputs.is_empty() {
            return Err(BuildError::NoInputs);
        }
        if change_outputs
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
        {
            return Err(BuildError::CallerSuppliedOpReturn);
        }

        let mut output = change_outputs;
        output.push(Self::op_return_output(commitment));
        // The OP_RETURN is the last output. A transaction can never carry close
        // to u32::MAX outputs (Bitcoin consensus limits dwarf that), so this
        // conversion cannot realistically fail.
        let op_return_vout = u32::try_from(output.len() - 1).expect("output index fits in u32");

        // Defensive: exactly one OP_RETURN must be present.
        let op_return_count = output
            .iter()
            .filter(|o| o.script_pubkey.is_op_return())
            .count();
        if op_return_count != 1 {
            return Err(BuildError::MultipleOpReturn);
        }

        let tx = Transaction {
            version: ANCHOR_TX_VERSION,
            lock_time: ANCHOR_TX_LOCKTIME,
            input: inputs,
            output,
        };

        Ok(AnchorTx {
            tx,
            commitment: commitment.clone(),
            op_return_vout,
        })
    }

    /// Builds an unsigned anchor transaction directly from a 32-byte root.
    ///
    /// # Errors
    ///
    /// See [`AnchorBuilder::build_unsigned`].
    pub fn build_unsigned_from_root(
        &self,
        merkle_root: [u8; 32],
        inputs: Vec<TxIn>,
        change_outputs: Vec<TxOut>,
    ) -> Result<AnchorTx, BuildError> {
        self.build_unsigned(&AnchorCommitment::new(merkle_root), inputs, change_outputs)
    }

    // ── Thin artifact-specific helpers ────────────────────────────────────
    //
    // Every artifact reduces to a 32-byte root, so these document caller intent
    // but are otherwise identical to `build_unsigned_from_root`.

    /// Anchors an attestation batch Merkle root.
    ///
    /// # Errors
    /// See [`AnchorBuilder::build_unsigned`].
    pub fn anchor_attestation_batch(
        &self,
        batch_root: [u8; 32],
        inputs: Vec<TxIn>,
        change_outputs: Vec<TxOut>,
    ) -> Result<AnchorTx, BuildError> {
        self.build_unsigned_from_root(batch_root, inputs, change_outputs)
    }

    /// Anchors a provenance record root.
    ///
    /// # Errors
    /// See [`AnchorBuilder::build_unsigned`].
    pub fn anchor_provenance(
        &self,
        provenance_root: [u8; 32],
        inputs: Vec<TxIn>,
        change_outputs: Vec<TxOut>,
    ) -> Result<AnchorTx, BuildError> {
        self.build_unsigned_from_root(provenance_root, inputs, change_outputs)
    }

    /// Anchors a federation checkpoint root.
    ///
    /// # Errors
    /// See [`AnchorBuilder::build_unsigned`].
    pub fn anchor_federation_checkpoint(
        &self,
        checkpoint_root: [u8; 32],
        inputs: Vec<TxIn>,
        change_outputs: Vec<TxOut>,
    ) -> Result<AnchorTx, BuildError> {
        self.build_unsigned_from_root(checkpoint_root, inputs, change_outputs)
    }

    /// Anchors a trust-anchor (key registry) rollover root.
    ///
    /// # Errors
    /// See [`AnchorBuilder::build_unsigned`].
    pub fn anchor_trust_anchor_rollover(
        &self,
        rollover_root: [u8; 32],
        inputs: Vec<TxIn>,
        change_outputs: Vec<TxOut>,
    ) -> Result<AnchorTx, BuildError> {
        self.build_unsigned_from_root(rollover_root, inputs, change_outputs)
    }
}
