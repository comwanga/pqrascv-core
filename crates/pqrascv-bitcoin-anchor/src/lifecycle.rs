//! Anchor lifecycle API (Phase 7E).
//!
//! [`AnchorLifecycle`] owns the full lifecycle of a Bitcoin anchor, tying
//! together the building blocks of phases 7A–7D plus the no_std core's
//! `SpvVerifier`:
//!
//! - [`create_anchor`](AnchorLifecycle::create_anchor) — build the unsigned
//!   anchor transaction (7A);
//! - [`broadcast_anchor`](AnchorLifecycle::broadcast_anchor) — submit it
//!   idempotently with bounded retry (7B);
//! - [`track_anchor`](AnchorLifecycle::track_anchor) /
//!   [`wait_for_confirmations`](AnchorLifecycle::wait_for_confirmations) —
//!   confirmation depth from the locally-validated header tip (7C);
//! - [`verify_anchor`](AnchorLifecycle::verify_anchor) — SPV-verify an inclusion
//!   proof, **binding it to the oracle's validated chain** rather than trusting
//!   the caller-supplied header or tip.
//!
//! # Trust binding
//!
//! The core `SpvVerifier::verify` trusts the `block_header` and tip height it is
//! handed. `verify_anchor` closes that gap: it derives the tip from the
//! [`HeaderOracle`] (7C/7D, locally PoW/continuity-validated) and rejects any
//! proof whose `block_header` does not byte-match the oracle's header at the
//! proof's height.

use bitcoin::{Transaction, TxIn, TxOut, Txid};

use pqrascv_bitcoin_anchor::proof::{InclusionProof, SpvError, SpvVerifier};
use pqrascv_bitcoin_anchor::AnchorCommitment;

use crate::broadcast::{retry_broadcast, BroadcastError, Broadcaster, RetryConfig};
use crate::builder::{AnchorBuilder, AnchorTx, BuildError};
use crate::oracle::{HeaderOracle, OracleError};

/// Errors spanning the anchor lifecycle.
///
/// Not `PartialEq`/`Clone` because the wrapped [`BroadcastError`] is neither;
/// match on variants instead.
#[derive(Debug)]
#[non_exhaustive]
pub enum LifecycleError {
    /// Building the unsigned transaction failed.
    Build(BuildError),
    /// Broadcasting failed (after retry).
    Broadcast(BroadcastError),
    /// A header source was unavailable or out of range.
    Oracle(OracleError),
    /// SPV proof verification failed.
    Spv(SpvError),
    /// The proof's `block_header` does not match the oracle's validated header
    /// at the proof's height — the proof is not on the trusted chain.
    HeaderMismatch { height: u32 },
    /// `wait_for_confirmations` exhausted its polls before reaching the target.
    ConfirmationTimeout { confirmations: u32, required: u32 },
}

impl From<BuildError> for LifecycleError {
    fn from(e: BuildError) -> Self {
        Self::Build(e)
    }
}
impl From<BroadcastError> for LifecycleError {
    fn from(e: BroadcastError) -> Self {
        Self::Broadcast(e)
    }
}
impl From<OracleError> for LifecycleError {
    fn from(e: OracleError) -> Self {
        Self::Oracle(e)
    }
}
impl From<SpvError> for LifecycleError {
    fn from(e: SpvError) -> Self {
        Self::Spv(e)
    }
}

impl core::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Build(e) => write!(f, "anchor build failed: {e}"),
            Self::Broadcast(e) => write!(f, "anchor broadcast failed: {e}"),
            Self::Oracle(e) => write!(f, "header oracle error: {e}"),
            Self::Spv(e) => write!(f, "spv verification failed: {e:?}"),
            Self::HeaderMismatch { height } => write!(
                f,
                "proof header at height {height} does not match the validated chain"
            ),
            Self::ConfirmationTimeout {
                confirmations,
                required,
            } => write!(
                f,
                "timed out waiting for confirmations: {confirmations}/{required}"
            ),
        }
    }
}

impl std::error::Error for LifecycleError {}

/// Owns the create → broadcast → track → verify lifecycle of a Bitcoin anchor.
///
/// Generic over a [`Broadcaster`] (7B) and a [`HeaderOracle`] (7C/7D) so it works
/// with the mock/fixture implementations in tests and the live backends in
/// production without code change.
pub struct AnchorLifecycle<B: Broadcaster, O: HeaderOracle> {
    broadcaster: B,
    oracle: O,
    retry: RetryConfig,
}

impl<B: Broadcaster, O: HeaderOracle> AnchorLifecycle<B, O> {
    /// Builds a lifecycle over a broadcaster and a header oracle, with the
    /// default retry policy.
    pub fn new(broadcaster: B, oracle: O) -> Self {
        Self {
            broadcaster,
            oracle,
            retry: RetryConfig::default(),
        }
    }

    /// Overrides the broadcast retry policy.
    #[must_use]
    pub fn with_retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    /// **create** — builds the unsigned anchor transaction committing to
    /// `commitment`, funded by caller-supplied `inputs` and `change` outputs.
    /// Non-custodial: the caller's wallet signs and the lifecycle never holds keys.
    ///
    /// # Errors
    /// [`LifecycleError::Build`] if the transaction cannot be assembled.
    pub fn create_anchor(
        &self,
        commitment: &AnchorCommitment,
        inputs: Vec<TxIn>,
        change: Vec<TxOut>,
    ) -> Result<AnchorTx, LifecycleError> {
        Ok(AnchorBuilder::new().build_unsigned(commitment, inputs, change)?)
    }

    /// **create** for any [`Anchorable`](crate::finality::Anchorable) artifact —
    /// a federation checkpoint (7F) or provenance record (7G). Computes its
    /// canonical commitment and builds the unsigned anchor transaction.
    ///
    /// # Errors
    /// [`LifecycleError::Build`] if the transaction cannot be assembled.
    pub fn create_anchor_for(
        &self,
        item: &impl crate::finality::Anchorable,
        inputs: Vec<TxIn>,
        change: Vec<TxOut>,
    ) -> Result<AnchorTx, LifecycleError> {
        self.create_anchor(&item.anchor_commitment(), inputs, change)
    }

    /// **broadcast** — submits a (caller-signed) transaction idempotently with
    /// bounded retry on transient failures, returning its txid.
    ///
    /// # Errors
    /// [`LifecycleError::Broadcast`] if submission fails after retry.
    pub fn broadcast_anchor(&self, tx: &Transaction) -> Result<Txid, LifecycleError> {
        let txid = retry_broadcast(
            self.retry,
            || self.broadcaster.broadcast(tx),
            |_ms| { /* caller-driven; tests inject no real sleep */ },
        )?;
        Ok(txid)
    }

    /// **track** — confirmation depth of a transaction known to be in the block
    /// at `block_height`, using the oracle's validated tip. Returns `0` if the
    /// tip has not yet reached `block_height`.
    ///
    /// # Errors
    /// [`LifecycleError::Oracle`] if the tip cannot be read.
    pub fn track_anchor(&self, block_height: u32) -> Result<u32, LifecycleError> {
        let tip = self.oracle.tip_height()?;
        Ok(confirmations_at(tip, block_height))
    }

    /// **wait** — polls until the anchor at `block_height` reaches `target`
    /// confirmations, sleeping `poll_interval_ms` between polls (via the injected
    /// `sleep`, so tests stay instant) for at most `max_polls` iterations.
    ///
    /// # Errors
    /// [`LifecycleError::ConfirmationTimeout`] if the target is not reached in
    /// `max_polls`; [`LifecycleError::Oracle`] if the tip cannot be read.
    pub fn wait_for_confirmations<S: FnMut(u64)>(
        &self,
        block_height: u32,
        target: u32,
        max_polls: u32,
        poll_interval_ms: u64,
        mut sleep: S,
    ) -> Result<u32, LifecycleError> {
        let mut last = 0;
        for _ in 0..max_polls.max(1) {
            let tip = self.oracle.tip_height()?;
            last = confirmations_at(tip, block_height);
            if last >= target {
                return Ok(last);
            }
            sleep(poll_interval_ms);
        }
        Err(LifecycleError::ConfirmationTimeout {
            confirmations: last,
            required: target,
        })
    }

    /// **verify** — SPV-verifies that `quote_hash` is anchored by `proof`,
    /// **binding the proof to the oracle's validated chain**: the tip comes from
    /// the oracle (not a caller assertion) and the proof's `block_header` must
    /// byte-match the oracle's header at `proof.block_height`.
    ///
    /// Returns the anchored block height on success.
    ///
    /// # Errors
    /// - [`LifecycleError::Oracle`] if the oracle lacks the proof's height;
    /// - [`LifecycleError::HeaderMismatch`] if the proof header is off-chain;
    /// - [`LifecycleError::Spv`] if SPV verification fails.
    pub fn verify_anchor(
        &self,
        proof: &InclusionProof,
        quote_hash: &[u8; 32],
        min_confirmations: u32,
    ) -> Result<u32, LifecycleError> {
        // Tip is taken from the locally-validated oracle, never asserted by the caller.
        let tip = self.oracle.tip_height()?;

        // Bind the proof to the validated chain: its header must be the one the
        // oracle serves at that height.
        let oracle_header = self.oracle.header_at(proof.block_height)?;
        let oracle_header_bytes = bitcoin::consensus::serialize(&oracle_header);
        if oracle_header_bytes != proof.block_header {
            return Err(LifecycleError::HeaderMismatch {
                height: proof.block_height,
            });
        }

        let verifier = SpvVerifier::new(min_confirmations, tip);
        let height = verifier.verify(proof, quote_hash)?;
        Ok(height)
    }
}

/// Confirmations for a tx in the block at `block_height` given a chain `tip`.
/// `0` if the tip has not yet reached the block.
fn confirmations_at(tip: u32, block_height: u32) -> u32 {
    if tip >= block_height {
        tip - block_height + 1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broadcast::MockBroadcaster;
    use crate::oracle::test_support::build_chain;
    use crate::oracle::{regtest_max_bits, FixtureHeaderOracle};
    use bitcoin::hashes::Hash as _;
    use bitcoin::{OutPoint, ScriptBuf, Sequence, Witness};

    fn dummy_input() -> TxIn {
        TxIn {
            previous_output: OutPoint::new(Txid::all_zeros(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    fn lifecycle_with_tip(
        base: u32,
        len: u32,
    ) -> AnchorLifecycle<MockBroadcaster, FixtureHeaderOracle> {
        let chain = build_chain(len, regtest_max_bits());
        let oracle = FixtureHeaderOracle::new(base, chain).unwrap();
        AnchorLifecycle::new(MockBroadcaster::new(), oracle)
    }

    #[test]
    fn create_anchor_builds_op_return_tx() {
        let life = lifecycle_with_tip(0, 1);
        let commitment = AnchorCommitment::new([0x11; 32]);
        let anchor = life
            .create_anchor(&commitment, vec![dummy_input()], vec![])
            .unwrap();
        // Exactly one output, the OP_RETURN, carrying our commitment.
        assert_eq!(anchor.tx.output.len(), 1);
        assert!(anchor.op_return_script().is_op_return());
    }

    #[test]
    fn broadcast_anchor_is_idempotent() {
        let life = lifecycle_with_tip(0, 1);
        let commitment = AnchorCommitment::new([0x22; 32]);
        let anchor = life
            .create_anchor(&commitment, vec![dummy_input()], vec![])
            .unwrap();
        let first = life.broadcast_anchor(&anchor.tx).unwrap();
        let second = life.broadcast_anchor(&anchor.tx).unwrap();
        assert_eq!(first, second);
        assert_eq!(first, anchor.txid());
    }

    #[test]
    fn track_anchor_reports_confirmation_depth() {
        // Oracle tip at height 100 (base 100, len 1). A tx in block 100 has 1 conf.
        let life = lifecycle_with_tip(100, 1);
        assert_eq!(life.track_anchor(100).unwrap(), 1);
        // A tx claimed in a future block has 0 confirmations.
        assert_eq!(life.track_anchor(150).unwrap(), 0);
    }

    #[test]
    fn wait_for_confirmations_succeeds_when_already_deep() {
        // Tip 105 (base 100, len 6). Block 100 ⇒ 6 confirmations.
        let life = lifecycle_with_tip(100, 6);
        let mut slept = 0u32;
        let got = life
            .wait_for_confirmations(100, 3, 5, 10, |_| slept += 1)
            .unwrap();
        assert_eq!(got, 6);
        assert_eq!(slept, 0, "should not sleep when already confirmed");
    }

    #[test]
    fn wait_for_confirmations_times_out() {
        // Tip 100 (1 conf), but we require 6 — fixed tip never advances.
        let life = lifecycle_with_tip(100, 1);
        let mut polls = 0u32;
        let err = life
            .wait_for_confirmations(100, 6, 3, 10, |_| polls += 1)
            .unwrap_err();
        assert!(matches!(
            err,
            LifecycleError::ConfirmationTimeout {
                confirmations: 1,
                required: 6,
            }
        ));
        assert_eq!(polls, 3, "slept between each of the 3 polls");
    }

    #[test]
    fn verify_anchor_rejects_off_chain_header() {
        // The proof claims a header that is NOT the oracle's header at that height.
        let life = lifecycle_with_tip(0, 3);
        let proof = InclusionProof {
            block_height: 1,
            block_header: vec![0xAB; 80], // not the oracle's header bytes
            tx_merkle_path: pqrascv_bitcoin_anchor::proof::TxMerklePath {
                txid: [0; 32],
                steps: vec![],
                block_merkle_root: [0; 32],
            },
            pqrascv_merkle_root: [0; 32],
            quote_merkle_path: pqrascv_bitcoin_anchor::merkle::MerkleProofPath {
                leaf_hash: [0; 32],
                root: [0; 32],
                path: vec![],
            },
        };
        assert!(matches!(
            life.verify_anchor(&proof, &[0; 32], 1),
            Err(LifecycleError::HeaderMismatch { height: 1 })
        ));
    }

    #[test]
    fn verify_anchor_rejects_height_beyond_oracle() {
        let life = lifecycle_with_tip(0, 3);
        let proof = InclusionProof {
            block_height: 999,
            block_header: vec![0xAB; 80],
            tx_merkle_path: pqrascv_bitcoin_anchor::proof::TxMerklePath {
                txid: [0; 32],
                steps: vec![],
                block_merkle_root: [0; 32],
            },
            pqrascv_merkle_root: [0; 32],
            quote_merkle_path: pqrascv_bitcoin_anchor::merkle::MerkleProofPath {
                leaf_hash: [0; 32],
                root: [0; 32],
                path: vec![],
            },
        };
        assert!(matches!(
            life.verify_anchor(&proof, &[0; 32], 1),
            Err(LifecycleError::Oracle(OracleError::OutOfRange))
        ));
    }

    // Note: the full SPV happy-path (valid merkle paths + matching header) is
    // covered by the core crate's `proof.rs` tests. The lifecycle's *new* logic
    // — deriving the tip from the oracle and binding the proof header to the
    // validated chain — is what these tests exercise.
}
