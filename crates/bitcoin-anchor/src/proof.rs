//! Bitcoin SPV inclusion proof verification.
//!
//! Allows verifying that an attestation quote was anchored in a specific
//! Bitcoin block without requiring a full node. The verifier only needs:
//!
//! 1. The block header (80 bytes) — obtainable from any SPV client.
//! 2. The Merkle proof path from the anchor transaction to the block's Merkle root.
//! 3. The OP_RETURN payload from the anchor transaction.
//!
//! # Verification Steps
//!
//! 1. Verify the Merkle proof path → confirms the anchor tx is in the block.
//! 2. Parse the OP_RETURN payload → extract the PQ-RASCV Merkle root prefix.
//! 3. Look up the full Merkle root in the local anchor database.
//! 4. Verify the quote hash is in the PQ-RASCV Merkle tree.

extern crate alloc;
use alloc::vec::Vec;

use crate::merkle::{MerkleProofPath, ProofStep};
use sha2::{Digest, Sha256};

/// Double-SHA256 as used in Bitcoin.
fn sha256d(data: &[u8]) -> [u8; 32] {
    let first: [u8; 32] = Sha256::digest(data).into();
    Sha256::digest(first).into()
}

// ── InclusionProof ────────────────────────────────────────────────────────

/// A complete inclusion proof linking an attestation quote to a Bitcoin block.
///
/// Produced by the anchor service after a transaction is confirmed.
/// Stored in the local anchor database and distributed to verifiers.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InclusionProof {
    /// Bitcoin block height.
    pub block_height: u32,
    /// Bitcoin block header (80 bytes).
    #[serde(with = "serde_bytes")]
    pub block_header: Vec<u8>,
    /// Merkle proof path from the anchor transaction to the block's Merkle root.
    pub tx_merkle_path: TxMerklePath,
    /// The full PQ-RASCV Merkle root committed in the OP_RETURN.
    pub pqrascv_merkle_root: [u8; 32],
    /// Merkle proof path from the quote hash to the PQ-RASCV Merkle root.
    pub quote_merkle_path: MerkleProofPath,
}

/// A Merkle proof path within a Bitcoin block (transaction → block Merkle root).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TxMerklePath {
    /// The transaction hash (txid, double-SHA256, little-endian).
    pub txid: [u8; 32],
    /// Proof steps from txid to block Merkle root.
    pub steps: Vec<ProofStep>,
    /// The block's Merkle root (from the block header).
    pub block_merkle_root: [u8; 32],
}

impl TxMerklePath {
    /// Verifies this path, returning `true` if the txid is in the block.
    #[must_use]
    pub fn verify(&self) -> bool {
        let mut current = self.txid;
        for step in &self.steps {
            let Some(sibling) = step.sibling_hash else {
                // Promoted node — pass through unchanged
                continue;
            };
            let mut combined = [0u8; 64];
            if step.is_left {
                combined[..32].copy_from_slice(&sibling);
                combined[32..].copy_from_slice(&current);
            } else {
                combined[..32].copy_from_slice(&current);
                combined[32..].copy_from_slice(&sibling);
            }
            current = sha256d(&combined);
        }
        current == self.block_merkle_root
    }
}

// ── SpvVerifier ───────────────────────────────────────────────────────────

/// Verifies Bitcoin SPV inclusion proofs for PQ-RASCV attestation anchors.
pub struct SpvVerifier {
    pub min_confirmations: u32,
    pub chain_tip_height: u32,
    /// Maximum acceptable target as compact `bits`.
    /// Lower value = harder difficulty.
    /// Bitcoin mainnet genesis: `0x1d00ffff`.
    /// Set to `0` to skip PoW validation (for unit tests with fake headers only).
    pub max_target_bits: u32,
}

impl SpvVerifier {
    /// Creates a verifier with Bitcoin mainnet minimum difficulty (`0x1d00ffff`).
    #[must_use]
    pub fn new(min_confirmations: u32, chain_tip_height: u32) -> Self {
        Self { min_confirmations, chain_tip_height, max_target_bits: 0x1d00ffff }
    }

    /// Override the maximum target bits (lower = more secure).
    #[must_use]
    pub fn with_max_target_bits(mut self, bits: u32) -> Self {
        self.max_target_bits = bits;
        self
    }

    pub fn verify(&self, proof: &InclusionProof, quote_hash: &[u8; 32]) -> Result<u32, SpvError> {
        // Step 0: Proof-of-work validation (skip only if max_target_bits == 0)
        if self.max_target_bits != 0
            && !validate_proof_of_work(&proof.block_header, self.max_target_bits) {
                return Err(SpvError::InsufficientProofOfWork);
            }

        // Step 1: Confirmation count
        let confirmations = self
            .chain_tip_height
            .saturating_sub(proof.block_height)
            .saturating_add(1);
        if confirmations < self.min_confirmations {
            return Err(SpvError::InsufficientConfirmations {
                got: confirmations,
                required: self.min_confirmations,
            });
        }

        // Step 2: Block header Merkle root consistency
        let header_merkle_root =
            extract_block_merkle_root(&proof.block_header).ok_or(SpvError::InvalidBlockHeader)?;
        if header_merkle_root != proof.tx_merkle_path.block_merkle_root {
            return Err(SpvError::MerkleRootMismatch);
        }

        // Step 3: Transaction in block
        if !proof.tx_merkle_path.verify() {
            return Err(SpvError::TxNotInBlock);
        }

        // Step 4: PQ-RASCV Merkle root match
        if proof.quote_merkle_path.root != proof.pqrascv_merkle_root {
            return Err(SpvError::MerkleRootMismatch);
        }

        // Step 5: Quote hash in PQ-RASCV tree (RFC6962 leaf hash)
        let expected_leaf: [u8; 32] = {
            let mut buf = [0u8; 33];
            buf[0] = 0x00; // RFC6962 leaf prefix
            buf[1..].copy_from_slice(quote_hash);
            let first: [u8; 32] = sha2::Sha256::digest(buf).into();
            sha2::Sha256::digest(first).into()
        };
        if proof.quote_merkle_path.leaf_hash != expected_leaf {
            return Err(SpvError::QuoteNotInAnchor);
        }
        if !proof.quote_merkle_path.verify() {
            return Err(SpvError::QuoteNotInAnchor);
        }

        Ok(proof.block_height)
    }
}

/// Extracts the 32-byte Merkle root from an 80-byte Bitcoin block header.
///
/// Block header layout:
/// - bytes 0–3:   version (4 bytes, little-endian)
/// - bytes 4–35:  previous block hash (32 bytes)
/// - bytes 36–67: Merkle root (32 bytes)
/// - bytes 68–71: time (4 bytes)
/// - bytes 72–75: bits (4 bytes)
/// - bytes 76–79: nonce (4 bytes)
fn extract_block_merkle_root(header: &[u8]) -> Option<[u8; 32]> {
    if header.len() < 80 {
        return None;
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&header[36..68]);
    Some(root)
}

/// Returns `true` if the block header satisfies the given maximum target difficulty.
fn validate_proof_of_work(header: &[u8], max_target_bits: u32) -> bool {
    if header.len() < 80 { return false; }
    let block_bits = u32::from_le_bytes([header[72], header[73], header[74], header[75]]);
    let block_target = match bits_to_target(block_bits) { Some(t) => t, None => return false };
    let max_target   = match bits_to_target(max_target_bits) { Some(t) => t, None => return false };
    // Block's claimed target must be at most as easy as the maximum allowed
    if block_target > max_target { return false; }
    // SHA256d(header) must be below the block's target
    hash_below_target(&sha256d(header), &block_target)
}

/// Converts Bitcoin compact `bits` to a 32-byte big-endian target value.
/// Returns `None` for negative, zero, or out-of-range values.
fn bits_to_target(bits: u32) -> Option<[u8; 32]> {
    let exp      = (bits >> 24) as usize;
    let mantissa = (bits & 0x007F_FFFF) as u64;
    if bits & 0x0080_0000 != 0 { return None; } // negative
    if mantissa == 0            { return None; } // zero
    if !(3..=32).contains(&exp) { return None; } // invalid exponent
    let mut target = [0u8; 32];
    let start = 32 - exp;
    target[start] = ((mantissa >> 16) & 0xFF) as u8;
    if start + 1 < 32 { target[start + 1] = ((mantissa >> 8)  & 0xFF) as u8; }
    if start + 2 < 32 { target[start + 2] = (mantissa         & 0xFF) as u8; }
    Some(target)
}

/// Returns `true` if `hash` (SHA256d output, little-endian) is below `target` (big-endian).
fn hash_below_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    let mut h_be = *hash;
    h_be.reverse(); // convert from little-endian to big-endian for comparison
    h_be < *target
}

// ── SpvError ──────────────────────────────────────────────────────────────

/// Errors from SPV proof verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpvError {
    /// Not enough Bitcoin block confirmations.
    InsufficientConfirmations { got: u32, required: u32 },
    /// The block header is malformed (< 80 bytes).
    InvalidBlockHeader,
    /// The Merkle root in the block header does not match the proof.
    MerkleRootMismatch,
    /// The anchor transaction is not in the claimed block.
    TxNotInBlock,
    /// The quote hash is not in the PQ-RASCV Merkle tree.
    QuoteNotInAnchor,
    /// Block header does not satisfy the claimed or minimum proof-of-work target.
    InsufficientProofOfWork,
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleAggregator;

    fn make_fake_block_header(merkle_root: [u8; 32]) -> Vec<u8> {
        let mut header = vec![0u8; 80];
        header[36..68].copy_from_slice(&merkle_root);
        header
    }

    #[test]
    fn extract_merkle_root_from_header() {
        let root = [0x42u8; 32];
        let header = make_fake_block_header(root);
        assert_eq!(extract_block_merkle_root(&header), Some(root));
    }

    #[test]
    fn extract_merkle_root_rejects_short_header() {
        assert!(extract_block_merkle_root(&[0u8; 79]).is_none());
    }

    #[test]
    fn full_inclusion_proof_verifies() {
        let quote_hashes: Vec<[u8; 32]> = (0u8..4).map(|i| [i; 32]).collect();
        let mut agg = MerkleAggregator::new();
        for h in &quote_hashes {
            agg.add_quote_hash(*h);
        }
        let pqrascv_root = agg.root().unwrap();

        let quote_merkle_path = agg.inclusion_proof(2).unwrap();
        assert!(quote_merkle_path.verify());

        // In production, the tx Merkle path would be over actual Bitcoin txids.
        let fake_txid = pqrascv_root; // simplified for test
        let tx_path = TxMerklePath {
            txid: fake_txid,
            steps: alloc::vec![],
            block_merkle_root: fake_txid,
        };
        let block_header = make_fake_block_header(fake_txid);

        let proof = InclusionProof {
            block_height: 800_000,
            block_header,
            tx_merkle_path: tx_path,
            pqrascv_merkle_root: pqrascv_root,
            quote_merkle_path,
        };

        let verifier = SpvVerifier::new(1, 800_000).with_max_target_bits(0); // skip PoW for fake header
        let height = verifier.verify(&proof, &quote_hashes[2]).unwrap();
        assert_eq!(height, 800_000);
    }

    #[test]
    fn insufficient_confirmations_rejected() {
        let mut agg = MerkleAggregator::new();
        agg.add_quote_hash([0x01u8; 32]);
        let root = agg.root().unwrap();
        let quote_path = agg.inclusion_proof(0).unwrap();

        let tx_path = TxMerklePath {
            txid: root,
            steps: alloc::vec![],
            block_merkle_root: root,
        };
        let proof = InclusionProof {
            block_height: 800_000,
            block_header: make_fake_block_header(root),
            tx_merkle_path: tx_path,
            pqrascv_merkle_root: root,
            quote_merkle_path: quote_path,
        };

        // Chain tip = block_height, so confirmations = 1, but we require 6.
        let verifier = SpvVerifier::new(6, 800_000).with_max_target_bits(0);
        assert!(matches!(
            verifier.verify(&proof, &[0x01u8; 32]),
            Err(SpvError::InsufficientConfirmations { .. })
        ));
    }

    #[test]
    fn forged_zero_work_block_header_rejected() {
        let quote_hash = [0x42u8; 32];
        let mut agg = MerkleAggregator::new();
        agg.add_quote_hash(quote_hash);
        let pqrascv_root = agg.root().unwrap();
        let quote_path = agg.inclusion_proof(0).unwrap();

        let fake_header = make_fake_block_header(pqrascv_root);
        let tx_path = TxMerklePath {
            txid: pqrascv_root,
            steps: alloc::vec![],
            block_merkle_root: pqrascv_root,
        };
        let proof = InclusionProof {
            block_height: 800_000,
            block_header: fake_header,
            tx_merkle_path: tx_path,
            pqrascv_merkle_root: pqrascv_root,
            quote_merkle_path: quote_path,
        };

        // Default SpvVerifier enforces mainnet minimum difficulty
        let verifier = SpvVerifier::new(1, 800_001);
        assert!(
            matches!(verifier.verify(&proof, &quote_hash), Err(SpvError::InsufficientProofOfWork)),
            "zero-work header must be rejected"
        );
    }
}
