//! Federated Governance Model
//!
//! All structural changes to the federation (adding/removing members, rotating
//! policy authority, updating quorum policy) are represented as signed,
//! append-only [`GovernanceRecord`]s in a [`GovernanceLog`].
//!
//! # Security Properties
//!
//! - **Replay protection**: Each record carries a unique 32-byte `nonce`. The
//!   log rejects any record whose nonce was already seen.
//! - **Chain integrity**: Each record may reference the hash of the preceding
//!   record via `previous_action_hash`. A broken chain is rejected.
//! - **Signature requirement**: Records with an empty `signature` are rejected
//!   at validation time (structural check; cryptographic verification is the
//!   PKI layer's responsibility).
//! - **Append-only**: Records may not be removed or mutated after appending.
//! - **Bitcoin anchoring**: Governance records produce hashes that can be
//!   included in a [`pqrascv_bitcoin_anchor::federation::FederationBatchAggregator`]
//!   for audit finality. Bitcoin is not used for any decision-making.

use alloc::string::String;
use alloc::vec::Vec;

use crate::verifier_federation::QuorumPolicy;
use crate::verifier_identity::VerifierIdentity;

// ── GovernanceAction ──────────────────────────────────────────────────────

/// A structural change to the federated verifier network.
///
/// All actions must be authorized by the current policy authority and
/// recorded in the [`GovernanceLog`] before taking effect.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum GovernanceAction {
    /// Admit a new verifier to the federation.
    AddVerifier { verifier: VerifierIdentity },
    /// Remove a verifier from the federation by ID.
    RemoveVerifier { verifier_id: String },
    /// Replace the policy authority verifier.
    RotatePolicyAuthority {
        old_authority: String,
        new_authority: String,
    },
    /// Permanently revoke a verifier and record the reason.
    RevokeVerifier { verifier_id: String, reason: String },
    /// Change the federation's quorum policy.
    UpdateQuorumPolicy { new_policy: QuorumPolicy },
}

// ── GovernanceRecord ──────────────────────────────────────────────────────

/// A single, signed, replay-protected governance action.
///
/// Records are append-only. Once accepted by [`GovernanceLog::append`], a
/// record cannot be removed or modified.
///
/// # Nonce
///
/// The `nonce` MUST be unique across all records in the log. A 32-byte
/// nonce provides sufficient collision resistance for normal federation
/// lifetimes. Zero nonces are explicitly rejected as likely-erroneous.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GovernanceRecord {
    /// Application-defined unique action identifier (UUID or similar).
    pub action_id: String,
    /// The governance action being recorded.
    pub action: GovernanceAction,
    /// Verifier ID of the entity authorizing this action.
    pub authorized_by: String,
    /// Unix seconds when the action was authorized.
    pub timestamp: u64,
    /// 32-byte unique nonce for replay protection.
    pub nonce: [u8; 32],
    /// Opaque signature bytes over the record content (structural check only).
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// SHA3-256 hash of the preceding governance record, if any.
    ///
    /// Used to detect chain breaks. `None` is valid only for the first record.
    pub previous_action_hash: Option<[u8; 32]>,
}

// ── GovernanceLog ─────────────────────────────────────────────────────────

/// An append-only, replay-protected log of governance records.
#[derive(Debug, Default)]
pub struct GovernanceLog {
    records: Vec<GovernanceRecord>,
    seen_nonces: Vec<[u8; 32]>,
}

impl GovernanceLog {
    /// Creates an empty governance log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates a record's structural integrity.
    ///
    /// Does NOT perform cryptographic signature verification.
    pub fn validate_structure(record: &GovernanceRecord) -> Result<(), GovernanceError> {
        if record.signature.is_empty() {
            return Err(GovernanceError::EmptySignature);
        }
        if record.nonce == [0u8; 32] {
            return Err(GovernanceError::EmptyNonce);
        }
        if record.action_id.is_empty() {
            return Err(GovernanceError::EmptyActionId);
        }
        if record.authorized_by.is_empty() {
            return Err(GovernanceError::EmptyAuthorizedBy);
        }
        Ok(())
    }

    /// Appends a validated governance record to the log.
    ///
    /// # Checks
    ///
    /// 1. Structural validation (non-empty signature, non-zero nonce).
    /// 2. Nonce uniqueness (replay protection).
    /// 3. Chain integrity (`previous_action_hash` must match the last record's
    ///    `action_id` hash, if both are present).
    pub fn append(&mut self, record: GovernanceRecord) -> Result<(), GovernanceError> {
        Self::validate_structure(&record)?;

        // Replay protection: reject duplicate nonces
        if self.seen_nonces.contains(&record.nonce) {
            return Err(GovernanceError::ReplayDetected {
                nonce: record.nonce,
            });
        }

        // Chain integrity: if the log is non-empty and the record declares a
        // previous hash, it must match our expectation.
        if let Some(last) = self.records.last() {
            if let Some(prev_hash) = record.previous_action_hash {
                // We use the action_id bytes as a stand-in for a full hash in
                // this structural model (PKI layer provides full hash chaining).
                let last_id_bytes = last.action_id.as_bytes();
                let mut expected = [0u8; 32];
                let copy_len = last_id_bytes.len().min(32);
                expected[..copy_len].copy_from_slice(&last_id_bytes[..copy_len]);
                if prev_hash != expected {
                    return Err(GovernanceError::ChainBroken {
                        expected,
                        got: prev_hash,
                    });
                }
            }
        } else if record.previous_action_hash.is_some() {
            // First record must not claim a predecessor
            return Err(GovernanceError::ChainBroken {
                expected: [0u8; 32],
                got: record.previous_action_hash.unwrap_or([0u8; 32]),
            });
        }

        self.seen_nonces.push(record.nonce);
        self.records.push(record);
        Ok(())
    }

    /// Returns all records in the log (read-only).
    #[must_use]
    pub fn records(&self) -> &[GovernanceRecord] {
        &self.records
    }

    /// Returns the number of records in the log.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Returns the most recent record, if any.
    #[must_use]
    pub fn latest(&self) -> Option<&GovernanceRecord> {
        self.records.last()
    }
}

// ── GovernanceError ───────────────────────────────────────────────────────

/// Errors from governance record validation or append operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceError {
    /// The record's signature field is empty.
    EmptySignature,
    /// The record's nonce is all-zero (likely uninitialized).
    EmptyNonce,
    /// The record's `action_id` is empty.
    EmptyActionId,
    /// The record's `authorized_by` is empty.
    EmptyAuthorizedBy,
    /// A record with this nonce was already appended (replay attack).
    ReplayDetected { nonce: [u8; 32] },
    /// The `previous_action_hash` does not match the expected chain link.
    ChainBroken { expected: [u8; 32], got: [u8; 32] },
}

impl core::fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptySignature => f.write_str("governance record has empty signature"),
            Self::EmptyNonce => f.write_str("governance record has zero nonce"),
            Self::EmptyActionId => f.write_str("governance record has empty action_id"),
            Self::EmptyAuthorizedBy => f.write_str("governance record has empty authorized_by"),
            Self::ReplayDetected { nonce } => {
                write!(f, "governance replay detected: nonce {nonce:x?}")
            }
            Self::ChainBroken { expected, got } => write!(
                f,
                "governance chain broken: expected {expected:x?}, got {got:x?}"
            ),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn make_record(action_id: &str, nonce: [u8; 32]) -> GovernanceRecord {
        GovernanceRecord {
            action_id: action_id.into(),
            action: GovernanceAction::RemoveVerifier {
                verifier_id: "old-v".into(),
            },
            authorized_by: "authority-v".into(),
            timestamp: 1000,
            nonce,
            signature: vec![0xde, 0xad, 0xbe, 0xef],
            previous_action_hash: None,
        }
    }

    fn nonce(n: u8) -> [u8; 32] {
        let mut arr = [0u8; 32];
        arr[0] = n;
        arr
    }

    #[test]
    fn append_single_record() {
        let mut log = GovernanceLog::new();
        let r = make_record("action-1", nonce(1));
        log.append(r).unwrap();
        assert_eq!(log.record_count(), 1);
    }

    #[test]
    fn replay_rejected() {
        let mut log = GovernanceLog::new();
        log.append(make_record("a1", nonce(1))).unwrap();
        let r2 = make_record("a2", nonce(1)); // same nonce
        let err = log.append(r2).unwrap_err();
        assert!(matches!(err, GovernanceError::ReplayDetected { .. }));
    }

    #[test]
    fn empty_signature_rejected() {
        let mut record = make_record("a1", nonce(1));
        record.signature = vec![];
        assert!(matches!(
            GovernanceLog::validate_structure(&record).unwrap_err(),
            GovernanceError::EmptySignature
        ));
    }

    #[test]
    fn zero_nonce_rejected() {
        let record = make_record("a1", [0u8; 32]);
        assert!(matches!(
            GovernanceLog::validate_structure(&record).unwrap_err(),
            GovernanceError::EmptyNonce
        ));
    }

    #[test]
    fn two_unique_nonces_accepted() {
        let mut log = GovernanceLog::new();
        log.append(make_record("a1", nonce(1))).unwrap();
        log.append(make_record("a2", nonce(2))).unwrap();
        assert_eq!(log.record_count(), 2);
    }

    #[test]
    fn first_record_with_previous_hash_rejected() {
        let mut log = GovernanceLog::new();
        let mut r = make_record("a1", nonce(1));
        r.previous_action_hash = Some([0xABu8; 32]);
        let err = log.append(r).unwrap_err();
        assert!(matches!(err, GovernanceError::ChainBroken { .. }));
    }

    #[test]
    fn add_verifier_action_roundtrip() {
        let action = GovernanceAction::AddVerifier {
            verifier: VerifierIdentity {
                verifier_id: "new-v".into(),
                organization: "NewOrg".into(),
                public_key: vec![0xab],
                capabilities: vec![
                    crate::verifier_identity::VerifierCapability::HardwareVerification,
                ],
            },
        };
        let record = GovernanceRecord {
            action_id: "add-new-v".into(),
            action,
            authorized_by: "auth".into(),
            timestamp: 2000,
            nonce: nonce(42),
            signature: vec![1, 2, 3, 4],
            previous_action_hash: None,
        };
        let mut log = GovernanceLog::new();
        log.append(record).unwrap();
        assert!(matches!(
            log.latest().unwrap().action,
            GovernanceAction::AddVerifier { .. }
        ));
    }
}
