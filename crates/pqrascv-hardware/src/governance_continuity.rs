//! Governance Continuity Tracking
//!
//! Provides hash-chained epoch transitions to ensure governance history
//! behaves like an append-only transparency log. Prevents governance replay
//! attacks, arbitrary rollbacks, and alternate history emergence.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A cryptographically linked transition between two federation governance epochs.
///
/// Chaining `previous_transition_hash` guarantees that the sequence of governance
/// changes forms an immutable DAG (or linear chain).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceTransition {
    /// The epoch number being transitioned from.
    pub previous_epoch: u64,
    /// The new epoch number becoming active. Must be strictly greater than `previous_epoch`.
    pub next_epoch: u64,
    /// The canonical hash of the immediate predecessor `GovernanceTransition`.
    /// Forms the cryptographic link preventing alternate governance histories.
    pub previous_transition_hash: [u8; 32],
    /// The canonical hash of this specific transition event.
    pub transition_hash: [u8; 32],
    /// The verifiers/authorities that approved this transition.
    pub approved_by: Vec<String>,
    /// The aggregate quorum signature authorizing the transition.
    #[serde(with = "serde_bytes")]
    pub quorum_signature: Vec<u8>,
}

impl GovernanceTransition {
    /// Verifies that this transition correctly links to its predecessor.
    ///
    /// # Errors
    /// Returns an error if the transition violates monotonicity or hash linkage.
    pub fn verify_linkage(&self, previous: &GovernanceTransition) -> Result<(), &'static str> {
        if self.previous_epoch != previous.next_epoch {
            return Err("epoch discontinuity detected");
        }
        if self.next_epoch <= self.previous_epoch {
            return Err("epoch transition must be strictly monotonic");
        }
        if self.previous_transition_hash != previous.transition_hash {
            return Err("governance transition hash chain broken");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_transition_linkage() {
        let t1 = GovernanceTransition {
            previous_epoch: 1,
            next_epoch: 2,
            previous_transition_hash: [0x00; 32],
            transition_hash: [0xAA; 32],
            approved_by: vec![],
            quorum_signature: vec![],
        };

        let t2 = GovernanceTransition {
            previous_epoch: 2,
            next_epoch: 3,
            previous_transition_hash: [0xAA; 32],
            transition_hash: [0xBB; 32],
            approved_by: vec![],
            quorum_signature: vec![],
        };

        assert!(t2.verify_linkage(&t1).is_ok());
    }

    #[test]
    fn invalid_hash_linkage() {
        let t1 = GovernanceTransition {
            previous_epoch: 1,
            next_epoch: 2,
            previous_transition_hash: [0x00; 32],
            transition_hash: [0xAA; 32],
            approved_by: vec![],
            quorum_signature: vec![],
        };

        let t2 = GovernanceTransition {
            previous_epoch: 2,
            next_epoch: 3,
            previous_transition_hash: [0xBB; 32], // Mismatch!
            transition_hash: [0xCC; 32],
            approved_by: vec![],
            quorum_signature: vec![],
        };

        assert!(t2.verify_linkage(&t1).is_err());
    }

    #[test]
    fn invalid_epoch_monotonicity() {
        let t1 = GovernanceTransition {
            previous_epoch: 1,
            next_epoch: 2,
            previous_transition_hash: [0x00; 32],
            transition_hash: [0xAA; 32],
            approved_by: vec![],
            quorum_signature: vec![],
        };

        let t2 = GovernanceTransition {
            previous_epoch: 2,
            next_epoch: 1, // Reverted!
            previous_transition_hash: [0xAA; 32],
            transition_hash: [0xBB; 32],
            approved_by: vec![],
            quorum_signature: vec![],
        };

        assert!(t2.verify_linkage(&t1).is_err());
    }
}
