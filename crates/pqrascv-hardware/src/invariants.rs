//! Global system invariants and Byzantine assumptions.
//!
//! This module defines the core architectural invariants of the PQ-RASCV system.
//! These invariants are enforced globally across all modules and failure to maintain
//! them is considered a critical Byzantine violation, resulting in a fail-closed state.

use crate::digest::TypedDigest;
use pqrascv_bitcoin_anchor::finality_anchor::FinalityState;

/// Global architectural invariants enforced by the federation node.
pub struct SystemInvariants;

impl SystemInvariants {
    /// Asserts that a timeline timestamp strictly increases relative to the historical watermark.
    /// Violations imply local clock tampering, rollback attacks, or Byzantine equivocation.
    ///
    /// # Panics
    /// Panics if `new_timestamp <= watermark`.
    pub fn assert_monotonic_time(watermark: u64, new_timestamp: u64) {
        if new_timestamp <= watermark {
            panic!(
                "CRITICAL INVARIANT VIOLATION: Non-monotonic time sequence. \
                 Watermark: {}, New: {}. This indicates Byzantine tampering or rollback.",
                watermark, new_timestamp
            );
        }
    }

    /// Asserts that a cryptographic state transition produces a canonical, deterministic hash.
    /// The empty hash `[0; 32]` is never considered a valid delta root.
    ///
    /// # Panics
    /// Panics if `root` is empty (all zeroes).
    pub fn assert_deterministic_delta_root(root: &TypedDigest) {
        if root.value.iter().all(|&b| b == 0) {
            panic!("CRITICAL INVARIANT VIOLATION: Zeroed delta root generated. State transitions must be cryptographically distinct.");
        }
    }

    /// Asserts that no two unique, finalized events share the same Sequence ID (Epoch/Timeline).
    /// This prevents split-brain and equivocation within a single node's view.
    ///
    /// # Panics
    /// Panics if `seq_a == seq_b`.
    pub fn assert_no_equivocation(seq_a: u64, seq_b: u64) {
        if seq_a == seq_b {
            panic!(
                "CRITICAL INVARIANT VIOLATION: Equivocation detected at sequence ID {}. \
                 Two divergent finalizing events share the same index.",
                seq_a
            );
        }
    }

    /// Asserts that replay windows strictly bound the historical horizon.
    ///
    /// # Panics
    /// Panics if the current replay length exceeds the maximum allowed deterministic boundary.
    pub fn assert_bounded_replay(current_length: usize, max_length: usize) {
        if current_length > max_length {
            panic!(
                "CRITICAL INVARIANT VIOLATION: Replay window length {} exceeds bounded maximum {}. \
                 This violates the state-space exhaustion assumptions.",
                current_length, max_length
            );
        }
    }
    /// Asserts that a finality state is strictly `IrreversibleFinality`.
    ///
    /// No system state derived from a FinalityCommitment may be considered
    /// immutable unless it is in the `IrreversibleFinality` state.
    ///
    /// # Panics
    /// Panics if the state is not `IrreversibleFinality`.
    pub fn assert_irreversible_finality(state: &FinalityState) {
        if state != &FinalityState::IrreversibleFinality {
            panic!(
                "CRITICAL INVARIANT VIOLATION: Attempted to assume immutability on a provisional state. \
                 Current state is {:?}, but IrreversibleFinality is required.",
                state
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::DigestAlgorithm;

    #[test]
    fn test_monotonic_time_valid() {
        SystemInvariants::assert_monotonic_time(100, 101); // should not panic
    }

    #[test]
    #[should_panic(expected = "Non-monotonic time sequence")]
    fn test_monotonic_time_invalid() {
        SystemInvariants::assert_monotonic_time(100, 100);
    }

    #[test]
    #[should_panic(expected = "Zeroed delta root generated")]
    fn test_zero_delta_root() {
        let zero_root = TypedDigest::new(DigestAlgorithm::Sha3_256, [0; 32]);
        SystemInvariants::assert_deterministic_delta_root(&zero_root);
    }

    #[test]
    #[should_panic(expected = "Equivocation detected")]
    fn test_equivocation_detected() {
        SystemInvariants::assert_no_equivocation(42, 42);
    }

    #[test]
    #[should_panic(expected = "Replay window length")]
    fn test_replay_window_exceeded() {
        SystemInvariants::assert_bounded_replay(1000, 500);
    }
    #[test]
    #[should_panic(expected = "Attempted to assume immutability on a provisional state")]
    fn test_irreversible_finality_panic() {
        SystemInvariants::assert_irreversible_finality(&FinalityState::StrongFinality);
    }

    #[test]
    fn test_irreversible_finality_success() {
        SystemInvariants::assert_irreversible_finality(&FinalityState::IrreversibleFinality);
    }
}
