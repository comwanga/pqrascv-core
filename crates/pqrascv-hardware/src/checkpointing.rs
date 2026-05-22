//! Rolling Integrity Checkpoints
//!
//! Provides boundary markers for continuous runtime integrity streams.
//! Checkpoints allow verifiers to safely prune historical deltas while
//! maintaining a cryptographic lineage (the `integrity_root`) that anchors
//! all subsequent attestations.

use crate::digest::TypedDigest;
use alloc::string::String;

/// A bounded slice of runtime integrity history summarized into a single anchor.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntegrityCheckpoint {
    /// Unique identifier for this checkpoint.
    pub checkpoint_id: String,
    /// The sequence number where this checkpoint begins.
    pub start_sequence: u64,
    /// The sequence number where this checkpoint ends.
    pub end_sequence: u64,
    /// The canonical rolling hash representing the terminal state of `end_sequence`.
    pub integrity_root: TypedDigest,
    /// The Unix timestamp when this checkpoint was generated.
    pub timestamp: u64,
}

impl IntegrityCheckpoint {
    /// Validates that a proposed child checkpoint logically follows this checkpoint.
    pub fn verify_linkage(&self, child: &IntegrityCheckpoint) -> Result<(), &'static str> {
        if child.start_sequence != self.end_sequence + 1 {
            return Err("checkpoint sequence continuity broken");
        }
        if child.timestamp < self.timestamp {
            return Err("checkpoint timestamps must be monotonic");
        }
        Ok(())
    }

    /// Safely evaluates whether this checkpoint is eligible for pruning based
    /// on a strict verifier retention policy limit.
    #[must_use]
    pub fn is_prunable(
        &self,
        oldest_retained_sequence: u64,
        current_timestamp: u64,
        max_age_secs: u64,
    ) -> bool {
        // Must be older than the retained sequence boundary
        if self.end_sequence >= oldest_retained_sequence {
            return false;
        }

        // Must exceed the maximum permitted age
        if current_timestamp.saturating_sub(self.timestamp) < max_age_secs {
            return false;
        }

        true
    }
}
