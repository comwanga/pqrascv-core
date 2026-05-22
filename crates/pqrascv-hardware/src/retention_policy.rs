//! Bounded Verifier Retention Semantics
//!
//! Enforces strict bounds on the amount of historical integrity data a
//! verifier will retain. Ensures that continuous attestation streams do not
//! cause unbounded memory or storage growth over the lifecycle of a long-running node.
//!
//! # Federation-Level Agreement (Issue 5 Fix)
//!
//! A single verifier discarding data while others still reference it creates
//! federation divergence. `RetentionPolicy` now carries federation-level
//! parameters:
//!
//! - `federation_quorum_size`: the number of verifiers that must agree before
//!   data can be safely considered globally prunable.
//! - `global_replay_window_secs`: the minimum time window all federation
//!   verifiers must retain data before pruning is permitted. This prevents
//!   a single fast node from amnesically pruning data that slow peers still need.
//!
//! The `is_globally_safe_to_prune` method combines both local bounds and
//! global federation agreement windows before permitting compaction.

/// A deterministic policy defining exactly when and how historical integrity
/// evidence must be pruned into compacted timelines.
///
/// Combines local node bounds with federation-level agreement parameters
/// to prevent asymmetric amnesia across the verifier network.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RetentionPolicy {
    /// The maximum number of historical checkpoints to retain before pruning.
    pub max_checkpoints: usize,
    /// The maximum age (in seconds) of any retained sequence or checkpoint.
    pub max_stream_age_secs: u64,
    /// The absolute maximum number of un-checkpointed sequences to hold in memory.
    pub max_retained_sequences: usize,
    /// The number of federation verifiers that must participate for data to be
    /// considered globally synchronized (and therefore prunable).
    pub federation_quorum_size: usize,
    /// The minimum age (in seconds) data must have before global pruning is
    /// permitted. Ensures slow federation peers have time to synchronize.
    pub global_replay_window_secs: u64,
}

impl RetentionPolicy {
    /// Creates a strictly bounded retention policy with federation-level agreement.
    #[must_use]
    pub fn new(
        max_checkpoints: usize,
        max_stream_age_secs: u64,
        max_retained_sequences: usize,
        federation_quorum_size: usize,
        global_replay_window_secs: u64,
    ) -> Self {
        Self {
            max_checkpoints,
            max_stream_age_secs,
            max_retained_sequences,
            federation_quorum_size,
            global_replay_window_secs,
        }
    }

    /// Evaluates whether a stream is violating its local memory bounds,
    /// indicating that an immediate checkpoint and compaction cycle is required.
    ///
    /// This is a local-only check. Use `is_globally_safe_to_prune` before
    /// actually discarding data from the federation-visible history.
    #[must_use]
    pub fn requires_compaction(
        &self,
        current_checkpoints: usize,
        current_sequences: usize,
    ) -> bool {
        current_checkpoints > self.max_checkpoints
            || current_sequences > self.max_retained_sequences
    }

    /// Evaluates whether it is globally safe to prune a data item, combining
    /// both local bounds and the federation-level replay window.
    ///
    /// # Parameters
    ///
    /// - `item_age_secs`: how old (in seconds) the data item is.
    /// - `confirmed_sync_count`: how many federation verifiers have confirmed
    ///   they have seen and checkpointed this data.
    ///
    /// Returns `true` only if:
    /// 1. The item exceeds the local `max_stream_age_secs`, AND
    /// 2. The item exceeds the global `global_replay_window_secs`, AND
    /// 3. At least `federation_quorum_size` peers have confirmed synchronization.
    #[must_use]
    pub fn is_globally_safe_to_prune(
        &self,
        item_age_secs: u64,
        confirmed_sync_count: usize,
    ) -> bool {
        item_age_secs >= self.max_stream_age_secs
            && item_age_secs >= self.global_replay_window_secs
            && confirmed_sync_count >= self.federation_quorum_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RetentionPolicy {
        RetentionPolicy::new(
            10,   // max_checkpoints
            3600, // max_stream_age_secs (1 hour)
            1000, // max_retained_sequences
            3,    // federation_quorum_size
            7200, // global_replay_window_secs (2 hours)
        )
    }

    #[test]
    fn requires_compaction_on_checkpoint_overflow() {
        let p = policy();
        assert!(p.requires_compaction(11, 0));
        assert!(!p.requires_compaction(10, 0));
    }

    #[test]
    fn requires_compaction_on_sequence_overflow() {
        let p = policy();
        assert!(p.requires_compaction(0, 1001));
        assert!(!p.requires_compaction(0, 1000));
    }

    #[test]
    fn global_prune_requires_quorum_and_age() {
        let p = policy();
        // Not old enough locally
        assert!(!p.is_globally_safe_to_prune(1800, 3));
        // Old enough locally but not globally
        assert!(!p.is_globally_safe_to_prune(3600, 3));
        // Old enough but insufficient quorum
        assert!(!p.is_globally_safe_to_prune(7200, 2));
        // Meets all conditions
        assert!(p.is_globally_safe_to_prune(7200, 3));
        assert!(p.is_globally_safe_to_prune(9999, 5));
    }
}
