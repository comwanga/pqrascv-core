//! Governed Retention Semantics
//!
//! Upgrades stream timeline retention from local node configuration to a formally
//! governed and signed federation policy. Ensures deterministic retention transitions
//! and rejects retention epoch rollbacks.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A federation-approved policy defining timeline compaction and retention bounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRetentionPolicy {
    /// The monotonic governance epoch during which this policy was enacted.
    pub policy_epoch: u64,
    /// The maximum allowable age of the active stream before mandatory compaction.
    pub max_stream_age_secs: u64,
    /// The maximum number of compacted checkpoints to retain in active memory
    /// before archival or pruning.
    pub max_checkpoints: usize,
    /// The verifiers/authorities that approved this retention policy.
    pub approved_by: Vec<String>,
    /// The aggregate quorum signature authorizing the policy.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl SignedRetentionPolicy {
    /// Validates an incoming policy update against the currently active policy.
    ///
    /// # Errors
    /// Returns an error if the new policy attempts to revert to an older or
    /// identical epoch, enforcing strict monotonicity.
    pub fn validate_transition(
        &self,
        current_policy: &SignedRetentionPolicy,
    ) -> Result<(), &'static str> {
        if self.policy_epoch <= current_policy.policy_epoch {
            return Err("retention policy rollback detected: new epoch must be strictly greater");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_policy_transition() {
        let current = SignedRetentionPolicy {
            policy_epoch: 5,
            max_stream_age_secs: 3600,
            max_checkpoints: 10,
            approved_by: vec![],
            signature: vec![],
        };

        let new_policy = SignedRetentionPolicy {
            policy_epoch: 6,
            max_stream_age_secs: 7200,
            max_checkpoints: 20,
            approved_by: vec![],
            signature: vec![],
        };

        assert!(new_policy.validate_transition(&current).is_ok());
    }

    #[test]
    fn invalid_policy_rollback() {
        let current = SignedRetentionPolicy {
            policy_epoch: 5,
            max_stream_age_secs: 3600,
            max_checkpoints: 10,
            approved_by: vec![],
            signature: vec![],
        };

        let rollback_policy = SignedRetentionPolicy {
            policy_epoch: 4, // Rollback!
            max_stream_age_secs: 3600,
            max_checkpoints: 10,
            approved_by: vec![],
            signature: vec![],
        };

        assert!(rollback_policy.validate_transition(&current).is_err());
    }

    #[test]
    fn invalid_policy_same_epoch() {
        let current = SignedRetentionPolicy {
            policy_epoch: 5,
            max_stream_age_secs: 3600,
            max_checkpoints: 10,
            approved_by: vec![],
            signature: vec![],
        };

        let updated_policy = SignedRetentionPolicy {
            policy_epoch: 5, // Same epoch, not monotonic!
            max_stream_age_secs: 7200,
            max_checkpoints: 10,
            approved_by: vec![],
            signature: vec![],
        };

        assert!(updated_policy.validate_transition(&current).is_err());
    }
}
