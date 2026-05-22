//! Cross-Verifier Stream Reconciliation
//!
//! Provides deterministic detection of diverged integrity streams across the
//! verifier federation. Identifies sequence gaps, replay attacks, and
//! cryptographic hash conflicts when two verifiers compare their locally
//! observed state of the same node.

use alloc::vec::Vec;

/// A formal report generated when two verifiers compare their observed
/// runtime integrity streams for a specific node.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamReconciliationReport {
    /// Sequence numbers that one verifier has but the other is missing.
    /// Indicates a transport failure or an active eclipse attack on one verifier.
    pub missing_sequences: Vec<u64>,
    /// Sequence numbers where both verifiers received data, but their
    /// locally computed `rolling_hash` values differ. Indicates a severe
    /// synchronization failure or an active equivocation attack by the node.
    pub conflicting_sequences: Vec<u64>,
    /// True if identical sequences were presented but rejected as replays
    /// during the reconciliation handshake.
    pub replay_detected: bool,
}

impl StreamReconciliationReport {
    /// Returns true if the two streams are in perfect cryptographic agreement.
    #[must_use]
    pub fn is_synchronized(&self) -> bool {
        self.missing_sequences.is_empty()
            && self.conflicting_sequences.is_empty()
            && !self.replay_detected
    }

    /// Evaluates the severity of the reconciliation report.
    /// Conflicting sequences are always fatal, as they represent cryptographic
    /// equivocation. Missing sequences might just be latency.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.replay_detected {
            return Err("reconciliation failed: stream replay detected");
        }
        if !self.conflicting_sequences.is_empty() {
            return Err("reconciliation failed: stream integrity conflict detected (equivocation)");
        }
        // Missing sequences are reported but do not necessarily fail validation
        // as they trigger a missing-data fetch rather than an immediate abort.
        Ok(())
    }
}
