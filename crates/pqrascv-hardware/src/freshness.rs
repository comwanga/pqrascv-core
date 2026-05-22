//! Evidence Freshness Semantics
//!
//! Provides time-bounding, monotonic sequencing, and expiration mechanisms
//! for live operational evidence, preventing replay attacks and stale
//! attestation ingestion.

#![cfg(feature = "live-evidence")]

/// The evaluated freshness state of a piece of collected evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FreshnessStatus {
    /// Evidence is well within the acceptable validity window.
    Fresh,
    /// Evidence is older than the preferred window but not yet expired.
    Stale,
    /// Evidence is completely outside the maximum validity window.
    Expired,
    /// The sequence number or timestamp is older than a previously seen state,
    /// indicating a potential replay attack or rollback.
    ReplaySuspected,
}

impl FreshnessStatus {
    /// Evaluates the freshness of a timestamped piece of evidence against
    /// a verifier's monotonic clock and defined validity limits.
    #[must_use]
    pub fn evaluate(
        evidence_timestamp: u64,
        verifier_now: u64,
        max_validity_secs: u64,
        stale_threshold_secs: u64,
        last_seen_timestamp: Option<u64>,
    ) -> Self {
        // Rollback / Replay Check
        if let Some(last_seen) = last_seen_timestamp {
            if evidence_timestamp <= last_seen {
                return Self::ReplaySuspected;
            }
        }

        // Future evidence is highly suspicious, treat as replay/drift
        if evidence_timestamp > verifier_now + 5 {
            return Self::ReplaySuspected;
        }

        let age = verifier_now.saturating_sub(evidence_timestamp);

        if age > max_validity_secs {
            Self::Expired
        } else if age > stale_threshold_secs {
            Self::Stale
        } else {
            Self::Fresh
        }
    }
}
