//! Verifier Transparency Accountability Log
//!
//! All verifier actions that affect attestation outcomes MUST be recorded as
//! [`VerifierTransparencyEvent`]s in an append-only
//! [`VerifierTransparencyLog`]. No event may be removed or mutated after
//! appending.
//!
//! # Relationship to [`TransparencyEvent`]
//!
//! [`crate::transparency_log::TransparencyEvent`] records attestation-level
//! events. This module records **verifier-level** events — actions taken by
//! the verifier itself (accepting/rejecting attestations, participating in
//! quorum, executing governance).

use alloc::string::String;
use alloc::vec::Vec;

use crate::digest::TypedDigest;

// ── VerifierEventType ─────────────────────────────────────────────────────

/// The type of event recorded in a verifier's transparency log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VerifierEventType {
    /// The verifier accepted an attestation as trustworthy.
    AttestationVerified,
    /// The verifier rejected an attestation.
    AttestationRejected,
    /// The verifier detected a policy violation.
    PolicyViolation,
    /// The verifier participated in a quorum vote.
    QuorumParticipation,
    /// The verifier executed or recorded a governance action.
    GovernanceActionExecuted,
}

// ── VerifierTransparencyEvent ─────────────────────────────────────────────

/// A single, immutable transparency event from a verifier.
///
/// The `event_hash` is a [`TypedDigest`] over the event content, produced
/// by the caller and stored here for auditability.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifierTransparencyEvent {
    /// The verifier that produced this event.
    pub verifier_id: String,
    /// Typed digest of the event content (SHA3-256 recommended).
    pub event_hash: TypedDigest,
    /// Unix seconds when the event occurred.
    pub timestamp: u64,
    /// Classification of the event.
    pub event_type: VerifierEventType,
}

// ── VerifierTransparencyLog ───────────────────────────────────────────────

/// An append-only log of verifier transparency events.
///
/// Events are pushed in order and may never be removed or reordered.
/// The log is keyed to a single `verifier_id`.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct VerifierTransparencyLog {
    /// The verifier this log belongs to.
    pub verifier_id: String,
    events: Vec<VerifierTransparencyEvent>,
}

impl VerifierTransparencyLog {
    /// Creates an empty log for the given verifier.
    #[must_use]
    pub fn new(verifier_id: String) -> Self {
        Self {
            verifier_id,
            events: Vec::new(),
        }
    }

    /// Appends an event to the log.
    ///
    /// Returns an error if the event's `verifier_id` does not match this log's
    /// `verifier_id`, preventing cross-verifier event injection.
    pub fn append(&mut self, event: VerifierTransparencyEvent) -> Result<(), TransparencyLogError> {
        if event.verifier_id != self.verifier_id {
            return Err(TransparencyLogError::VerifierIdMismatch {
                expected: self.verifier_id.clone(),
                got: event.verifier_id,
            });
        }
        self.events.push(event);
        Ok(())
    }

    /// Returns the number of events in the log.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Returns a read-only slice of all events.
    #[must_use]
    pub fn events(&self) -> &[VerifierTransparencyEvent] {
        &self.events
    }

    /// Returns the latest event, if any.
    #[must_use]
    pub fn latest(&self) -> Option<&VerifierTransparencyEvent> {
        self.events.last()
    }
}

// ── TransparencyLogError ──────────────────────────────────────────────────

/// Errors from transparency log operations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TransparencyLogError {
    /// The event's `verifier_id` does not match the log's `verifier_id`.
    VerifierIdMismatch { expected: String, got: String },
}

impl core::fmt::Display for TransparencyLogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VerifierIdMismatch { expected, got } => write!(
                f,
                "verifier ID mismatch in transparency log: expected {expected}, got {got}"
            ),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::DigestAlgorithm;

    fn make_event(verifier_id: &str, ts: u64, event_type: VerifierEventType) -> VerifierTransparencyEvent {
        VerifierTransparencyEvent {
            verifier_id: verifier_id.into(),
            event_hash: TypedDigest {
                algorithm: DigestAlgorithm::Sha3_256,
                value: [0u8; 32],
            },
            timestamp: ts,
            event_type,
        }
    }

    #[test]
    fn append_and_count() {
        let mut log = VerifierTransparencyLog::new("v1".into());
        assert_eq!(log.event_count(), 0);

        log.append(make_event("v1", 100, VerifierEventType::AttestationVerified))
            .unwrap();
        log.append(make_event("v1", 200, VerifierEventType::QuorumParticipation))
            .unwrap();
        assert_eq!(log.event_count(), 2);
    }

    #[test]
    fn rejects_wrong_verifier_id() {
        let mut log = VerifierTransparencyLog::new("v1".into());
        let err = log
            .append(make_event("v2", 100, VerifierEventType::PolicyViolation))
            .unwrap_err();
        assert!(matches!(
            err,
            TransparencyLogError::VerifierIdMismatch { .. }
        ));
    }

    #[test]
    fn latest_returns_last_appended() {
        let mut log = VerifierTransparencyLog::new("v1".into());
        log.append(make_event("v1", 10, VerifierEventType::AttestationVerified))
            .unwrap();
        log.append(make_event("v1", 20, VerifierEventType::AttestationRejected))
            .unwrap();
        assert_eq!(log.latest().unwrap().timestamp, 20);
        assert_eq!(
            log.latest().unwrap().event_type,
            VerifierEventType::AttestationRejected
        );
    }
}
