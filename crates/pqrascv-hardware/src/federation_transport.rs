//! Verifier Federation Synchronization Messaging
//!
//! Provides the strict, replay-resistant messaging formats used for
//! cross-verifier synchronization within the federation. Relies on ML-DSA
//! for envelope signatures and explicit sequence windows to mitigate
//! message reordering, latency, or adversarial replay.

use crate::pq_transport::TransportEpoch;
use alloc::string::String;
use alloc::vec::Vec;

/// The specific actions a verifier can broadcast to the federation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FederationMessage {
    ConsensusVote,
    PolicyEpochUpdate,
    TransparencyEvent,
    TimelineCheckpoint,
    GovernanceEvent,
    EpochTransition(TransportEpoch),
}

/// A strictly authenticated, strictly sequenced envelope for federation messages.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedFederationEnvelope {
    pub message_id: String,
    pub sender: String,
    pub sequence: u64,
    pub payload: FederationMessage,
    /// ML-DSA signature over the CBOR-encoded payload, sequence, and sender.
    pub signature: Vec<u8>,
}

/// Explicitly tracks sequence progression for incoming messages from a specific
/// remote verifier, mitigating replay attacks while tolerating bounded
/// federation latency (network jitter).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayWindow {
    pub highest_seen: u64,
    pub accepted_gap: u64,
}

impl ReplayWindow {
    /// Initializes a new replay window with a specified tolerance for gaps.
    #[must_use]
    pub fn new(accepted_gap: u64) -> Self {
        Self {
            highest_seen: 0,
            accepted_gap,
        }
    }

    /// Evaluates an incoming message sequence.
    /// Fails closed if the sequence is a strict replay or if it exceeds the
    /// maximum permitted discontinuity gap.
    pub fn evaluate_sequence(&mut self, sequence: u64) -> Result<(), &'static str> {
        if sequence <= self.highest_seen {
            return Err("message sequence replay detected");
        }

        if sequence - self.highest_seen > self.accepted_gap {
            // Note: Unlike TCP, we don't automatically resync. A gap too large
            // means we missed critical federation state and must trigger
            // a formal reconciliation stream.
            return Err("message sequence gap exceeds accepted tolerance");
        }

        self.highest_seen = sequence;
        Ok(())
    }
}
