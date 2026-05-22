//! Node Attestation Session Lifecycle
//!
//! Manages the lifecycle of continuous attestation for a sovereign Bitcoin node,
//! preventing replay attacks and ensuring monotonicity.

use crate::bitcoin_node_identity::BitcoinNodeIdentity;
use alloc::string::String;

/// Represents an active, time-bounded attestation session for a Bitcoin node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeAttestationSession {
    /// Unique identifier for this attestation session.
    pub session_id: String,
    /// The identity of the Bitcoin node bound to this session.
    pub node_identity: BitcoinNodeIdentity,
    /// The ID of the verifier federation evaluating this session.
    pub verifier_federation: String,
    /// Timestamp (Unix seconds) when this session was established.
    pub started_at: u64,
    /// Timestamp (Unix seconds) of the last successful verification in this session.
    pub last_verified: u64,
    /// Indicates whether the session is currently active and valid.
    pub active: bool,
}

impl NodeAttestationSession {
    /// Creates a new `NodeAttestationSession`.
    #[must_use]
    pub fn new(
        session_id: String,
        node_identity: BitcoinNodeIdentity,
        verifier_federation: String,
        started_at: u64,
    ) -> Self {
        Self {
            session_id,
            node_identity,
            verifier_federation,
            started_at,
            last_verified: started_at,
            active: true,
        }
    }

    /// Renews the session by updating the last_verified timestamp.
    ///
    /// The new timestamp must be strictly greater than the previous to ensure monotonicity.
    pub fn renew(&mut self, now_secs: u64) -> Result<(), &'static str> {
        if !self.active {
            return Err("Cannot renew an inactive session");
        }
        if now_secs <= self.last_verified {
            return Err("Renewal timestamp must be strictly monotonic");
        }
        self.last_verified = now_secs;
        Ok(())
    }

    /// Terminates the attestation session.
    pub fn terminate(&mut self) {
        self.active = false;
    }
}
