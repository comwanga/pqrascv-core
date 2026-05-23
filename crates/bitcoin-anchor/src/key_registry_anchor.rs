use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Represents the registration state of a Verifier's identity key on the Bitcoin blockchain.
///
/// In Phase 3.4, a verifier's key must be explicitly bound to the Bitcoin anchor. To prevent
/// delays while waiting for Bitcoin block confirmations, a verifier can be in a `Provisional`
/// state, transitioning to `Anchored` once confirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifierRegistrationState {
    /// The key has been submitted for anchoring but lacks sufficient Bitcoin confirmations.
    /// The verifier may participate provisionally in the federation, but its votes might
    /// be weighted or treated differently depending on the federation's exact policy.
    Provisional {
        /// The transaction ID where the anchoring occurred.
        txid: [u8; 32],
        /// The epoch in which the provisional registration occurred.
        epoch_id: u64,
    },
    /// The key has reached the required threshold of Bitcoin confirmations and is fully
    /// trusted as part of the consensus quorum.
    Anchored,
    /// The key registration has been revoked.
    Revoked {
        /// The epoch when the revocation takes effect.
        revocation_epoch: u64,
    },
}

/// A structure representing a verifier's identity binding anchored on Bitcoin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchoredVerifierKey {
    /// The unique identifier of the verifier.
    pub verifier_id: String,
    /// The public key or its digest representing the verifier's identity.
    pub public_key: Vec<u8>,
    /// The registration state (e.g., Provisional, Anchored, Revoked).
    pub state: VerifierRegistrationState,
    /// The timestamp (physical or logical) when the key was last updated.
    pub timestamp: u64,
}

impl AnchoredVerifierKey {
    /// Creates a new provisional anchored key entry.
    pub fn new_provisional(
        verifier_id: String,
        public_key: Vec<u8>,
        txid: [u8; 32],
        epoch_id: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            verifier_id,
            public_key,
            state: VerifierRegistrationState::Provisional { txid, epoch_id },
            timestamp,
        }
    }

    /// Transitions the key state to Anchored.
    pub fn mark_anchored(&mut self) {
        self.state = VerifierRegistrationState::Anchored;
    }

    /// Revokes the key starting at a specific epoch.
    pub fn revoke(&mut self, revocation_epoch: u64) {
        self.state = VerifierRegistrationState::Revoked { revocation_epoch };
    }
}
