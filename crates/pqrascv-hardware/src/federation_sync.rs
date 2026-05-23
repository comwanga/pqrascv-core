//! Signed Federation Synchronization
//!
//! Handles deterministic state synchronization within a federation.
//! Conflicting sync states must be immediately visible to preserve safety.

use crate::byzantine_quorum::QuorumCertificate;
use alloc::string::String;
use serde::{Deserialize, Serialize};

/// A compact summary of a federation's active trust state for synchronization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationSyncState {
    /// The identity of the federation.
    pub federation_id: String,
    /// The canonical hash of the current active trust state.
    pub latest_state_hash: [u8; 32],
    /// The active policy governance epoch.
    pub latest_policy_epoch: u64,
    /// The latest revocation epoch applied to the state.
    pub latest_revocation_epoch: u64,
}

/// A verifiable proof of synchronization, backed by a quorum certificate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationSyncProof {
    /// The canonical hash of the `FederationSyncState`.
    pub sync_hash: [u8; 32],
    /// The quorum certificate proving federation consensus on this state.
    pub quorum_certificate: QuorumCertificate,
}

impl FederationSyncState {
    /// Computes the deterministic hash of the synchronization state.
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(self.federation_id.as_bytes());
        hasher.update(self.latest_state_hash);
        hasher.update(self.latest_policy_epoch.to_be_bytes());
        hasher.update(self.latest_revocation_epoch.to_be_bytes());
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_state_hash_determinism() {
        let state1 = FederationSyncState {
            federation_id: "fed-A".into(),
            latest_state_hash: [0xAA; 32],
            latest_policy_epoch: 1,
            latest_revocation_epoch: 2,
        };

        let state2 = FederationSyncState {
            federation_id: "fed-A".into(),
            latest_state_hash: [0xAA; 32],
            latest_policy_epoch: 1,
            latest_revocation_epoch: 2,
        };

        assert_eq!(state1.compute_hash(), state2.compute_hash());

        let state3 = FederationSyncState {
            federation_id: "fed-A".into(),
            latest_state_hash: [0xBB; 32], // Changed
            latest_policy_epoch: 1,
            latest_revocation_epoch: 2,
        };

        assert_ne!(state1.compute_hash(), state3.compute_hash());
    }
}
