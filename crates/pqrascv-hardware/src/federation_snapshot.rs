use serde::{Deserialize, Serialize};

/// Represents a cryptographically auditable point-in-time state of the verifier federation.
///
/// Snapshots are NOT backups. They are cryptographic continuity checkpoints, governance
/// continuity proofs, and replay/recovery anchors. They provide an append-only lineage
/// of the federation's evolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationSnapshot {
    /// Unique identifier for this snapshot.
    pub snapshot_id: String,
    /// Identifier of the federation this snapshot applies to.
    pub federation_id: String,
    /// The governance epoch sequence number when this snapshot was created.
    pub governance_epoch: u64,
    /// Cryptographic hash representing the active federation topology (verifiers, quorum requirements).
    pub topology_hash: [u8; 32],
    /// Cryptographic hash of the current set of authorized verifier identities.
    pub verifier_set_hash: [u8; 32],
    /// Root hash of the rolling state checkpoint at this snapshot.
    pub checkpoint_root: [u8; 32],
    /// Root hash of the reconciled timeline history up to this snapshot.
    pub timeline_root: [u8; 32],
    /// Timestamp (typically HLC or physical) marking the creation of this recovery anchor.
    pub recovery_timestamp: u64,
    /// Cryptographic hash of the previous snapshot, enforcing an append-only lineage.
    pub previous_snapshot_hash: Option<[u8; 32]>,
    /// The canonical hash of this snapshot itself.
    pub snapshot_hash: [u8; 32],
}

impl FederationSnapshot {
    /// Computes the deterministic hash of the snapshot contents (excluding `snapshot_hash` itself).
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(self.snapshot_id.as_bytes());
        hasher.update(self.federation_id.as_bytes());
        hasher.update(self.governance_epoch.to_be_bytes());
        hasher.update(self.topology_hash);
        hasher.update(self.verifier_set_hash);
        hasher.update(self.checkpoint_root);
        hasher.update(self.timeline_root);
        hasher.update(self.recovery_timestamp.to_be_bytes());
        if let Some(prev) = &self.previous_snapshot_hash {
            hasher.update(prev);
        }
        let mut result = [0u8; 32];
        result.copy_from_slice(&hasher.finalize());
        result
    }

    /// Validates the internal consistency of the snapshot, ensuring the `snapshot_hash`
    /// correctly binds to its contents.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.compute_hash() == self.snapshot_hash
    }

    /// Verifies that this snapshot is a valid immediate successor to the provided `previous` snapshot.
    #[must_use]
    pub fn is_valid_successor(&self, previous: &FederationSnapshot) -> bool {
        if self.governance_epoch <= previous.governance_epoch {
            return false;
        }
        if let Some(expected_prev) = self.previous_snapshot_hash {
            if expected_prev != previous.snapshot_hash {
                return false;
            }
        } else {
            // A successor MUST link back to the previous hash.
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_hashing_and_validation() {
        let mut snapshot = FederationSnapshot {
            snapshot_id: "snap-01".into(),
            federation_id: "fed-main".into(),
            governance_epoch: 42,
            topology_hash: [1; 32],
            verifier_set_hash: [2; 32],
            checkpoint_root: [3; 32],
            timeline_root: [4; 32],
            recovery_timestamp: 1234567890,
            previous_snapshot_hash: None,
            snapshot_hash: [0; 32],
        };

        snapshot.snapshot_hash = snapshot.compute_hash();
        assert!(snapshot.is_valid());

        // Tamper with it
        snapshot.governance_epoch = 43;
        assert!(!snapshot.is_valid());
    }

    #[test]
    fn snapshot_lineage() {
        let mut snap1 = FederationSnapshot {
            snapshot_id: "snap-01".into(),
            federation_id: "fed-main".into(),
            governance_epoch: 1,
            topology_hash: [1; 32],
            verifier_set_hash: [2; 32],
            checkpoint_root: [3; 32],
            timeline_root: [4; 32],
            recovery_timestamp: 100,
            previous_snapshot_hash: None,
            snapshot_hash: [0; 32],
        };
        snap1.snapshot_hash = snap1.compute_hash();

        let mut snap2 = FederationSnapshot {
            snapshot_id: "snap-02".into(),
            federation_id: "fed-main".into(),
            governance_epoch: 2,
            topology_hash: [1; 32],
            verifier_set_hash: [2; 32],
            checkpoint_root: [5; 32],
            timeline_root: [6; 32],
            recovery_timestamp: 200,
            previous_snapshot_hash: Some(snap1.snapshot_hash),
            snapshot_hash: [0; 32],
        };
        snap2.snapshot_hash = snap2.compute_hash();

        assert!(snap2.is_valid_successor(&snap1));
    }
}
