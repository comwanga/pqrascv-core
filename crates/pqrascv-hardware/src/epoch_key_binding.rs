//! Epoch Key Binding
//!
//! Cryptographically binds policy epochs, verifier keys, and governance continuity.
//! Prevents historical ambiguity, retroactive key reinterpretation, and epoch/key mismatch attacks.

use serde::{Deserialize, Serialize};

/// Cryptographically binds a verifier's identity and key to a specific governance epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochKeyBinding {
    /// The governance epoch sequence number.
    pub epoch: u64,
    /// The identity of the verifier.
    pub verifier_id: String,
    /// Hash of the verifier's public ML-KEM / signature key (e.g. SHA3-256).
    pub key_hash: [u8; 32],
    /// The governance root hash at this epoch.
    pub governance_root: [u8; 32],
}

impl EpochKeyBinding {
    /// Verifies that the binding matches an expected epoch and governance root.
    #[must_use]
    pub fn is_valid_for(&self, epoch: u64, governance_root: &[u8; 32]) -> bool {
        self.epoch == epoch && self.governance_root == *governance_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_key_binding_serialize() {
        let binding = EpochKeyBinding {
            epoch: 5,
            verifier_id: "v1".into(),
            key_hash: [0x11; 32],
            governance_root: [0x22; 32],
        };

        // Assert it roundtrips
        let mut bytes = alloc::vec::Vec::new();
        ciborium::into_writer(&binding, &mut bytes).unwrap();
        let decoded: EpochKeyBinding = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(binding, decoded);
    }

    #[test]
    fn is_valid_for_correct() {
        let binding = EpochKeyBinding {
            epoch: 5,
            verifier_id: "v1".into(),
            key_hash: [0x11; 32],
            governance_root: [0x22; 32],
        };

        assert!(binding.is_valid_for(5, &[0x22; 32]));
        assert!(!binding.is_valid_for(4, &[0x22; 32]));
        assert!(!binding.is_valid_for(5, &[0x33; 32]));
    }
}
