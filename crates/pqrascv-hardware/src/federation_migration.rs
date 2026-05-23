use serde::{Deserialize, Serialize};

/// Represents the sovereign migration of a federation from one topology/identity to another.
///
/// Migration explicitly preserves governance continuity and verifier lineage while
/// preventing ambiguous or hidden federation restructuring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationMigration {
    /// The original federation identifier.
    pub source_federation_id: String,
    /// The new federation identifier.
    pub target_federation_id: String,
    /// The governance epoch in which the migration is enacted.
    pub migration_epoch: u64,
    /// Cryptographic root binding the old state to the new state.
    pub migration_root: [u8; 32],
}

impl FederationMigration {
    /// Validates the structural integrity of the migration intent.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        // Source and target must be distinct
        if self.source_federation_id == self.target_federation_id {
            return false;
        }

        if self.source_federation_id.is_empty() || self.target_federation_id.is_empty() {
            return false;
        }

        // Must have a valid root binding
        if self.migration_root == [0; 32] {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_migration() {
        let mig = FederationMigration {
            source_federation_id: "fed-v1".into(),
            target_federation_id: "fed-v2".into(),
            migration_epoch: 100,
            migration_root: [1; 32],
        };
        assert!(mig.is_valid());
    }

    #[test]
    fn invalid_migration_same_id() {
        let mig = FederationMigration {
            source_federation_id: "fed-v1".into(),
            target_federation_id: "fed-v1".into(),
            migration_epoch: 100,
            migration_root: [1; 32],
        };
        assert!(!mig.is_valid());
    }

    #[test]
    fn invalid_migration_zero_root() {
        let mig = FederationMigration {
            source_federation_id: "fed-v1".into(),
            target_federation_id: "fed-v2".into(),
            migration_epoch: 100,
            migration_root: [0; 32],
        };
        assert!(!mig.is_valid());
    }
}
