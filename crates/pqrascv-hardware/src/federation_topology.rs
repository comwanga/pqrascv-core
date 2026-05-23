//! Topology-Aware Federation Semantics
//!
//! Models hierarchical and scoped trust domains within a Byzantine federation.
//! Prevents flat authority assumptions by ensuring verifiers only possess
//! jurisdiction over their explicitly defined `authority_scope`.

use crate::trust_domains::TrustDomain;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Defines the structural role of a verifier within the federation topology.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FederationRole {
    /// Has global governance authority and can approve cross-zone transitions.
    RootAuthority,
    /// Has authority scoped to a specific geographic or logical zone.
    RegionalAuthority,
    /// Executes validation but has no governance or policy authority.
    EdgeVerifier,
    /// Passively mirrors state and provides auditability without voting power.
    Observer,
}

/// Explicitly bounds the authority of a verifier to specific operational domains.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityScope {
    /// The specific trust domains (e.g., `SecureBoot`, `RuntimeIntegrity`) this
    /// verifier is authorized to evaluate or govern.
    pub trust_domains: Vec<TrustDomain>,
    pub governance_allowed: bool,
    pub revocation_allowed: bool,
    pub attestation_allowed: bool,
}

/// A distinctly bounded region of trust within the larger federation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationZone {
    /// Unique identifier for this trust zone.
    pub zone_id: String,
    /// The identities of verifiers assigned to this zone.
    pub members: Vec<String>,
    /// Verifiers explicitly delegated authority over this zone.
    pub delegated_authorities: Vec<String>,
}

/// The comprehensive structural model of the verifier federation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationTopology {
    /// Unique identifier for the entire federation.
    pub federation_id: String,
    /// The collection of isolated trust zones within the federation.
    pub zones: Vec<FederationZone>,
    pub verifier_roles: Vec<(String, FederationRole)>,
}

impl AuthorityScope {
    /// Checks if the verifier has authority over a specific trust domain within a zone.
    #[must_use]
    pub fn has_authority(&self, domain: &TrustDomain, require_governance: bool) -> bool {
        if !self.trust_domains.contains(domain) {
            return false;
        }

        if require_governance && !self.governance_allowed {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_enforcement() {
        let edge_scope = AuthorityScope {
            trust_domains: vec![TrustDomain::RuntimeIntegrity],
            governance_allowed: false,
            revocation_allowed: false,
            attestation_allowed: true,
        };

        // Has authority for runtime
        assert!(edge_scope.has_authority(&TrustDomain::RuntimeIntegrity, false));

        // Fails on wrong domain
        assert!(!edge_scope.has_authority(&TrustDomain::HardwareIdentity, false));

        // Fails if governance required
        assert!(!edge_scope.has_authority(&TrustDomain::RuntimeIntegrity, true));

        let root_scope = AuthorityScope {
            trust_domains: vec![TrustDomain::RuntimeIntegrity, TrustDomain::HardwareIdentity],
            governance_allowed: true,
            revocation_allowed: true,
            attestation_allowed: true,
        };

        // Root can do governance
        assert!(root_scope.has_authority(&TrustDomain::HardwareIdentity, true));
    }
}
