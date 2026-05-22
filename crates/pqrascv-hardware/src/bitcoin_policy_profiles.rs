//! Deterministic Bitcoin Node Policy Profiles
//!
//! Provides pre-defined policy presets tailored to specific operational
//! roles of sovereign Bitcoin nodes.

use crate::policy::HardwarePolicyEngine;
use crate::policy::HardwarePolicyRule;

/// Defines a node's operational role and corresponding security posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BitcoinNodeProfile {
    /// Full, standalone, sovereign mainnet node.
    SovereignMainnetNode,
    /// A node participating in a federated verification quorum.
    FederationVerifierNode,
    /// An offline or deeply isolated node for auditing/archival.
    AirgappedAuditNode,
    /// A node dedicated to monitoring the chainstate and mempool (e.g. LN watchtower).
    WatchtowerNode,
    /// A constrained node running on embedded hardware or IoT devices.
    MinimalEmbeddedNode,
}

impl BitcoinNodeProfile {
    /// Returns the base hardware policy rules for this profile.
    #[must_use]
    pub fn policy_engine(&self) -> HardwarePolicyEngine {
        let mut rules = alloc::vec![
            HardwarePolicyRule::RequireHardwareRootedBackend,
            HardwarePolicyRule::RequireMeasuredBoot,
            HardwarePolicyRule::RequireNormalizedPcrs,
            HardwarePolicyRule::RequireHardwareMonotonicCounter,
            HardwarePolicyRule::RequireNonceBinding,
            HardwarePolicyRule::RequireBitcoinNodeIdentity,
            HardwarePolicyRule::RequireBitcoinWorkloadIntegrity,
            HardwarePolicyRule::RequireNodeRuntimeContinuity,
        ];

        match self {
            Self::SovereignMainnetNode => {
                rules.push(HardwarePolicyRule::RequireSecureBootState(crate::secure_boot::SecureBootState::Enabled));
            }
            Self::FederationVerifierNode => {
                rules.push(HardwarePolicyRule::RequireSecureBootState(crate::secure_boot::SecureBootState::Enabled));
                rules.push(HardwarePolicyRule::RequireVerifierFederation);
                rules.push(HardwarePolicyRule::RequireFederatedNodeVerification);
                rules.push(HardwarePolicyRule::RequireNodeTransparencyAnchoring);
            }
            Self::AirgappedAuditNode => {
                rules.push(HardwarePolicyRule::RequireSecureBootState(crate::secure_boot::SecureBootState::Enabled));
            }
            Self::WatchtowerNode => {
                // Watchtowers may not enforce strict hardware binding if running in cloud,
                // but we assume hardware isolation here for maximal security.
            }
            Self::MinimalEmbeddedNode => {
                // Embedded nodes might lack advanced hardware features, but they still
                // verify workload integrity.
            }
        }

        rules.push(HardwarePolicyRule::RequireDeterministicNodePolicy);
        HardwarePolicyEngine::new(rules)
    }
}
