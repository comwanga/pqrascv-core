//! Sovereign Deployment Reference Modeling
//!
//! Provides the operational topologies and deployment modes for
//! attested Bitcoin nodes.

/// Represents the high-level deployment topology of the node and its verifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeploymentMode {
    /// A single node acting as its own primary sovereign verifier, potentially with an
    /// offline hardware wallet or policy engine for ultimate control.
    SovereignSingleNode,
    /// A node verified continuously by a distributed quorum of verifiers.
    FederatedCluster,
    /// An air-gapped node where attestation evidence is manually exported and
    /// verified on a completely isolated machine.
    AirgappedAudit,
    /// A mesh of peer verifiers that cross-verify each other's Bitcoin nodes.
    HybridVerifierMesh,
}
