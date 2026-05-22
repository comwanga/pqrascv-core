//! Distributed Verifier Orchestrator
//!
//! Coordinates the end-to-end verification flow for a sovereign Bitcoin node,
//! including collecting evidence, distributing it to the federation, aggregating
//! consensus, and producing the final explainable report.

use crate::attested_node_report::{AttestedNodeReport, TransparencyStatus};
use crate::bitcoin_node_identity::BitcoinNodeIdentity;
use crate::distributed_consensus::ConsensusEvaluation;
use crate::trust_domains::TrustEvaluation;
use alloc::string::String;
use alloc::vec::Vec;

/// Orchestrates the distributed verification process for a node.
pub struct VerifierOrchestrator {
    /// The local verifier's identity.
    pub orchestrator_id: String,
    /// The ID of the federation this orchestrator belongs to.
    pub federation_id: String,
}

impl VerifierOrchestrator {
    /// Creates a new orchestrator instance.
    #[must_use]
    pub fn new(orchestrator_id: String, federation_id: String) -> Self {
        Self {
            orchestrator_id,
            federation_id,
        }
    }

    /// Orchestrates the final aggregation of an attestation report.
    ///
    /// In a real implementation, this would involve network I/O to collect
    /// votes from other verifiers and anchor to the transparency log.
    /// This method demonstrates the deterministic assembly of the final trust state.
    #[must_use]
    pub fn aggregate_report(
        &self,
        node_identity: BitcoinNodeIdentity,
        local_evaluations: Vec<TrustEvaluation>,
        consensus: ConsensusEvaluation,
        transparency_status: TransparencyStatus,
    ) -> AttestedNodeReport {
        // If consensus failed or local evaluation failed, it shouldn't be marked as anchored
        // unless it's explicitly pending. We default to the provided status for flexibility.
        let anchored = matches!(transparency_status, TransparencyStatus::Anchored);

        AttestedNodeReport {
            node_identity,
            trust_evaluations: local_evaluations,
            verifier_consensus: consensus,
            transparency_status,
            anchored,
        }
    }
}
