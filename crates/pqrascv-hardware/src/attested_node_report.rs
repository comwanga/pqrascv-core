//! Attested Node Report
//!
//! Provides the final, explainable verification report for a Bitcoin node.
//! This serves as the consolidated cryptographic proof of the node's trust state.

use crate::bitcoin_node_identity::BitcoinNodeIdentity;
use crate::distributed_consensus::ConsensusEvaluation;
use crate::trust_domains::TrustEvaluation;
use alloc::vec::Vec;

/// Indicates whether the node's attestation has been successfully anchored
/// to a transparency log and/or the Bitcoin blockchain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TransparencyStatus {
    /// The report has not been anchored.
    NotAnchored,
    /// The report is pending inclusion in a log/chain.
    PendingInclusion,
    /// The report is fully anchored and verifiable.
    Anchored,
}

/// The comprehensive, explainable attestation report for a Bitcoin node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttestedNodeReport {
    /// The verified identity of the Bitcoin node.
    pub node_identity: BitcoinNodeIdentity,
    /// The explicit results of evaluating the node across all trust domains.
    pub trust_evaluations: Vec<TrustEvaluation>,
    /// The result of the distributed verifier quorum evaluating this node.
    pub verifier_consensus: ConsensusEvaluation,
    /// The transparency anchoring status of this specific report.
    pub transparency_status: TransparencyStatus,
    /// True if the report is finalized and anchored (convenience boolean).
    pub anchored: bool,
}

impl AttestedNodeReport {
    /// Determines if the node is considered fully trusted overall.
    ///
    /// A node is fully trusted only if:
    /// 1. Every individual trust domain evaluation is trusted.
    /// 2. The verifier consensus reached a `Trusted` decision.
    #[must_use]
    pub fn is_fully_trusted(&self) -> bool {
        let all_domains_trusted = self.trust_evaluations.iter().all(|eval| eval.trusted);
        let consensus_trusted = matches!(
            self.verifier_consensus.final_decision,
            crate::distributed_consensus::ConsensusDecision::Trusted
        );
        all_domains_trusted && consensus_trusted
    }
}
