//! Append-only audit lineage for deterministic reconstruction.
//!
//! This module provides the `AuditTrace` system which tracks state transitions,
//! consensus events, and policy evaluation results across all federation modules.
//! The trace forms a cryptographically linked append-only log that proves
//! the lineage of any given federation state.

use alloc::vec::Vec;
use crate::digest::{DigestAlgorithm, TypedDigest};
use sha3::{Digest, Sha3_256};

/// A cryptographically linked, append-only audit trace.
/// Provides proof of federation state lineage.
#[derive(Debug, Clone)]
pub struct AuditTrace {
    /// The starting state hash of the trace.
    pub genesis_root: TypedDigest,
    /// The rolling hash of all events applied so far.
    pub latest_root: TypedDigest,
    /// The append-only log of deterministic events.
    pub events: Vec<TraceEvent>,
    /// The strictly monotonic sequence ID.
    pub sequence: u64,
}

/// A deterministic state transition event recorded in the trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceEvent {
    PolicyEvaluated {
        evaluator: &'static str,
        result_hash: TypedDigest,
    },
    QuorumFormed {
        epoch: u64,
        quorum_hash: TypedDigest,
    },
    SnapshotSealed {
        snapshot_id: [u8; 32],
        snapshot_hash: TypedDigest,
        anchor_height: Option<u64>,
        confirmation_depth: Option<u64>,
        finality_state: alloc::string::String,
    },
    ReplayApplied {
        start_seq: u64,
        end_seq: u64,
        final_hash: TypedDigest,
    },
}

impl TraceEvent {
    /// Computes the deterministic hash of the event.
    #[must_use]
    pub fn compute_hash(&self) -> TypedDigest {
        let mut hasher = Sha3_256::new();
        match self {
            TraceEvent::PolicyEvaluated { evaluator, result_hash } => {
                hasher.update(b"PolicyEvaluated");
                hasher.update(evaluator.as_bytes());
                hasher.update(&result_hash.value);
            }
            TraceEvent::QuorumFormed { epoch, quorum_hash } => {
                hasher.update(b"QuorumFormed");
                hasher.update(epoch.to_be_bytes());
                hasher.update(&quorum_hash.value);
            }
            TraceEvent::SnapshotSealed { snapshot_id, snapshot_hash, anchor_height, confirmation_depth, finality_state } => {
                hasher.update(b"SnapshotSealed");
                hasher.update(snapshot_id);
                hasher.update(&snapshot_hash.value);
                if let Some(h) = anchor_height { hasher.update(h.to_be_bytes()); }
                if let Some(c) = confirmation_depth { hasher.update(c.to_be_bytes()); }
                hasher.update(finality_state.as_bytes());
            }
            TraceEvent::ReplayApplied { start_seq, end_seq, final_hash } => {
                hasher.update(b"ReplayApplied");
                hasher.update(start_seq.to_be_bytes());
                hasher.update(end_seq.to_be_bytes());
                hasher.update(&final_hash.value);
            }
        }
        let result: [u8; 32] = hasher.finalize().into();
        TypedDigest::new(DigestAlgorithm::Sha3_256, result)
    }
}

impl AuditTrace {
    /// Creates a new, empty audit trace starting from the given genesis root.
    #[must_use]
    pub fn new(genesis_root: TypedDigest) -> Self {
        Self {
            genesis_root: genesis_root.clone(),
            latest_root: genesis_root,
            events: Vec::new(),
            sequence: 0,
        }
    }

    /// Appends a new event to the trace, deterministically advancing the latest root.
    /// 
    /// The new root is: `SHA3-256(previous_root || event_hash)`
    pub fn append_event(&mut self, event: TraceEvent) {
        let event_hash = event.compute_hash();
        
        let mut hasher = Sha3_256::new();
        hasher.update(&self.latest_root.value);
        hasher.update(&event_hash.value);
        
        let next_root: [u8; 32] = hasher.finalize().into();
        
        self.latest_root = TypedDigest::new(DigestAlgorithm::Sha3_256, next_root);
        self.events.push(event);
        self.sequence = self.sequence.saturating_add(1);
    }
    
    /// Verifies the structural integrity and cryptographically recomputes the entire trace
    /// to ensure the `latest_root` matches the sequence of `events` applied to `genesis_root`.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let mut current_root = self.genesis_root.clone();
        
        for event in &self.events {
            let event_hash = event.compute_hash();
            let mut hasher = Sha3_256::new();
            hasher.update(&current_root.value);
            hasher.update(&event_hash.value);
            
            let next_root: [u8; 32] = hasher.finalize().into();
            current_root = TypedDigest::new(DigestAlgorithm::Sha3_256, next_root);
        }
        
        current_root == self.latest_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_trace_append_and_verify() {
        let genesis = TypedDigest::new(DigestAlgorithm::Sha3_256, [1; 32]);
        let mut trace = AuditTrace::new(genesis);

        trace.append_event(TraceEvent::PolicyEvaluated {
            evaluator: "HardwarePolicy",
            result_hash: TypedDigest::new(DigestAlgorithm::Sha3_256, [2; 32]),
        });

        trace.append_event(TraceEvent::QuorumFormed {
            epoch: 42,
            quorum_hash: TypedDigest::new(DigestAlgorithm::Sha3_256, [3; 32]),
        });

        assert_eq!(trace.events.len(), 2);
        assert_eq!(trace.sequence, 2);
        assert!(trace.verify_integrity());
    }

    #[test]
    fn test_audit_trace_tamper_detection() {
        let genesis = TypedDigest::new(DigestAlgorithm::Sha3_256, [1; 32]);
        let mut trace = AuditTrace::new(genesis);

        trace.append_event(TraceEvent::QuorumFormed {
            epoch: 42,
            quorum_hash: TypedDigest::new(DigestAlgorithm::Sha3_256, [3; 32]),
        });

        // Tamper with the events without updating the root
        trace.events[0] = TraceEvent::QuorumFormed {
            epoch: 99,
            quorum_hash: TypedDigest::new(DigestAlgorithm::Sha3_256, [3; 32]),
        };

        assert!(!trace.verify_integrity());
    }
}
