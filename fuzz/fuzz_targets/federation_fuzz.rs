//! Fuzz target: Phase 2.9 federation infrastructure.
//!
//! Exercises:
//! - GovernanceRecord deserialization and structural validation
//! - VerifierFederation construction edge cases (empty, zero threshold, threshold > members)
//! - ConsensusEvaluation::evaluate with arbitrary vote counts and quorum policies
//! - TimelineReconciliationReport construction with arbitrary conflict sets
//! - FederatedPolicyEpoch::try_finalize edge cases (quorum, double-finalize)
//!
//! None of these should ever panic or exhibit UB.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqrascv_hardware::{
    digest::{DigestAlgorithm, TypedDigest},
    distributed_consensus::{ConsensusEvaluation, VerifierVote},
    governance::{GovernanceAction, GovernanceLog, GovernanceRecord},
    policy_federation::{FederatedPolicyEpoch, FederatedPolicyRegistry},
    timeline_reconciliation::TimelineReconciler,
    trust_domains::VerificationDecisionReason,
    verifier_federation::{FederationError, QuorumPolicy, VerifierFederation},
    verifier_identity::{VerifierCapability, VerifierIdentity},
    verifier_timeline::{AttestationEvent, AttestationTimeline},
};

/// Build a minimal `VerifierIdentity` from a seed byte.
fn make_identity(seed: u8) -> VerifierIdentity {
    VerifierIdentity {
        verifier_id: alloc::format!("v{seed}"),
        organization: "fuzz-org".into(),
        public_key: alloc::vec![seed; 32],
        capabilities: alloc::vec![VerifierCapability::HardwareVerification],
    }
}

/// Build a `VerifierFederation` with `n` members and the given `QuorumPolicy`.
fn make_federation(n: u8, policy: QuorumPolicy) -> Result<VerifierFederation, FederationError> {
    let members: alloc::vec::Vec<VerifierIdentity> = (0..n).map(make_identity).collect();
    let fed = VerifierFederation {
        federation_id: "fuzz-fed".into(),
        members,
        quorum_policy: policy,
    };
    fed.validate()?;
    Ok(fed)
}

extern crate alloc;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    let n_members = data[0].saturating_add(1).min(10); // 1..=10 members
    let threshold = data[1];
    let vote_count = data[2] as usize;
    let trusted_votes = data[3] as usize;
    let epoch_approvers = data[4] as usize;
    let nonce_byte = data[5];
    let hash_val_a = data[6];
    let hash_val_b = data[7];

    // ── 1. VerifierFederation construction ────────────────────────────────
    let quorum_policies = [
        QuorumPolicy::Majority,
        QuorumPolicy::SuperMajority,
        QuorumPolicy::Unanimous,
        QuorumPolicy::Threshold(threshold),
    ];
    for policy in quorum_policies {
        let _ = make_federation(n_members, policy);
    }

    // Work with a known-valid federation for downstream tests
    let Ok(fed) = make_federation(n_members.max(3), QuorumPolicy::Majority) else {
        return;
    };

    // ── 2. ConsensusEvaluation with arbitrary votes ────────────────────────
    let total_votes = vote_count.min(fed.member_count() * 2).min(20);
    let trusted_count = trusted_votes.min(total_votes);

    let mut votes: alloc::vec::Vec<VerifierVote> = (0..total_votes)
        .map(|i| VerifierVote {
            verifier_id: alloc::format!("v{}", i % fed.member_count()),
            trusted: i < trusted_count,
            reasons: alloc::vec![VerificationDecisionReason::Trusted],
            warnings: alloc::vec![],
        })
        .collect();

    let eval = ConsensusEvaluation::evaluate("fuzz-attest".into(), votes.clone(), &fed);
    // Must not panic; result is informational
    let _ = eval.final_decision.is_trusted();

    // ── 3. FederatedPolicyEpoch finalization ──────────────────────────────
    let quorum_needed = fed.quorum_required();
    let approver_count = epoch_approvers.min(20);

    let mut epoch = FederatedPolicyEpoch {
        epoch_id: 1,
        approved_by: (0..approver_count)
            .map(|i| alloc::format!("v{}", i % fed.member_count()))
            .collect(),
        quorum_reached: false,
        created_at: 1_000_000,
        previous_epoch: None,
    };

    // try_finalize should never panic
    let _ = epoch.try_finalize(&fed);

    // Double-finalize should return EpochAlreadyFinalized if first succeeded
    if epoch.quorum_reached {
        let _ = epoch.try_finalize(&fed);
    }

    // ── 4. FederatedPolicyRegistry monotonicity / split-brain ─────────────
    let mut registry = FederatedPolicyRegistry::new();
    let epoch_a = FederatedPolicyEpoch {
        epoch_id: 1,
        approved_by: alloc::vec!["v0".into()],
        quorum_reached: false,
        created_at: 1_000_000,
        previous_epoch: None,
    };
    let epoch_b = FederatedPolicyEpoch {
        epoch_id: 1, // Same id — should trigger split-brain
        approved_by: alloc::vec!["v1".into()],
        quorum_reached: false,
        created_at: 1_000_001,
        previous_epoch: None,
    };
    let epoch_c = FederatedPolicyEpoch {
        epoch_id: 0, // Non-monotonic
        approved_by: alloc::vec!["v0".into()],
        quorum_reached: false,
        created_at: 999_999,
        previous_epoch: None,
    };
    let _ = registry.propose(epoch_a, &fed);
    let _ = registry.propose(epoch_b, &fed); // split-brain
    let _ = registry.propose(epoch_c, &fed); // non-monotonic

    // ── 5. GovernanceRecord validation ────────────────────────────────────
    let nonce = {
        let mut n = [0u8; 32];
        n[0] = nonce_byte;
        n
    };
    let record = GovernanceRecord {
        action_id: "fuzz-action-1".into(),
        action: GovernanceAction::RemoveVerifier {
            verifier_id: "v0".into(),
        },
        authorized_by: "v1".into(),
        timestamp: 1_000_000,
        nonce,
        signature: alloc::vec![0xde, 0xad, 0xbe, 0xef],
        previous_action_hash: None,
    };

    let mut log = GovernanceLog::new();
    let _ = log.append(record.clone());

    // Replay attempt — should be rejected with ReplayDetected
    let _ = log.append(record);

    // Record with empty nonce — should be rejected
    let empty_nonce_record = GovernanceRecord {
        action_id: "fuzz-action-2".into(),
        action: GovernanceAction::RemoveVerifier {
            verifier_id: "v1".into(),
        },
        authorized_by: "v0".into(),
        timestamp: 1_000_001,
        nonce: [0u8; 32],
        signature: alloc::vec![0x01],
        previous_action_hash: None,
    };
    let _ = log.append(empty_nonce_record);

    // Record with empty signature — should be rejected
    let empty_sig_record = GovernanceRecord {
        action_id: "fuzz-action-3".into(),
        action: GovernanceAction::RemoveVerifier {
            verifier_id: "v2".into(),
        },
        authorized_by: "v0".into(),
        timestamp: 1_000_002,
        nonce: {
            let mut n = [0u8; 32];
            n[1] = nonce_byte.wrapping_add(1);
            n
        },
        signature: alloc::vec![],
        previous_action_hash: None,
    };
    let _ = log.append(empty_sig_record);

    // ── 6. Timeline reconciliation with arbitrary event sets ──────────────
    let make_event = |seq: u64, hash: u8| AttestationEvent::RuntimeMeasurementReceived {
        sequence_number: seq,
        timestamp: seq * 1000,
        event_hash: TypedDigest {
            algorithm: DigestAlgorithm::Sha3_256,
            value: [hash; 32],
        },
    };

    let mut tl_a = AttestationTimeline::new("device-a".into());
    let mut tl_b = AttestationTimeline::new("device-b".into());

    // Populate timelines from fuzz bytes
    if data.len() >= 16 {
        for i in 0..4usize {
            let seq = i as u64;
            tl_a.push(make_event(seq, data.get(8 + i).copied().unwrap_or(hash_val_a)));
            tl_b.push(make_event(seq, data.get(12 + i).copied().unwrap_or(hash_val_b)));
        }
    }

    // Must not panic regardless of conflict set
    let report = TimelineReconciler::reconcile(
        "fuzz-reconcile".into(),
        "va".into(),
        &tl_a,
        "vb".into(),
        &tl_b,
    );
    let _ = report.conflicts_detected;
    let _ = report.missing_events;
    let _ = report.conflict_details.len();
});
