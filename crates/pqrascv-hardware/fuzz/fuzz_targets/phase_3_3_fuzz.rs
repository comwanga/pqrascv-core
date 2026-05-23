#![no_main]

use libfuzzer_sys::fuzz_target;
use pqrascv_hardware::equivocation::{EquivocationEvidence, SignedStateCommitment};
use pqrascv_hardware::verifier_revocation::{VerifierRevocation, RevocationReason};
use pqrascv_hardware::federation_topology::{AuthorityScope, FederationRole};
use pqrascv_hardware::trust_domains::TrustDomain;
use pqrascv_hardware::byzantine_quorum::{ByzantineQuorumResult, VoteSet};
use alloc::string::String;
use alloc::vec;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    // 1. Fuzz Equivocation Evidence construction
    let mut hash_a = [0u8; 32];
    let mut hash_b = [0u8; 32];
    hash_a.copy_from_slice(&data[0..32]);
    hash_b.copy_from_slice(&data[32..64]);

    let seq = u64::from_le_bytes([
        data.get(0).copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
        data.get(4).copied().unwrap_or(0),
        data.get(5).copied().unwrap_or(0),
        data.get(6).copied().unwrap_or(0),
        data.get(7).copied().unwrap_or(0),
    ]);

    let a = SignedStateCommitment {
        verifier_id: "v1".into(),
        sequence: seq,
        state_hash: hash_a,
        signature: vec![data[0]],
    };
    
    let b = SignedStateCommitment {
        verifier_id: "v1".into(),
        sequence: seq,
        state_hash: hash_b,
        signature: vec![data.get(1).copied().unwrap_or(0)],
    };

    let _ = EquivocationEvidence::try_from_commitments(a, b, 12345);

    // 2. Fuzz Revocation Evaluation
    let revocation = VerifierRevocation {
        verifier_id: "v2".into(),
        revocation_epoch: 1,
        effective_from_sequence: 100,
        revoked_by: vec![],
        reason: RevocationReason::ByzantineBehavior,
        timestamp: 0,
        signature: vec![],
    };

    let _ = revocation.is_revoked_at_sequence(seq);

    // 3. Fuzz Topology Authority Evaluation
    let scope = AuthorityScope {
        role: FederationRole::EdgeVerifier,
        allowed_domains: vec![TrustDomain::RuntimeIntegrity],
        allowed_zones: vec!["zone-a".into()],
    };

    let _ = scope.has_authority(&TrustDomain::HardwareIdentity, "zone-a");

    // 4. Fuzz Byzantine Quorum Evaluation
    // Use the arbitrary sequence to generate a pseudo-random number of total verifiers
    let total_verifiers = (seq % 100) as usize;
    let votes = vec![
        VoteSet {
            state_hash: hash_a,
            verifier_ids: vec!["v1".into(), "v2".into()],
        },
        VoteSet {
            state_hash: hash_b,
            verifier_ids: vec!["v3".into()],
        }
    ];

    let _ = ByzantineQuorumResult::evaluate(total_verifiers, &votes);
});
