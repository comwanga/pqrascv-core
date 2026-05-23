#![no_main]

use libfuzzer_sys::fuzz_target;
use pqrascv_hardware::{
    adaptive_sync::{AdaptiveSyncEngine, SyncBackoffState},
    eclipse_resistance::{FederationConnectivityReport, PeerDiversityConstraints, SynchronizationSpread},
    gossip_protocol::GossipDeduplication,
    peer_reputation::{PeerOperationalScore, PeerPenalty},
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut dedup = GossipDeduplication::new(10);
    if data.len() >= 32 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[0..32]);
        let _ = dedup.is_duplicate_or_record(hash);
    }

    let mut score = PeerOperationalScore::new("fuzz_peer".into());
    if data[0] % 5 == 0 {
        score.apply_penalty(&PeerPenalty::MalformedMessage);
    } else if data[0] % 5 == 1 {
        score.apply_penalty(&PeerPenalty::ReplayAttempt);
    } else if data[0] % 5 == 2 {
        score.apply_penalty(&PeerPenalty::SyncFailure);
    } else if data[0] % 5 == 3 {
        score.apply_penalty(&PeerPenalty::ExcessiveSkew);
    } else {
        score.apply_penalty(&PeerPenalty::Flooding);
    }

    // 3. Fuzz Adaptive Sync Engine
    let mut engine = AdaptiveSyncEngine::new();
    let backoff = engine.get_or_create_backoff("fuzz_peer");
    backoff.record_failure(data[0] as u64);
    let _ = engine.evaluate_health();

    let spread = SynchronizationSpread {
        active_regions: alloc::collections::BTreeSet::new(),
        unique_peer_sources: data[0] as usize,
    };
    let constraints = PeerDiversityConstraints {
        min_active_peers: 5,
        min_regional_spread: 3,
    };
    let _ = FederationConnectivityReport::evaluate(
        data.len(),
        data.len() / 2,
        spread,
        &constraints,
    );
});
