#[cfg(test)]
mod tests {
    use crate::audit_trace::{AuditTrace, TraceEvent};
    use crate::digest::{DigestAlgorithm, TypedDigest};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn deterministic_trace_generation(
            seed in any::<[u8; 32]>(),
            event1_seed in any::<[u8; 32]>(),
            event2_seed in any::<[u8; 32]>()
        ) {
            let genesis = TypedDigest::new(DigestAlgorithm::Sha3_256, seed);

            let mut trace_a = AuditTrace::new(genesis);
            let mut trace_b = AuditTrace::new(genesis);

            let ev1 = TraceEvent::QuorumFormed {
                epoch: 1,
                quorum_hash: TypedDigest::new(DigestAlgorithm::Sha3_256, event1_seed)
            };

            let ev2 = TraceEvent::SnapshotSealed {
                snapshot_id: event2_seed,
                snapshot_hash: TypedDigest::new(DigestAlgorithm::Sha3_256, event2_seed),
                anchor_height: Some(100),
                confirmation_depth: Some(6),
                finality_state: alloc::string::String::from("IrreversibleFinality"),
            };

            trace_a.append_event(ev1.clone());
            trace_a.append_event(ev2.clone());

            trace_b.append_event(ev1);
            trace_b.append_event(ev2);

            // Roots must match exactly given identical inputs
            prop_assert_eq!(&trace_a.latest_root, &trace_b.latest_root);

            // The audit trace must structurally verify
            prop_assert!(trace_a.verify_integrity());
        }
    }
}
