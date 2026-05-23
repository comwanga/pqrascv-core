# Phase 3.5: Infrastructure Resilience

This phase implements recovery, partition healing, and deterministic state reconstruction.

## 1. Federation Snapshots (`FEDERATION_SNAPSHOTS.md`)
Snapshots are cryptographic continuity checkpoints, NOT simple backups. They provide an append-only lineage of the federation's evolution.

## 2. Deterministic Replay (`DETERMINISTIC_REPLAY.md`)
Replay state maintains a bounded rolling window of events (`ReplayWindow`) to prevent memory exhaustion and deterministic DoS surfaces.

## 3. Partition Detection (`PARTITION_DETECTION.md`)
Divergent histories are exposed explicitly via `PartitionEvidence`. Immediate fork roots are tracked directly, and deeper history is referenced indirectly to maintain bounded memory.

## 4. Partition Healing (`PARTITION_HEALING.md`)
Healing requires explicit governance decisions (`PartitionHealingDecision`). Silent auto-merging is strictly forbidden.

## 5. Verifier Rejoin (`VERIFIER_REJOIN.md`)
Rejoin proofs validate current HLC synchronization, minimum retained checkpoint depth, and recovery lineage verification.

## 6. Quorum Reformation (`QUORUM_REFORMATION.md`)
Quorum reformation is a distinct, append-only governance event. It requires explicit cryptographic linkages to the previous quorum state.

## 7. Disaster Recovery (`DISASTER_RECOVERY.md`)
Checkpoints maintain an append-only chain, providing deterministic restoration boundaries that can be globally audited via Bitcoin.

## 8. Federation Migration (`FEDERATION_MIGRATION.md`)
Migration preserves governance continuity and verifier lineage while preventing ambiguous federation restructuring.

## 9. Recovery Governance (`RECOVERY_GOVERNANCE.md`)
All recovery actions are signed, append-only, and support Bitcoin anchoring.

## 10. Recovery Lineage (`RECOVERY_LINEAGE.md`)
Explicitly models recovery ancestry via `RecoveryLineage` struct to ensure deterministic historical reconstruction.

## 11. Bitcoin Anchoring (`BITCOIN_RECOVERY_ANCHORING.md`)
Anchors recovery events to Bitcoin to ensure global, immutable auditability of the disaster recovery lineage, quorum reformation, and sovereign migrations.
