# Phase 3.6 Threat Model

## Synchronization Threats

### 1. Snapshot Amplification Attack
**Threat**: Attacker repeatedly requests massive replay chunks, exhausting verifier bandwidth and RAM.
**Mitigation**: `snapshot_sync.rs` requires bounded chunking and Merkle proofs. Invalid hashes terminate the sync stream immediately.

### 2. Eclipse Attack
**Threat**: Malicious nodes surround a verifier, providing a falsified topology.
**Mitigation**: `eclipse_resistance.rs` enforces topological spread. Verifiers fail-closed if minimum diverse routing paths drop below thresholds.

### 3. Federation Stagnation
**Threat**: An attacker blocks sync messages but continues to broadcast heartbeats, causing silent partition decay.
**Mitigation**: `federation_liveness.rs` evaluates quorum timeliness and fails liveness if state falls too far behind the global epoch.
