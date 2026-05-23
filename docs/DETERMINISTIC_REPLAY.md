# Deterministic Replay

This document details deterministic replay semantics for the PQ-RASCV federation.

## Replay Window
Replay state maintains a bounded rolling window of events (`ReplayWindow`) to prevent memory exhaustion and deterministic DoS surfaces. Older events are compacted into the `applied_event_root`.

See `crates/pqrascv-hardware/src/deterministic_replay.rs`.
