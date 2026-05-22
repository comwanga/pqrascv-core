# TIMELINE_RECONCILIATION — Cross-Verifier Divergence Detection

## Overview

`timeline_reconciliation.rs` provides a stateless reconciler that compares two
`AttestationTimeline`s from different verifiers and produces a structured
`TimelineReconciliationReport`. Any detected divergence sets
`conflicts_detected = true`, triggering the fail-closed `RequireTimelineConsistency`
policy rule.

---

## Core Types

### `TimelineConflictType`

```rust
pub enum TimelineConflictType {
    MissingEvent   { event_sequence: u64 },
    ConflictingEvent { sequence: u64 },
    DivergentHistory { from_sequence: u64 },
}
```

| Type | Meaning |
|---|---|
| `MissingEvent` | A sequence number present in one timeline is absent from the other |
| `ConflictingEvent` | Same sequence number maps to different event hashes |
| `DivergentHistory` | Emitted as a diagnostic marker at the first conflict sequence |

### `TimelineConflict`

```rust
pub struct TimelineConflict {
    pub verifier_a:    String,
    pub verifier_b:    String,
    pub conflict_type: TimelineConflictType,
}
```

### `TimelineReconciliationReport`

```rust
pub struct TimelineReconciliationReport {
    pub reconciliation_id:  String,
    pub verifier_timelines: Vec<String>,
    pub conflicts_detected: bool,
    pub missing_events:     bool,
    pub conflict_details:   Vec<TimelineConflict>,
}
```

---

## Reconciliation Algorithm

`TimelineReconciler::reconcile(id, verifier_id_a, timeline_a, verifier_id_b, timeline_b) -> TimelineReconciliationReport`

1. Extract events from both timelines via `AttestationEvent::sequence_number()`.
2. Determine `max_seq = max(max_seq_a, max_seq_b)`. If both empty, return
   clean report.
3. For each sequence `0..=max_seq`:
   - **Both present, same hash** → no conflict.
   - **Both present, different hash** → `ConflictingEvent`.
   - **Present in A, absent in B** → `MissingEvent`, sets `missing_events`.
   - **Absent in A, present in B** → `MissingEvent`, sets `missing_events`.
   - **Both absent** → no conflict.
4. At the first conflict sequence, emit a `DivergentHistory` diagnostic.
5. `conflicts_detected = !conflict_details.is_empty()`.

**Determinism**: Pure function — same inputs always yield the same report.

---

## `AttestationEvent` Schema

Each event carries:

```rust
sequence_number: u64,       // monotonic per timeline
timestamp:       u64,       // Unix seconds
event_hash:      TypedDigest,  // SHA3-256 of event content
```

Reconciliation compares `event_hash.value` and `event_hash.algorithm` to
detect content divergence at the same sequence position.

---

## Policy Integration

`RequireTimelineConsistency` in `policy.rs`:
1. Retrieves `ctx.timeline_reconciliation`.
2. If absent → `HardwarePolicyError::TimelineConflictDetected`.
3. If `conflicts_detected || missing_events` → `HardwarePolicyError::TimelineConflictDetected`.

---

## Security Properties

- **Fail-closed**: any divergence (including missing events) → policy failure.
- **No ambiguous states**: `Inconclusive` is not a possible report outcome;
  ambiguity is treated as conflict.
- **Stateless**: reconciler holds no mutable state; concurrent calls are safe.
- **Sequence-granular**: detection is per-event, not just per-timeline, giving
  precise identification of when divergence began.

---

## Relationship to Other Modules

| Module | Relationship |
|---|---|
| `verifier_timeline.rs` | Provides `AttestationTimeline` and `AttestationEvent` |
| `verifier_transparency.rs` | Transparency events are inputs to timeline construction |
| `policy.rs` | `RequireTimelineConsistency` fails closed on `conflicts_detected` |
