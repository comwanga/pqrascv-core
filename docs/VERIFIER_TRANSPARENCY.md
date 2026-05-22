# VERIFIER_TRANSPARENCY — Append-Only Accountability Log

## Overview

Every verifier action that affects an attestation outcome MUST be recorded as
an immutable `VerifierTransparencyEvent` in a `VerifierTransparencyLog`. The
log is append-only: events may never be removed, reordered, or mutated after
insertion.

---

## Core Types

### `VerifierEventType`

```rust
pub enum VerifierEventType {
    AttestationVerified,
    AttestationRejected,
    PolicyViolation,
    QuorumParticipation,
    GovernanceActionExecuted,
}
```

### `VerifierTransparencyEvent`

```rust
pub struct VerifierTransparencyEvent {
    pub verifier_id:  String,
    pub event_hash:   TypedDigest,   // SHA3-256 of event content
    pub timestamp:    u64,           // Unix seconds
    pub event_type:   VerifierEventType,
}
```

The `event_hash` is produced by the caller over the serialized event content.
This crate stores it but does not recompute it, keeping the module transport-
agnostic.

### `VerifierTransparencyLog`

```rust
pub struct VerifierTransparencyLog {
    pub verifier_id: String,
    events: Vec<VerifierTransparencyEvent>,  // private: no direct mutation
}
```

The `events` field is private. Access is only via `append`, `events()`, and
`latest()`.

---

## Append Protocol

`VerifierTransparencyLog::append(event) -> Result<(), TransparencyLogError>`:

1. Verifies `event.verifier_id == self.verifier_id`.
   - Mismatch → `TransparencyLogError::VerifierIdMismatch { expected, got }`.
2. Pushes to the internal `Vec`. No removal method exists.

The `verifier_id` check prevents cross-verifier event injection — a verifier
cannot log events on behalf of another verifier.

---

## Read Methods

| Method | Returns |
|---|---|
| `events() -> &[VerifierTransparencyEvent]` | Read-only slice |
| `event_count() -> usize` | Length of log |
| `latest() -> Option<&VerifierTransparencyEvent>` | Most-recent event |

---

## Policy Integration

The `RequireTransparencyConsensus` rule checks that no timeline conflicts exist
in `ctx.timeline_reconciliation`. Verifier transparency logs are the primary
input for reconciliation: discrepancies between what verifiers claim they did
(transparency log) and what reconciliation detects (timeline) indicate tampering.

---

## Distinction from `TransparencyEvent`

| Type | Module | What it records |
|---|---|---|
| `TransparencyEvent` | `transparency_log.rs` | Attestation-level events (device outcomes) |
| `VerifierTransparencyEvent` | `verifier_transparency.rs` | Verifier-level actions (verifier decisions) |

---

## Security Properties

- **Append-only**: No delete or update API.
- **Identity-locked**: Events can only be appended by the owning verifier.
- **Tamper evidence**: `event_hash` (SHA3-256) provides content integrity;
  if the hash doesn't match the serialized event, tampering is detectable.
- **Bitcoin anchoring**: Verifier transparency event batches can be included in
  `FederationBatchAggregator` for permanent Bitcoin-layer proof of existence.
