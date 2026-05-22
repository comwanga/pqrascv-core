# REPUTATION_AUDIT — Informational-Only Verifier Reputation

## Overview

`reputation.rs` provides `VerifierReputation`, an **informational-only**
accounting of a verifier's historical behaviour. Reputation data is never used
in trust decisions, consensus calculations, or policy evaluation. It exists
solely to support human audit and anomaly detection.

> **Critical invariant**: `VerifierReputation` does NOT implement
> `ConsensusTrust`. No path from `reliability_score()` flows into
> `ConsensusEvaluation::evaluate`. This is enforced at the type level.

---

## Core Type

```rust
/// AUDIT ONLY — must not influence consensus, policy, or trust decisions.
pub struct VerifierReputation {
    pub verifier_id:              String,
    pub successful_verifications: u64,
    pub policy_conflicts:         u64,
    pub transparency_failures:    u64,
    pub quorum_participations:    u64,
    pub last_updated:             u64,   // Unix seconds
}
```

---

## Recording Methods

| Method | Counter incremented |
|---|---|
| `record_success(now)` | `successful_verifications` |
| `record_conflict(now)` | `policy_conflicts` |
| `record_transparency_failure(now)` | `transparency_failures` |
| `record_quorum_participation(now)` | `quorum_participations` |

All counters use saturating arithmetic to prevent overflow.

---

## Informational Score

```rust
/// AUDIT ONLY — returns a value in [0.0, 1.0].
/// This value MUST NOT be used to make trust or policy decisions.
pub fn reliability_score(&self) -> f64
```

**Formula**: `successful_verifications / (successful_verifications + policy_conflicts + transparency_failures)`

| Condition | Score |
|---|---|
| All success, no failures | `1.0` |
| No events at all | `0.0` |
| Mixed | Between `0.0` and `1.0` |

`quorum_participations` does not enter the score (participation is not itself
a quality indicator).

---

## Usage Guidance

✅ **Allowed**:
- Display in operator dashboards
- Include in post-incident reports
- Use as a heuristic for human investigation

❌ **Prohibited**:
- Passing `reliability_score()` to `ConsensusEvaluation::evaluate`
- Using reputation to weight votes
- Using reputation to grant or deny federation membership

---

## Security Properties

- **No influence on consensus**: Enforced by type system — no impl of
  `ConsensusTrust` on `VerifierReputation`.
- **Tamper transparency**: All reputation changes are driven by events that
  also appear in `VerifierTransparencyLog`, so discrepancies are detectable.
- **Saturation safety**: Counters cannot wrap around.
