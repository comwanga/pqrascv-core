# DISTRIBUTED_CONSENSUS — Verifier Vote Aggregation

## Overview

`distributed_consensus.rs` implements the deterministic vote-tallying layer
that converts per-verifier verdicts into a single, auditable `ConsensusDecision`.
It is the core trust-judgment mechanism for Phase 2.9 federated verification.

---

## Core Types

### `VerifierVote`

```rust
pub struct VerifierVote {
    pub verifier_id: String,
    pub trusted:     bool,
    pub reasons:     Vec<VerificationDecisionReason>,
    pub warnings:    Vec<String>,
}
```

Each participating verifier submits exactly one `VerifierVote`. The `trusted`
field is the single binary verdict; `reasons` and `warnings` provide auditable
supporting detail.

### `ConsensusEvaluation`

```rust
pub struct ConsensusEvaluation {
    pub attestation_id:  String,
    pub verifier_votes:  Vec<VerifierVote>,
    pub final_decision:  ConsensusDecision,
    pub participating:   usize,
    pub quorum_required: usize,
}
```

### `ConsensusDecision`

```rust
pub enum ConsensusDecision {
    Trusted,
    Untrusted,
    Inconclusive,
    QuorumFailed { participating: usize, required: usize },
}
```

---

## Consensus Algorithm

`ConsensusEvaluation::evaluate(attestation_id, votes, federation) -> Self`:

1. Compute `quorum_required` from `federation.quorum_required()`.
2. **Participation check**: if `votes.len() < quorum_required` → `QuorumFailed`.
3. **Trusted count**: count votes where `trusted == true`.
   - If `trusted_count >= quorum_required` → `Trusted`.
4. **Untrusted count**: count votes where `trusted == false`.
   - If `untrusted_count >= quorum_required` → `Untrusted`.
5. Otherwise (votes split, neither side reached quorum) → `Inconclusive`.

### Determinism Guarantee

- No randomness is used.
- Vote ordering does not affect the outcome (counts are computed over the full
  slice before any branching decision).
- Same `(attestation_id, votes, federation)` inputs always produce the same
  `ConsensusEvaluation`.

---

## Policy Integration

The `RequireConsensusQuorum { min_votes }` rule in `policy.rs` evaluates:

1. Retrieves `context.consensus_evaluation`.
2. Checks `evaluation.participating >= min_votes`.
3. Checks `evaluation.final_decision.is_trusted()`.

Either failure returns `HardwarePolicyError::ConsensusQuorumFailed`.

---

## `ConsensusDecision::is_trusted()`

```rust
impl ConsensusDecision {
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }
}
```

Only `Trusted` returns `true`. `Inconclusive` and `QuorumFailed` are treated
as failures by the policy engine.

---

## Security Properties

- **Fail-closed**: insufficient participation → `QuorumFailed` (not `Inconclusive`).
- **No abstentions**: every participating verifier must cast a `trusted` or
  `untrusted` vote. Silence (non-participation) is not a vote.
- **No reputation weighting**: all votes are equal. Reputation data (`reputation.rs`)
  is strictly audit-only and does not enter this computation.
