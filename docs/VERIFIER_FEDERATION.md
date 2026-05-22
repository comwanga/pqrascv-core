# VERIFIER_FEDERATION — Membership & Quorum Policy

## Overview

A `VerifierFederation` groups multiple `VerifierIdentity` members under a
shared `QuorumPolicy`. The federation is the authority that determines how many
verifier votes constitute a legitimate consensus decision.

---

## Core Types

### `VerifierFederation`

```rust
pub struct VerifierFederation {
    pub federation_id:  String,
    pub members:        Vec<VerifierIdentity>,
    pub quorum_policy:  QuorumPolicy,
}
```

### `QuorumPolicy`

```rust
pub enum QuorumPolicy {
    Majority,           // ⌈n/2⌉ + 1
    SuperMajority,      // ⌈2n/3⌉ + 1
    Unanimous,          // n
    Threshold(u8),      // exact count
}
```

---

## Quorum Semantics

| Policy | Required votes (n members) | Notes |
|---|---|---|
| `Majority` | `⌈n/2⌉ + 1` | Simple majority |
| `SuperMajority` | `⌈2n/3⌉ + 1` | Byzantine-fault-tolerant threshold |
| `Unanimous` | `n` | All members must vote `trusted` |
| `Threshold(t)` | `t as usize` | Fixed count; fails if `t == 0` or `t > n` |

The quorum function is **deterministic and pure**: identical federation state
always produces the same required count regardless of call order.

---

## Validation

`VerifierFederation::validate() -> Result<(), FederationError>`

| `FederationError` | Condition |
|---|---|
| `EmptyMembership` | `members.is_empty()` |
| `ZeroThreshold` | `QuorumPolicy::Threshold(0)` |
| `ThresholdExceedsMembership` | `t as usize > members.len()` |
| `DuplicateMember` | Two entries share the same `verifier_id` |

---

## Key Methods

| Method | Purpose |
|---|---|
| `member_count() -> usize` | Total registered members |
| `quorum_required() -> usize` | Minimum votes for consensus |
| `is_quorum_satisfied(vote_count) -> bool` | `vote_count >= quorum_required()` |
| `members_with_capability(cap) -> Vec<&VerifierIdentity>` | Filter by capability |

---

## Security Properties

- **No empty federations**: `EmptyMembership` is rejected at construction.
- **No zero threshold**: `Threshold(0)` would trivially satisfy quorum; rejected.
- **Threshold cap**: A threshold exceeding membership is unreachable; rejected.
- **Duplicate rejection**: Two members with the same ID indicate a configuration
  error or an attempt to inflate vote counts.

---

## Relationship to Other Modules

| Module | Relationship |
|---|---|
| `distributed_consensus.rs` | `ConsensusEvaluation::evaluate` takes a `&VerifierFederation` |
| `policy_federation.rs` | `FederatedPolicyEpoch::try_finalize` calls `federation.quorum_required()` |
| `governance.rs` | `UpdateQuorumPolicy` changes the federation's `QuorumPolicy` |
| `policy.rs` | `HardwarePolicyContext.federation` carries a `&VerifierFederation` |
