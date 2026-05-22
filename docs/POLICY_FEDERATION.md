# POLICY_FEDERATION — Epoch Approval & Split-Brain Rejection

## Overview

`policy_federation.rs` governs how policy changes (represented as _epochs_)
are approved across a federation. No policy epoch may take effect unless a
quorum of federation members has explicitly approved it. Once finalized, epochs
are immutable.

---

## Core Types

### `FederatedPolicyEpoch`

```rust
pub struct FederatedPolicyEpoch {
    pub epoch_id:        u64,
    pub approved_by:     Vec<String>,   // verifier IDs that approved
    pub quorum_reached:  bool,
    pub created_at:      u64,
    pub previous_epoch:  Option<u64>,
}
```

### `FederatedPolicyError`

| Variant | Condition |
|---|---|
| `QuorumNotReached { approvals, required }` | `approved_by.len() < quorum_required()` |
| `ConflictingEpoch { existing, proposed }` | Proposed epoch conflicts with an existing non-finalized epoch |
| `SplitBrainDetected` | Two non-finalized epochs share the same `epoch_id` |
| `EpochAlreadyFinalized` | Attempt to re-finalize or mutate a finalized epoch |
| `NonMonotonicEpoch { previous, proposed }` | `proposed <= previous` |

---

## Finalization Protocol

`FederatedPolicyEpoch::try_finalize(&mut self, federation: &VerifierFederation) -> Result<(), FederatedPolicyError>`:

1. Deduplicates `approved_by` (same verifier cannot cast double-vote).
2. Checks `approved_by.len() >= federation.quorum_required()`.
   - If not, returns `QuorumNotReached`.
3. Sets `quorum_reached = true`.
4. On subsequent call: returns `EpochAlreadyFinalized` (immutability guarantee).

---

## `FederatedPolicyRegistry`

A simple ordered container that tracks proposed and active epochs.

| Method | Purpose |
|---|---|
| `propose(epoch, federation)` | Validates monotonicity and split-brain, then registers |
| `active_epoch()` | Returns the latest finalized epoch |

### Monotonicity Enforcement

`propose` rejects any `epoch_id <= last_finalized_id` with `NonMonotonicEpoch`.
This prevents epoch rollback attacks.

### Split-Brain Detection

If two entries with the same `epoch_id` exist in a non-finalized state,
`SplitBrainDetected` is returned. This catches concurrent conflicting proposals
before quorum is reached.

---

## Policy Integration

The `RequireFederatedPolicyApproval` rule in `policy.rs`:

1. Retrieves `context.federated_epoch`.
2. Checks `epoch.quorum_reached == true`.
3. If not reached: returns `HardwarePolicyError::FederatedEpochQuorumNotReached`.

---

## Security Properties

- **Quorum before activation**: No epoch takes effect without a federation
  majority (or configured threshold).
- **Immutability on finalization**: `EpochAlreadyFinalized` prevents mutation
  after the fact.
- **Monotonicity**: Rollback to a previous epoch is structurally impossible.
- **Split-brain rejection**: Two incompatible proposals before quorum are
  caught and flagged.

---

## Relationship to Other Modules

| Module | Relationship |
|---|---|
| `verifier_federation.rs` | Provides `quorum_required()` used in `try_finalize` |
| `governance.rs` | Policy epoch proposals are governance actions |
| `bitcoin-anchor/federation.rs` | `add_policy_epoch` anchors finalized epoch hashes to Bitcoin |
