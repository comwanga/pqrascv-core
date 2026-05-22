# GOVERNANCE — Signed Governance Model, Replay Protection & Bitcoin Anchoring

## Overview

`governance.rs` provides a **cryptographically signed, replay-protected,
hash-chained governance log**. All changes to federation membership, quorum
policy, and verifier authority flow through `GovernanceRecord`s that are
appended to an immutable `GovernanceLog`.

---

## Core Types

### `GovernanceAction`

```rust
pub enum GovernanceAction {
    AddVerifier    { verifier: VerifierIdentity },
    RemoveVerifier { verifier_id: String },
    RotatePolicyAuthority { old: String, new: String },
    RevokeVerifier { verifier_id: String, reason: String },
    UpdateQuorumPolicy { new_policy: QuorumPolicy },
}
```

All changes to the federation's trust topology are expressed as `GovernanceAction`
variants, providing a uniform, auditable record.

### `GovernanceRecord`

```rust
pub struct GovernanceRecord {
    pub action_id:            String,
    pub action:               GovernanceAction,
    pub authorized_by:        String,        // verifier_id of authorizer
    pub timestamp:            u64,
    pub nonce:                [u8; 32],      // uniqueness token
    pub signature:            Vec<u8>,
    pub previous_action_hash: Option<[u8; 32]>,
}
```

| Field | Purpose |
|---|---|
| `nonce` | Unique per-record token; prevents replay |
| `signature` | Covers the record content; validates authorization |
| `previous_action_hash` | Links to previous record, forming an append-only chain |

### `GovernanceError`

| Variant | Condition |
|---|---|
| `InvalidSignature` | Signature verification failed |
| `ReplayDetected { nonce }` | A record with this nonce was previously seen |
| `UnauthorizedAction` | `authorized_by` lacks the required capability |
| `ChainBroken` | `previous_action_hash` does not match the head of the chain |
| `EmptySignature` | `signature.is_empty()` |
| `EmptyNonce` | `nonce == [0u8; 32]` |

---

## `GovernanceLog`

```rust
pub struct GovernanceLog { /* private internals */ }
```

| Method | Purpose |
|---|---|
| `append(record) -> Result<(), GovernanceError>` | Validates and appends a record |
| `validate_structure(record) -> Result<(), GovernanceError>` | Static structural check |
| `len() -> usize` | Number of records |
| `records() -> &[GovernanceRecord]` | Read-only slice |

### Append Protocol

1. `validate_structure`: rejects `EmptySignature`, `EmptyNonce`.
2. **Nonce uniqueness**: checks against all previously seen nonces; rejects
   `ReplayDetected` on collision.
3. **Chain linkage**: the record's `previous_action_hash` must match
   `SHA3-256(last_record)` (or `None` for the first record).
   Mismatch → `ChainBroken`.
4. Appends to the log.

---

## Bitcoin Anchoring

`GovernanceRecord` hashes can be batch-anchored to Bitcoin via
`FederationBatchAggregator::add_governance_event(hash)`. This provides:

- **Existence proof**: the governance action was recorded before a specific
  Bitcoin block.
- **Ordering proof**: the Merkle tree captures relative ordering of events.
- **Audit finality**: the Bitcoin blockchain is globally verifiable and
  immutable.

> **Bitcoin is AUDIT ONLY**: the anchoring step produces no policy decisions.
> The anchor merely proves the governance action existed at a point in time.

---

## Replay Protection Design

Each `GovernanceRecord` carries a 32-byte `nonce`. The `GovernanceLog` maintains
an internal set of all seen nonces. Submitting a record with a previously used
nonce returns `ReplayDetected` regardless of other field values. Zero nonces
(`[0u8; 32]`) are rejected at the structural validation step.

---

## Hash Chain Integrity

The `previous_action_hash` field binds each record to its predecessor, forming
a singly-linked chain. Any tampering with a record in the middle of the chain
breaks the linkage and causes `ChainBroken` on the next append. External
auditors can independently verify the chain by recomputing SHA3-256 hashes.

---

## Security Properties

| Threat | Mitigation |
|---|---|
| Replay attack | Per-record nonce uniqueness |
| Insertion of unauthorised actions | Signature check (caller responsibility) |
| Record modification | Hash-chained linkage; `records()` is read-only |
| History truncation | Chain breaks at first missing record |
| Zero-nonce bypass | `EmptyNonce` structural rejection |
