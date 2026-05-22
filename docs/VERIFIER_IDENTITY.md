# VERIFIER_IDENTITY — Cryptographic Verifier Model

## Overview

In PQ-RASCV Phase 2.9, every entity that participates in attestation
verification is a **first-class cryptographic principal** represented by a
`VerifierIdentity`. Implicit trust in verifiers is eliminated; participation in
any federation requires a valid, time-bounded `VerifierCertificate`.

---

## Core Types

### `VerifierIdentity`

```rust
pub struct VerifierIdentity {
    pub verifier_id:   String,
    pub organization:  String,
    pub public_key:    Vec<u8>,
    pub capabilities:  Vec<VerifierCapability>,
}
```

| Field | Constraint |
|---|---|
| `verifier_id` | Non-empty, globally unique within a federation |
| `organization` | Informational; used in audit logs |
| `public_key` | Non-empty byte vector; algorithm implied by deployment context |
| `capabilities` | Non-empty; at least one `VerifierCapability` required |

### `VerifierCapability`

```rust
pub enum VerifierCapability {
    HardwareVerification,
    RuntimeVerification,
    ProvenanceVerification,
    BitcoinAnchoring,
    TransparencyLogging,
    PolicyAuthority,
}
```

Capabilities scope what a verifier may do within a federation. A verifier
attempting an action outside its stated capabilities is rejected by federation
policy.

### `VerifierCertificate`

```rust
pub struct VerifierCertificate {
    pub verifier_id:  String,
    pub issued_by:    String,
    pub valid_from:   u64,   // Unix seconds
    pub valid_until:  u64,   // Unix seconds
    pub capabilities: Vec<VerifierCapability>,
    pub signature:    Vec<u8>,
}
```

#### Validity Methods

| Method | Semantics |
|---|---|
| `is_valid_at(now: u64) -> bool` | Returns `true` iff `valid_from <= now < valid_until` |
| `has_capability(cap) -> bool` | Returns `true` if the requested capability is present |
| `validate_structure() -> Result<(), CertificateError>` | Rejects malformed certificates |

#### `CertificateError` Variants

| Variant | Trigger |
|---|---|
| `Expired` | `now >= valid_until` |
| `NotYetValid` | `now < valid_from` |
| `EmptyPublicKey` | `public_key.is_empty()` |
| `EmptySignature` | `signature.is_empty()` |
| `MissingCapabilities` | `capabilities.is_empty()` |
| `InvalidTimeRange` | `valid_from >= valid_until` |

---

## Certificate Lifecycle

```
Issue → Active → [Rotated | Revoked | Expired]
```

1. **Issue**: Authority signs the certificate; `valid_from` is set to now.
2. **Active**: `is_valid_at(now)` returns `true`; the verifier may participate.
3. **Rotated**: A governance action (`RotatePolicyAuthority`) replaces the old
   certificate; the old one expires at its `valid_until` or is immediately
   revoked.
4. **Revoked**: A `RevokeVerifier` governance action records the revocation.
   Post-revocation, the verifier ID must not appear in any federation quorum
   vote. The `GovernanceLog` provides an immutable audit trail.

---

## Security Properties

- **No implicit trust**: A verifier not present in the federation's member list
  is never consulted.
- **Time-bounded authority**: Certificates expire. Failure to renew before
  `valid_until` leaves the verifier unable to participate until re-issued.
- **Capability scoping**: A verifier with only `RuntimeVerification` may not
  perform `PolicyAuthority` actions.

---

## Relationship to Other Modules

| Module | Relationship |
|---|---|
| `verifier_federation.rs` | `VerifierFederation` holds a `Vec<VerifierIdentity>` |
| `governance.rs` | `GovernanceRecord` references verifier IDs for `AddVerifier`, `RevokeVerifier` |
| `distributed_consensus.rs` | `VerifierVote` is keyed by `verifier_id` |
| `verifier_transparency.rs` | `VerifierTransparencyEvent.verifier_id` must match a known identity |
