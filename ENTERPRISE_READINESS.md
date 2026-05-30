# Enterprise Readiness Assessment

Version: v1.0.0-rc.5 | Branch: fix/security-audit-hardening | Date: 2026-05-30

This document records what is production-safe today, what is experimental and
requires additional hardening before production use, and what is explicitly on
the roadmap. It does not claim readiness without evidence.

---

## Test Suite Coverage (Phase 6 Validation Run)

Full workspace test suite result as of this assessment:

| Crate | Tests | Result |
|-------|-------|--------|
| `pqrascv-core` (unit) | 122 | ✅ pass |
| `pqrascv-core` (adversarial) | 17 | ✅ pass |
| `pqrascv-core` (integration) | 6 | ✅ pass |
| `pqrascv-hardware` | 183 | ✅ pass |
| `pqrascv-verifier` | 24 | ✅ pass |
| `pqrascv-bitcoin-anchor` | 45 | ✅ pass |
| Doc tests | 6 | ✅ pass (3 ignored — `no_run`) |
| **Total** | **403** | **✅ 0 failures** |

No fuzzing infrastructure is present in the workspace. This is a known gap
(see Known Limitations below).

---

## Operational Maturity Matrix

### Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Production-safe today — tested, documented, security gaps understood |
| ⚠️  | Experimental — functional but has documented constraints |
| ❌ | Not ready — missing evidence, untested on hardware, or fundamental gaps |

---

### Core Attestation (`pqrascv-core`)

| Capability | Status | Notes |
|------------|--------|-------|
| ML-DSA-65 sign / verify | ✅ | FIPS 204 compliant; deterministic; cross-tested |
| CBOR quote generation and parsing | ✅ | Size-bounded; roundtrip tested |
| Nonce issuance and replay detection | ✅ | Bounded FIFO (65 536-cap); type-level handle consumption |
| Multi-node replay protection | ⚠️  | `InMemoryNonceLedger` is per-process only; distributed nonce consensus requires external coordination (documented in `nonce/mod.rs`) |
| Policy evaluation (V1) | ✅ | Rule-based; deterministic; tested |
| Policy evaluation (V2 — `PolicyEngineV2`) | ✅ | Full test coverage including PKI and provenance paths |
| PKI chain validation | ✅ | Trust anchor lifecycle, revocation, expiry all tested |
| PKI root trust anchor rollover | ✅ | Overlapping validity windows tested; rollback rejection tested |
| SLSA provenance (v0 — `provenance`) | ✅ | Roundtrip and tamper tests pass |
| Sigstore/Fulcio/Rekor provenance (`provenance_v2`) | ⚠️  | Conditions 1–10 implemented; DER + raw r\|\|s fallback; no live Rekor endpoint tested; offline-only verification |
| Software RoT backend | ⚠️  | Functional for CI/dev; explicitly marked `software-rot-unsafe`; not for production |
| DICE backend | ⚠️  | Implemented; no hardware validation evidence |
| TPM 2.0 backend | ❌ | Architecture sound; no evidence of test against real TPM or swtpm; see `TPM_INTEGRATION.md` |

---

### Verifier (`pqrascv-verifier`)

| Capability | Status | Notes |
|------------|--------|-------|
| `verify_cbor` — signature, nonce, policy | ✅ | Fully tested including adversarial cases |
| `verify_with_challenge` | ✅ | Tested |
| PKI-gated verification | ✅ | E2E root→intermediate→device path tested |
| Sigstore-gated verification | ✅ | Tested with synthetic bundles |
| Replay protection — caller obligation | ⚠️  | Verifier does not consume from `NonceLedger`; caller must do so; documented in `verify_cbor` and `verify_with_challenge` |

---

### Hardware Federation (`pqrascv-hardware`)

| Capability | Status | Notes |
|------------|--------|-------|
| Federated policy epoch management | ✅ | Monotonicity, split-brain rejection, quorum check; 12 tests |
| Byzantine quorum evaluation | ⚠️  | Correct for N≥4 with f=(N-1)/3; equivocation detection absent (documented); vote deduplication absent (documented) |
| Distributed consensus aggregation | ⚠️  | Correct count logic; no verifier ID deduplication or membership check (documented) |
| Temporal ambiguity evidence | ⚠️  | `observer_signature` stored but not verified; fabrication risk documented |
| `QuorumCertificate` signatures | ⚠️  | Signature bytes stored; no verification implemented in this crate |
| PCR semantic mapping | ✅ | Canonical slot mapping tested; normalization tested |
| Governance log | ✅ | Nonce replay rejection, append-only audit tested |
| PQ transport (ML-KEM + ML-DSA) | ✅ | Seal/open, ratchet replay prevention tested |

---

### Bitcoin Anchor (`pqrascv-bitcoin-anchor`)

| Capability | Status | Notes |
|------------|--------|-------|
| RFC 6962 Merkle tree with domain separation | ✅ | CVE-2012-2459 duplicate-node attack rejected; inclusion proofs tested |
| Bitcoin OP_RETURN commitment | ✅ | 32-byte root, magic/version rejection tested |
| SPV inclusion proof with PoW | ✅ | Proof-of-work threshold, insufficient confirmations rejection tested |
| Timeline Merkle | ✅ | Domain separation, inclusion proofs tested |
| Federation batch aggregation | ✅ | Deterministic root, event count, policy epoch domain separation tested |

---

## Remaining Known Limitations

The following are documented gaps in the current implementation. They are not
silent — each has a module-level Known Limitation section and adversarial tests
that confirm the current behavior.

### 1. Unauthenticated Verifier Identity in Policy Epochs

**Location:** `crates/pqrascv-hardware/src/policy_federation.rs`

`FederatedPolicyEpoch::try_finalize()` checks `approved_by.len() >= quorum_required()`
but does not verify that the approver IDs are actual federation members, nor
that any cryptographic proof of identity was provided. Any caller with write
access to the epoch object can inject phantom approver IDs.

**Current security boundary:** access control to the epoch object.

**Hardening path:** each approver signs the epoch ID with their ML-DSA key;
`try_finalize()` verifies each signature against the corresponding member's
`public_key` field.

### 2. No Vote Deduplication or Membership Check in Distributed Consensus

**Location:** `crates/pqrascv-hardware/src/distributed_consensus.rs`

`ConsensusEvaluation::evaluate()` counts `votes.len()` with no deduplication
by `verifier_id` and no check against `federation.members`. Duplicate votes or
phantom-identity votes satisfy quorum by count alone.

**Current security boundary:** the caller is responsible for submitting one
vote per member.

**Hardening path:** deduplicate by `verifier_id` before counting; reject votes
whose `verifier_id` is not in `federation.members`.

### 3. Equivocation Not Detected in Byzantine Quorum

**Location:** `crates/pqrascv-hardware/src/byzantine_quorum.rs`

`ByzantineQuorumResult::evaluate()` does not detect a verifier appearing in
multiple `VoteSet`s for different state hashes. Such equivocation is counted
toward both hashes rather than flagged as `UnsafeEquivocation`.

**Hardening path:** collect all verifier IDs across all vote sets; if any ID
appears in two or more sets, return `ByzantineSafetyState::UnsafeEquivocation`.

### 4. Unverified Observer Signature on Temporal Ambiguity Evidence

**Location:** `crates/pqrascv-hardware/src/temporal_ambiguity.rs`

`TemporalAmbiguityEvidence::observer_signature` is stored but never
cryptographically verified. Any caller can fabricate evidence for any verifier
identity without a signing key.

**Hardening path:** define a `verify_observer_signature(federation)` method
that looks up the claimed `observing_verifier_id`'s `public_key` and verifies
the signature over the evidence fields.

### 5. TPM Backend Untested Against Hardware

**Location:** `crates/pqrascv-core/src/backends/tpm.rs`, `TPM_INTEGRATION.md`

Architecture is sound. No evidence of testing against a real TPM device or
`swtpm` simulation. The firmware hash is not derived from or linked to the TPM
measurement log (documented mitigation options in `TPM_INTEGRATION.md`).

**Hardening path:** CI integration against `swtpm`; integration tests against
at least one physical TPM 2.0 device.

### 6. Multi-Node Replay Protection Gap

**Location:** `crates/pqrascv-core/src/nonce/mod.rs`

`InMemoryNonceLedger` is a per-process, in-memory store. In a multi-node
verifier deployment, each node maintains an independent ledger. A nonce
consumed on node A is not visible to node B; an attacker can replay a quote
to a node that has not seen the nonce.

**Documented:** module-level deployment requirements section and
`multi_node_replay_gap_exists_by_design` test.

**Hardening path:** distributed ledger (Redis, etcd, PostgreSQL) with atomic
`get-or-set` semantics, or nonce binding to a specific verifier node identity.

### 7. ML-DSA RC Dependency Migration Risk

**Location:** `CRYPTO_STABILITY.md`

`ml-dsa = "=0.1.0-rc.8"` is a release candidate. Key and signature encoding
may change before `1.0.0`. Persisted verifying keys (1952 bytes), signatures
(3309 bytes), and CBOR-encoded quotes would require migration if encoding
changes.

**Hardening path:** test round-trip compatibility across the RC→stable boundary
when stable is released; have a key rotation plan for enrolled devices.

---

## Recommended Deployment Boundaries

### Production-safe today

- Short-lived attestation sessions (no key persistence across library version upgrades)
- CI/CD pipeline policy enforcement with software or DICE backends
- Single-node verifier deployments where nonce replay within a session is the threat model
- Bitcoin Merkle anchoring and timeline commitments
- PKI lifecycle management (trust anchors, rollover, revocation)

### Experimental — do not use for regulated or high-assurance deployments

- Multi-node distributed verifier federations (replay gap, unauthenticated quorum votes)
- TPM 2.0 backend (untested against hardware)
- Sigstore/Fulcio/Rekor provenance verification against a live Rekor log
  (no live-endpoint integration test exists)
- Federation Byzantine quorum decisions where equivocation detection is required

### Roadmap — not implemented yet

- Cryptographic proof of verifier identity in policy epoch approvals
- Vote deduplication and membership validation in consensus aggregation
- Equivocation detection in Byzantine quorum evaluation
- Observer signature verification in temporal ambiguity evidence
- TPM swtpm CI integration
- Distributed nonce ledger for multi-node replay protection
- ML-DSA 1.0.0 migration validation

---

## What This Assessment Does Not Cover

- Formal verification of cryptographic properties
- Penetration testing of networked deployments
- Side-channel analysis of ML-DSA or ML-KEM implementations
- Compliance certification (FIPS, Common Criteria, SOC 2)

These require third-party engagement and are out of scope for this codebase-level assessment.
