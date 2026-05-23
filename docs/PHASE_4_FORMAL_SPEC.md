# Phase 4: Formal Verification Specification (Level B)

This document defines the formal correctness properties, state machine invariants, and deterministic guarantees for the PQ-RASCV Byzantine Federation. It serves as the canonical reference for invariant checks, property-based testing (via `proptest`), and fuzzing campaigns (via `cargo-fuzz`).

## 1. System Model & Assumptions

### 1.1 Scope
This specification covers the **Federation Consensus Layer**, **Hardware Attestation Layer**, and **Bitcoin Anchor Finality Layer**. It does not cover the post-quantum cryptography primitives themselves (which are assumed correct based on external standardization and PINNING).

### 1.2 Threat Model
- **Byzantine Nodes:** Up to $f$ malicious nodes in a $3f + 1$ federation. Malicious nodes may equivocate, withhold messages, or send malformed data.
- **Network:** Asynchronous, partially reliable network. Messages may be dropped, duplicated, or delayed arbitrarily.
- **Hardware:** The trusted execution environment (TEE) and TPM/DICE modules are assumed to provide genuine hardware evidence. The policy engine must correctly evaluate this evidence against predefined profiles.
- **Bitcoin:** The Bitcoin blockchain is assumed to be immutable after $k$ confirmations.

## 2. Global State Machine Invariants

The core federation logic is modeled as a deterministic state machine $S_{i+1} = \delta(S_i, E)$, where $E$ is a valid transition event.

### 2.1 INVARIANT: State Hash Determinism
For any identical starting state $S_i$ and event $E$, the transition function $\delta$ MUST produce the exact same resultant state $S_{i+1}$ and state root hash.

**Enforcement:** `invariants::SystemInvariants::assert_deterministic_delta_root`
**Testing:** Proptest generation of random valid events applied to cloned states.

### 2.2 INVARIANT: Monotonic Sequence and Epochs
The Sequence ID (Timeline) and Epoch Number MUST strictly monotonically increase across finalized state transitions.

**Enforcement:** `invariants::SystemInvariants::assert_monotonic_time` and `assert_no_equivocation`
**Testing:** Proptest assertions that no sequence ID goes backward or repeats.

### 2.3 INVARIANT: Audit Trace Append-Only Lineage
Every node MUST maintain a cryptographically linked `AuditTrace`. The $N$-th root in the trace MUST be deterministically derivable from the genesis root and the sequence of $N$ transition hashes.

**Enforcement:** `audit_trace::AuditTrace::verify_integrity`
**Testing:** Proptest validation of random event sequences.

### 2.4 INVARIANT: Replay Horizon Boundedness
The history available for deterministic replay MUST NOT exceed the globally defined maximum bounded length.

**Enforcement:** `invariants::SystemInvariants::assert_bounded_replay`
**Testing:** Proptest validation generating chains exceeding the bound to trigger panics.

## 3. Quorum & Finality Invariants

### 3.1 INVARIANT: Threshold Signatures
A `QuorumFormed` event MUST contain valid signatures from at least $2f + 1$ distinct nodes out of the current validator set.

### 3.2 INVARIANT: Cross-Phase Closure Consistency
A `FinalityCommitment` (Bitcoin Anchor) MUST correspond to a previously finalized `QuorumFormed` event. It represents absolute, irreversible finality.

**Enforcement:** `consistency_checker::ConsistencyChecker::validate_system_consistency`
**Testing:** Proptest validation that `SnapshotSealed` without `QuorumFormed` results in failure.

## 4. Verification Methodology

### 4.1 Property-Based Testing (`proptest`)
Used to mathematically prove deterministic properties.
- **Targets:** `AuditTrace` integrity, state machine transitions, root hash determinism, replay bounds.

### 4.2 Fuzzing (`cargo-fuzz`)
Used to discover undefined behavior, memory unsafety, and panic boundaries.
- **Targets:** CBOR/JSON deserializers, `FinalityCommitment` parsers, policy engine evaluation on malformed hardware evidence.

## 5. Formal Definitions

Let:
- $H(x)$ be the SHA3-256 hash function.
- $Trace_n$ be the Audit Trace at step $n$.
- $Root_n$ be the root hash at step $n$.

**Trace Root Evolution:**
$Root_0 = H(Genesis)$
$Root_{n+1} = H(Root_n \Vert H(Event_{n+1}))$

The state is considered **Correct** iff $\forall n, Root_n$ matches the expected consensus state root and $Event_n$ is locally valid.
