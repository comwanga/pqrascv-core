# Phase 3.5 Threat Model

This document outlines the threat model for the Phase 3.5 infrastructure resilience updates.

## 1. Malicious Divergence Amplification
**Threat:** An adversary artificially creates complex, nested partitions to exhaust verifier memory when tracking `PartitionEvidence`.
**Mitigation:** `PartitionEvidence` tracks only immediate fork roots (`conflicting_roots`) and delegates deeper history to a cryptographic lineage hash (`lineage_reference_root`).

## 2. Replay Memory Exhaustion
**Threat:** An adversary feeds an infinite stream of replayed events to a verifier recovering its state.
**Mitigation:** `deterministic_replay.rs` utilizes a `ReplayWindow` which explicitly bounds memory and compactly folds older elements into `applied_event_root`.

## 3. Silent Partition Reconciliation
**Threat:** Conflicting histories are auto-merged, causing silent history truncation and lost auditability.
**Mitigation:** Automatic healing is explicitly forbidden. Healing decisions (`PartitionHealingDecision`) must be formally recorded and passed through governance.

## 4. Unauditable Recovery Restitution
**Threat:** The federation recovers from a disaster but cannot cryptographically prove the integrity of the recovered state.
**Mitigation:** `disaster_recovery.rs` defines deterministic boundaries that are globally audited via Bitcoin Anchoring (`RecoveryAnchorType::DisasterRecoveryAnchor`).

## 5. Stale Verifier Reintroduction
**Threat:** A temporarily partitioned verifier reconnects using a stale continuity state, bypassing intermediate revocations.
**Mitigation:** `RejoinProof` forces current epoch matching, recovery lineage proof, and explicit revocation checks.
