# PCR Baselines and Versioning

To defend against malicious software downgrades and unauthorized configuration changes, PQ-RASCV v2 provides versioned baseline tracking and rollback protection.

## Baseline Structs

- `PolicyVersion`:
  - `epoch`: Monotonically increasing epoch number.
  - `created_at`: Creation timestamp.
  - `supersedes`: Epoch this policy explicitly overrides.
- `PcrBaseline`:
  - `baseline_id`: Unique identifier for the baseline.
  - `version`: Monotonic revision index.
  - `measurements`: Collection of `ExpectedPcr` entries mapping to slot semantics.
  - `supersedes`: Link to a previous baseline ID.

## Successor Verification & Anti-Rollback

Baselines evolve in a linked-list style manner. Rollback protection is enforced via `PcrBaseline::is_valid_successor(&self, previous_baseline: &PcrBaseline)`:
1. **Version Monotonicity**: The successor's version MUST be strictly greater than the predecessor's version.
2. **Explicit Supersession**: If the successor contains a `supersedes` baseline ID, it must match the predecessor's ID.

If these constraints are violated, the verifier rejects the transition, failing with `VerificationDecisionReason::BaselineRollbackDetected`.
