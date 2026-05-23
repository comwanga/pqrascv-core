# Governance Continuity

## Replay and Fork Resistance
Without strict temporal binding, a malicious coalition could potentially replay an older, valid governance transition to overwrite a newer policy state. 

To prevent this, `GovernanceTransition` structures are cryptographically hash-chained (`previous_transition_hash`).

## Governance DAG
Because each transition references the previous one, governance history behaves as an append-only Directed Acyclic Graph (DAG) or linear chain. This prevents the emergence of alternate valid histories, and makes epoch transitions completely deterministic and auditable.
