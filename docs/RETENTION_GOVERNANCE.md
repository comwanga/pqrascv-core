# Retention Governance

## The Need for Governed Retention
Allowing local edge nodes to dictate their own stream history retention opens the door to asynchronous amnesia attacks, where malicious nodes intentionally "forget" specific attestation gaps to avoid scrutiny.

## Mechanism
Retention policy (e.g., maximum stream age, maximum uncompacted checkpoints) is now a globally agreed-upon federation consensus item. Transitions are wrapped in `SignedRetentionPolicy` and are strictly monotonic.

## Rollback Rejection
A federation cannot revert to an older retention epoch. This ensures that a compromised majority cannot retroactively lower retention requirements to prune an active forensic investigation from the timeline.
