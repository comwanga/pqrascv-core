# Disaster Recovery

This document outlines the disaster recovery architecture for the PQ-RASCV federation.

## Disaster Recovery Checkpoints
Disaster recovery checkpoints maintain an append-only chain, providing deterministic restoration boundaries that can be globally audited via Bitcoin.

See `crates/pqrascv-hardware/src/disaster_recovery.rs` for implementation details.
