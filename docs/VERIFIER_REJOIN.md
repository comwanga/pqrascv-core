# Verifier Rejoin

Rejoin proofs validate current HLC synchronization, minimum retained checkpoint depth, and recovery lineage verification before allowing a verifier back into the quorum. This prevents stale state reintroduction and missed revocation reuse.

See `crates/pqrascv-hardware/src/verifier_rejoin.rs`.
