# Federation Synchronization

## Deterministic Convergence
To guarantee that disjoint verifiers hold the exact same understanding of global trust, PQ-RASCV defines `FederationSyncState`.

This state is a cryptographically canonical reduction of:
1. Active State Hash
2. Active Governance Epoch
3. Latest Revocation Epoch

## Visibility Over Resolution
If a synchronization check fails, the protocol intentionally halts local downstream dependencies. It prioritizes the visibility of the divergence over attempting to "auto-resolve" the conflict, which could obscure a stealthy partition attack.
