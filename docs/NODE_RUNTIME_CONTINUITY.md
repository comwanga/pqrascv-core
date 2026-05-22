# Node Runtime Continuity

Continuous attestation ensures a Bitcoin node remains in a trusted state long after the initial boot process.

## Continuous Monitoring

The node maintains a `NodeAttestationSession`, providing a monotonic sequence of runtime measurements.

## Drift Detection

The `BitcoinRuntimeState` tracks observable node behavior:
- Chain tip height
- Peer connections
- Mempool status

If the node's behavior deviates from its expected operational profile (e.g., dropping all peers unexpectedly while remaining online), the policy engine can flag this as `RuntimeNodeDrift`.
