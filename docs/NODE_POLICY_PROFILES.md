# Node Policy Profiles

Deterministic profiles simplify the application of strict hardware rules based on the node's operational role.

## `BitcoinNodeProfile`

- `SovereignMainnetNode`: Requires hardware root, measured boot, secure boot, and workload integrity.
- `FederationVerifierNode`: Adds requirements for verifier federation consensus and transparency anchoring.
- `AirgappedAuditNode`: Focuses on boot and offline workload integrity.
- `WatchtowerNode`: Specialized profile for monitoring LN states.
- `MinimalEmbeddedNode`: Relaxed hardware constraints for IoT/embedded deployments.
