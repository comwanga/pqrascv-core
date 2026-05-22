# Phase 3.0 Threat Model

This document outlines the specific threats mitigated by the Sovereign Bitcoin Node architecture.

## Mitigated Threats

1. **Unauthorized Configuration Changes**: If an attacker gains host access and modifies `bitcoin.conf` (e.g., to enable `rpcbind=0.0.0.0` or change `rpcauth`), the hardware measurement changes. The `RequireBitcoinWorkloadIntegrity` rule detects this drift and flags the node as untrusted.
2. **Binary Substitution**: If `bitcoind` is replaced with a malicious fork, the `executable_hash` will fail verification against the `BitcoinNodeIdentity`.
3. **Verifier Collusion**: A single compromised verifier cannot fake an attestation report. The `RequireFederatedNodeVerification` rule demands consensus from the `VerifierFederation`.
4. **Split-Brain Attestation**: If verifiers provide different answers to different clients, the `RequireNodeTransparencyAnchoring` rule ensures the conflicting state is detectable via public transparency logs or the Bitcoin chain itself.
5. **Replay Attacks**: A compromised node cannot replay old evidence to hide current tampering. The `NodeAttestationSession` enforces monotonic sequences and time windows.
