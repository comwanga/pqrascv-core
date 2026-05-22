# Sovereign Bitcoin Node Architecture

The Phase 3.0 release transforms PQ-RASCV from a generalized hardware attestation framework into a domain-specific, verifier-centric trust engine for Sovereign Bitcoin Infrastructure.

## Core Philosophy

A Bitcoin node is not a generic cloud workload. It is a sovereign cryptographic entity that participates in the global consensus of the Bitcoin network. Its security cannot be entrusted to implicit cloud isolation or non-transparent host environments.

This architecture explicitly binds the **Bitcoin Workload** (Bitcoin Core) to the **Hardware Root of Trust** (TPM 2.0 / DICE / TDX), ensuring that the node's operational state is deterministically verifiable from power-on through runtime.

## Trust Domains

The architecture separates verification into discrete, non-collapsible domains:
1. **Hardware Identity**: Binding to physical/confidential hardware.
2. **Measured Boot**: Verifying the bootloader and OS kernel.
3. **Secure Boot**: Enforcing execution permissions.
4. **Workload Integrity**: Verifying `bitcoind` and `bitcoin.conf`.
5. **Runtime Continuity**: Monitoring node runtime state continuously.
6. **Consensus Integrity**: Distributed verifier quorums.
7. **Transparency**: Anchoring attestation states to public logs (or Bitcoin itself).

## Lifecycle

1. **Boot**: The hardware root of trust hashes the boot sequence.
2. **Identity Setup**: The `BitcoinNodeIdentity` is established, defining the expected binary and configuration hashes.
3. **Runtime Monitoring**: A `BitcoinRuntimeState` continuously measures mempool, chain tip, and peers without interacting with consensus validity.
4. **Attestation Session**: A `NodeAttestationSession` binds the hardware evidence to the running node.
5. **Distributed Verification**: A `VerifierOrchestrator` distributes evidence to a verifier federation.
6. **Consensus Decision**: The federation evaluates the evidence against strict `HardwarePolicyRule` profiles.
7. **Anchoring**: The resulting `AttestedNodeReport` is anchored to a transparency log.
