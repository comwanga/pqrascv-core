# Attested Bitcoin Node

An Attested Bitcoin Node is a specialized execution profile where the Bitcoin node's identity, binary, configuration, and execution environment are continuously verified by a hardware root of trust.

## The Problem

Traditional Bitcoin nodes operate under the assumption that the host OS and underlying hardware are implicitly trusted. If a node operator's infrastructure is compromised (e.g., unauthorized configuration changes to `bitcoin.conf`, substitution of the `bitcoind` binary, or hypervisor-level tampering), the node may silently operate against the operator's intent.

## The Solution

By integrating PQ-RASCV, an Attested Bitcoin Node:
- Emits cryptographic evidence of its boot sequence.
- Binds the execution of `bitcoind` to hardware measurements.
- Enforces a deterministic policy profile.
- Produces an `AttestedNodeReport` that can be independently verified by a distributed federation of verifiers.
