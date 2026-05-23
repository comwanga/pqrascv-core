# Phase 3.3 Threat Model Updates

## Scope Expansion
Phase 3.3 significantly shifts the threat model from "Hardware Exploitation and Runtime Drift" to "Byzantine Governance and Temporal Ambiguity".

## Mitigated Threats
1. **Malicious Verifier Persistence**: Solved by epoch-bound, sequence-bound revocation mechanisms.
2. **Equivocation / Split-Brain**: Solved by canonical contradiction proofs leading to immediate revocation.
3. **Partition Attacks**: Solved by separating Byzantine Safety (UnsafePartition) from Liveness, preventing auto-merging of disjoint quorum states.
4. **Governance Replay**: Solved by hash-chaining `GovernanceTransition` events.
5. **Privilege Escalation**: Solved by bounding verifier authority within topological scopes (`TrustDomain`, `FederationZone`).

## Unresolved Risks (Future Phases)
As noted by architecture feedback, **Federation Time Semantics** remain the largest unresolved threat surface. Relying on asynchronous timestamps without logical federation clocks or bounded skew tolerance leaves coordination vulnerable to temporal ambiguity and malicious delay attacks. This will be addressed in future phases.
