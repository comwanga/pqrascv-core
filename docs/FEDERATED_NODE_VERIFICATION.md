# Federated Node Verification

Single-verifier systems introduce a central point of failure. If the verifier is compromised, the node's trust state is compromised.

## Distributed Consensus

PQ-RASCV uses a distributed quorum of verifiers to evaluate node evidence.

- **`VerifierVote`**: Each verifier independently evaluates the hardware evidence and submits a cryptographically signed vote.
- **`ConsensusEvaluation`**: The votes are aggregated into a deterministic `ConsensusDecision`.
- **Quorum Policies**: Policies like `Majority`, `Unanimous`, or `Threshold(n)` dictate how many trusted votes are required to produce a finalized `Trusted` state.
