# Verifier Orchestration

The `VerifierOrchestrator` coordinates the end-to-end continuous verification lifecycle.

## Responsibilities

1. **Evidence Collection**: Gathers hardware measurements and runtime state from the node.
2. **Distribution**: Sends evidence to the verifier federation.
3. **Aggregation**: Collects `VerifierVote` responses and computes the `ConsensusEvaluation`.
4. **Anchoring**: Submits the `ConsensusEvaluation` to the transparency log or Bitcoin chain.
5. **Reporting**: Produces the final `AttestedNodeReport`.
