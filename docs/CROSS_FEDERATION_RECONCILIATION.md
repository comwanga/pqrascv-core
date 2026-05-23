# Cross-Federation Reconciliation

## Sovereign Boundaries
Multiple independent PQ-RASCV federations may exist globally. They do not implicitly trust one another. Cross-federation interaction must assume mutual distrust.

## Observational Reconciliation
The `CrossFederationReport` evaluates states across independent federation boundaries. Its core architectural rule is strict observation:

**It must NEVER automatically merge states, auto-resolve quorum failures, or adopt external policies.**

By explicitly mapping divergence points, the system allows human operators or meta-governance layers to evaluate discrepancies safely without poisoning the local verified state.
