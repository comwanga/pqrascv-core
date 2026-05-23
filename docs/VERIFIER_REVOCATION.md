# Verifier Revocation

## Epoch-Bound Revocation
Verifiers compromised by key exposure or detected engaging in Byzantine behavior must be globally and deterministically revoked across the federation.

Revocation proofs in PQ-RASCV are bound by `effective_from_sequence`. This provides a strict separation between historical auditability and forward validity.

## Properties
1. **Append-Only:** Revocations cannot be undone.
2. **Replay Protected:** A verifier cannot replay an old, valid revocation against a newer epoch to mask a later action.
3. **Fail-Closed:** A revoked verifier's signatures are immediately rejected for any sequence `>= effective_from_sequence`.
4. **Historical Preservation:** Signatures generated *before* `effective_from_sequence` remain mathematically valid for historical audit reconstruction.

## Detection & Propagation
Revocation proofs are primarily propagated in-band over `pq_transport` for low-latency distribution, with transparency log (Bitcoin) anchoring acting as the verifiable secondary fallback.
