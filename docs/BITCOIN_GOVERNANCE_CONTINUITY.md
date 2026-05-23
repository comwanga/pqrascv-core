# Bitcoin Governance Anchoring

## Separation of Concerns
While Phase 3.2 heavily leveraged `IncrementalAnchor` for continuous runtime attestation streams, Phase 3.3 introduces the `GovernanceAnchor`.

This separation is critical. Runtime anchors prove continuity, sequence integrity, and checkpoint validity. Governance anchors prove federation authority, revocation lineage, quorum legitimacy, and epoch continuity.

## Semantic Isolation
By isolating governance anchors into a separate OP_RETURN structure, we ensure that Bitcoin's timestamping and immutability properties correctly map to the domain they are securing. A runtime anomaly does not corrupt the governance timeline, and vice versa.
