# Federation Topology

## Flat vs. Scoped Trust
Early iterations of PQ-RASCV relied on flat federations where all verifiers possessed equal authority. Real-world sovereign deployments require regional, organizational, and logical isolation.

## Topology Model
1. **Root Authority**: Can authorize inter-zone transitions and global governance updates.
2. **Regional Authority**: Authority strictly scoped to a specified `FederationZone`.
3. **Edge Verifier**: Conducts active hardware validation but holds no governance authority.
4. **Observer**: Retains a verifiable copy of the active state and logs for audit purposes without consensus voting power.

## Trust Domains
To prevent unintentional privilege escalation, a verifier's `AuthorityScope` binds its role not just to geographic/logical zones, but to specific evaluation segments (`TrustDomain`s like SecureBoot or HardwareIdentity). A verifier compromised in a specific zone cannot manipulate policy for another zone.
