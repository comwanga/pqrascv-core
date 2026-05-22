# Sovereign Deployment Models

PQ-RASCV supports multiple deployment topologies for sovereign nodes:

## 1. Sovereign Single Node
A node acting as its own primary verifier. While vulnerable to central compromise of the verifier, this model is useful for offline/hardware-wallet setups where ultimate control remains with a single sovereign entity.

## 2. Federated Cluster
A single high-value node continuously verified by a distributed quorum of verifiers. This is the primary target for institutional or federated Bitcoin setups (e.g., Fedimint guardians, Liquid functionaries).

## 3. Airgapped Audit
A deeply isolated node where attestation evidence is manually exported and evaluated on a physically separate, air-gapped verifier machine.

## 4. Hybrid Verifier Mesh
A network of peer verifiers that cross-verify each other's nodes, creating a decentralized web of trust around node integrity.
