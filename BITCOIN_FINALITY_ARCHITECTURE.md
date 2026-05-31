# Bitcoin Trust Finality Layer — Architecture & Readiness Review

> Phase 7H deliverable. This document classifies the PQ-RASCV Bitcoin anchoring
> subsystem (verification path, anchoring path, trust assumptions, attack
> surfaces, operational model) and benchmarks it against comparable transparency
> / timestamping systems. It describes what the code **does** and is explicit
> about what it does **not** yet do. No marketing claims.

## 1. Subsystem shape

Two crates, deliberately split by trust and `no_std` boundary:

| Crate (package) | Directory | Role | Build |
|---|---|---|---|
| `pqrascv-bitcoin-anchor` | `crates/bitcoin-anchor` | **Commitment + verification core.** Merkle aggregation, `AnchorCommitment` (OP_RETURN format), `SpvVerifier`/`InclusionProof`, artifact aggregators. | `no_std`, no network, no heavy deps |
| `pqrascv-bitcoin-broadcast` | `crates/pqrascv-bitcoin-anchor` | **Network-facing lifecycle.** AnchorBuilder, Broadcaster, HeaderOracle, MultiSourceHeaderOracle, AnchorLifecycle, finality artifacts. | `std`, rust-bitcoin 0.32, optional live HTTP backends |

The core never depends on the network crate. Verifiers can embed the `no_std`
core alone; only the party that *creates* and *tracks* anchors needs the
lifecycle crate.

## 2. Verification path

```
quote ──SHA3-256──► MerkleAggregator ──► PQ-RASCV root
                                            │ (committed in OP_RETURN)
InclusionProof { block_height, block_header, tx_merkle_path,
                 pqrascv_merkle_root, quote_merkle_path }
                                            │
HeaderOracle (local PoW/continuity/difficulty)        ← closes the trust gap
   └─ MultiSourceHeaderOracle (quorum, eclipse, fail-closed)
                                            │
AnchorLifecycle::verify_anchor ──► SpvVerifier::verify ──► Ok(block_height)
```

- **SPV proof** (`proof.rs`): verifies the tx-to-block Merkle path, the block
  header's Merkle-root consistency, the PQ-RASCV quote Merkle path (RFC-6962
  leaf hashing), proof-of-work against a configured max target, and a minimum
  confirmation depth.
- **Header trust (7C, `oracle.rs`)**: `validate_chain` enforces, *without
  trusting the caller*, that every header meets its own PoW target, links to its
  predecessor (`prev_blockhash`), and keeps difficulty (`nBits`) stable within
  each 2016-block retarget period. All header/PoW math is rust-bitcoin's.
- **Independent chain trust (7D, `multi_source.rs`)**: `MultiSourceHeaderOracle`
  requires a quorum of sources to agree on the header at a height, flags
  divergent/eclipsed sources, and **fails closed** (`NoQuorum`) on a split
  rather than silently choosing a chain.
- **Trust binding (7E, `lifecycle.rs`)**: `verify_anchor` derives the chain tip
  from the validated oracle (not a caller assertion) and rejects any proof whose
  `block_header` does not byte-match the oracle's header at the proof height
  (`HeaderMismatch`) before running SPV. This is what turns "verify against
  whatever header you were handed" into "verify against the chain we validated."

## 3. Anchoring path

```
artifact root (attestation batch / provenance / federation checkpoint /
               trust-anchor rollover)
        │
AnchorCommitment ("PQRASCV" || 0x02 || root[32], 40-byte OP_RETURN)
        │
AnchorBuilder::build_unsigned ──► unsigned bitcoin::Transaction (OP_RETURN last)
        │  (caller's external wallet funds + signs — NON-CUSTODIAL)
Broadcaster ──► txid   (idempotent submit, bounded transient-only retry)
        │
AnchorLifecycle::{broadcast_anchor, track_anchor, wait_for_confirmations}
```

- **7A AnchorBuilder** (`builder.rs`): deterministic, non-custodial. Produces the
  OP_RETURN `TxOut` and an **unsigned** transaction from caller-supplied inputs
  and change; never holds keys, funds, or signs. OP_RETURN is always the last
  output for a stable vout. Artifact helpers (`anchor_attestation_batch`,
  `anchor_provenance`, `anchor_federation_checkpoint`,
  `anchor_trust_anchor_rollover`) funnel to one path.
- **7B Broadcaster** (`broadcast.rs`): trait with bounded, transient-only retry
  and an **idempotency contract** (re-broadcasting a known tx returns the same
  txid, not an error). Reference backends — Bitcoin Core RPC, Esplora REST,
  Electrum — live behind the `live-network` feature and environment variables; a
  `MockBroadcaster` exercises the contract deterministically with no network.
- **7E Lifecycle** (`lifecycle.rs`): `create_anchor` / `broadcast_anchor` /
  `track_anchor` / `wait_for_confirmations` / `verify_anchor`, generic over the
  broadcaster and oracle.
- **7F/7G Finality** (`finality.rs`): `FederationCheckpoint` (chained governance
  history) and `ProvenanceAnchor` (firmware-identity finality) reduce to a
  domain-separated SHA3-256 root and anchor via `create_anchor_for`.

## 4. Trust assumptions

| # | Assumption | Basis / mitigation |
|---|---|---|
| T1 | Bitcoin proof-of-work makes deep-confirmed history practically immutable. | Foundational; confirmation-depth policy (`min_confirmations`) sets the cost of a reorg. |
| T2 | A *quorum* of header sources is not simultaneously controlled by the attacker. | `MultiSourceHeaderOracle`; below quorum it fails closed rather than trusting a minority. |
| T3 | Header validity is checked locally, not trusted from a source. | `validate_chain` (PoW + continuity + within-period difficulty). |
| T4 | The anchoring party controls its own funding wallet. | Non-custodial: the subsystem builds unsigned txs only; key custody is the operator's. |
| T5 | OP_RETURN data (40 bytes) is carried by miners. | Within standardness limits (80 bytes); a single OP_RETURN output. |

## 5. Attack surfaces

- **Eclipse / fake chain** → `MultiSourceHeaderOracle` quorum + divergence
  flagging + fail-closed. A single malicious source cannot carry a decision when
  quorum > 1.
- **Forged / low-work headers** → `validate_chain` rejects any header whose hash
  exceeds its target, or that breaks continuity, or that changes difficulty
  mid-period.
- **Forged inclusion proof** → `verify_anchor` binds the proof's header to the
  validated chain (`HeaderMismatch`); the SPV path independently checks both
  Merkle trees and the OP_RETURN commitment.
- **Broadcast censorship** → multiple independent backends (Core/Esplora/Electrum)
  and retry; the operator can submit through any path.
- **Reorg** → mitigated by confirmation depth; shallow anchors are explicitly
  not final. `track_anchor` returns 0 confirmations until the tip reaches the block.
- **Commitment collision across artifact kinds** → domain-separated SHA3-256
  tags (`pqrascv-fed-checkpoint-v1`, `pqrascv-provenance-v1`).
- **Malleability / txid prediction** → for SegWit-funded inputs the legacy txid
  is stable across signing; for legacy inputs a scriptSig changes the txid (the
  builder documents this).

### Known gaps (honest)

- **Difficulty retarget value** is not recomputed: `validate_chain` enforces
  difficulty *stability within a period* and that each header meets its claimed
  target, but does not yet verify that a boundary's new target is the
  arithmetically correct retarget (timespan / median-time-past rules). A forged
  chain that respected per-header PoW but used an *invalid retarget* at a 2016
  boundary would not be caught by difficulty rules alone (though its cumulative
  work would still have to exceed the honest chain for T1/T2 to be defeated).
- **Live backends are unit-tested only by contract.** Real
  `sendrawtransaction` / REST / Electrum round-trips, real "already-known"
  responses, real fee values, and real header retrieval are exercised only with
  `--features live-network` against a configured node; the default test suite
  uses mocks/fixtures and makes no network calls.
- **Idempotency detection is heuristic** per backend (substring match on
  "already known" responses); the locally-recomputed txid is never trusted from
  the server.
- **BIP157/158 compact-filter oracle** is not implemented (the Core/Esplora/
  Electrum oracles cover the requirement).
- **ABI/encoding fidelity** for live header/tx round-trips should be confirmed
  against a real node before production sign-off.

## 6. Operational model

- **Anchoring**: the operator runs (or points at) a Bitcoin Core node, Esplora,
  or Electrum endpoint, holds a funding wallet *outside* this subsystem, and uses
  `AnchorLifecycle` to build → fund/sign (external) → broadcast → track. No
  custodial keys live in PQ-RASCV.
- **Verifying**: any party with the `no_std` core, an `InclusionProof`, and a
  trusted header view (ideally a `MultiSourceHeaderOracle`) can verify offline.
- **Evidence retention**: anchors are immutable and offline-verifiable; a stored
  `InclusionProof` plus the Bitcoin headers is sufficient to re-prove inclusion
  indefinitely, surviving PKI rotation, vendor disappearance, and infrastructure
  migration (the motivation for 7G).

## 7. Comparison with related systems

| System | Mechanism | Relationship to this subsystem |
|---|---|---|
| **OpenTimestamps** | OP_RETURN commitment of a Merkle root via public calendar servers. | Closest analogue. PQ-RASCV is **self-hosted** (no calendar dependency), **artifact-agnostic**, and **non-custodial**, and additionally validates headers locally + cross-source. It does not (yet) implement OTS's calendar aggregation or `.ots` interchange format. |
| **Certificate Transparency** | Append-only Merkle log on **trusted** logs + gossip/SCTs. | CT trusts log operators (with detectability); Bitcoin substitutes decentralized PoW immutability for trusted-log + auditor gossip. PQ-RASCV's Merkle commitment is conceptually a CT-style leaf, anchored to Bitcoin rather than a log. |
| **Sigstore / Rekor** | Transparency log for signing events (already integrated elsewhere in PQ-RASCV). | Complementary: Rekor gives fast inclusion + monitor-based detection; Bitcoin anchoring gives the deepest, slowest, hardest-to-rewrite layer. A root can be in **both**. |
| **Enterprise evidence retention** | WORM storage, notarization, long-term audit. | Bitcoin anchoring provides decentralized WORM semantics with offline verifiability and no dependence on a single retention vendor. |

## 8. Readiness classification

| Aspect | Status |
|---|---|
| Verification logic (SPV, header validation, multi-source) | **Production-correct logic**, unit-tested; consensus math delegated to rust-bitcoin. |
| Anchoring logic (builder, lifecycle, finality) | **Production-correct logic**, unit-tested; non-custodial by construction. |
| Live network backends | **Reference-quality**, contract-tested; require live-node validation before production sign-off. |
| Difficulty-retarget completeness | **Partial** (stability enforced; retarget value not recomputed). |
| Real-vector fidelity | **Pending** (synthetic/fixture headers; confirm against a real node). |

**Conclusion.** The subsystem now spans the full lifecycle — commitment,
deterministic non-custodial transaction construction, idempotent broadcast,
locally-validated and cross-checked header synchronization, confirmation
tracking, and trust-bound SPV verification — plus governance and provenance
finality. Its *logic* is at Tier-1 quality and is the appropriate long-term home
for immutable PQ-RASCV evidence, alongside the Verifier, Policy Engine, and
ML-DSA core. The remaining work to reach Tier-1 *operational* sign-off is
empirical, not architectural: live-node validation of the backends and a
real-attestation-vector check of header/tx encoding, plus (optionally) full
difficulty-retarget verification and a BIP157/158 oracle.

## 9. Source map

- Verification core: `crates/bitcoin-anchor/src/{proof,merkle,lib}.rs`
- Build/broadcast: `crates/pqrascv-bitcoin-anchor/src/{builder,broadcast,backends}.rs` (commit `33872fb`)
- Header oracles: `crates/pqrascv-bitcoin-anchor/src/{oracle,multi_source}.rs` (commit `df4ab55`)
- Lifecycle: `crates/pqrascv-bitcoin-anchor/src/lifecycle.rs`
- Finality artifacts: `crates/pqrascv-bitcoin-anchor/src/finality.rs`
