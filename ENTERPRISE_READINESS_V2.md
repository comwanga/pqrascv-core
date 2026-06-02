# PQ-RASCV Enterprise Readiness Re-Audit (V2)

> Phase 8 deliverable. Per-subsystem maturity assessment using **only** evidence
> from source code and tests in this repository. No marketing, no speculation.
> Scores reflect what the code and test suite demonstrate as of this audit.
>
> This V2 supersedes the earlier readiness audit and reflects the hardening done
> in Phases 1–7 of this program (crypto-migration readiness, federation
> cryptographic authentication, hardware-attestation chain verification,
> distributed replay protection, enterprise PKI operations, keyd hardening, and
> the Bitcoin Trust Finality Layer).

## Classification scale

| Level | Meaning (evidence-based) |
|---|---|
| **Production Ready** | Complete, no stubs; cryptographically/structurally correct; strong adversarial test coverage; safe error handling. |
| **Pilot Ready** | Complete and sound logic; a bounded gap remains (live-environment validation, observability, real vendor vectors, or platform-gated test execution). |
| **Experimental** | Feature-complete but under-tested, or missing operational hooks needed for production. |
| **Research** | Prototype / not yet complete. |

## Test inventory (source `#[test]` counts)

| Crate | Tests | Notes |
|---|---:|---|
| `pqrascv-core` | 214 | crypto, PKI, nonce, quote, provenance, backends |
| `pqrascv-hardware` | 211 | federation, consensus, policy engine, TPM |
| `bitcoin-anchor` (core) | 45 | SPV verify, merkle, artifact aggregators |
| `pqrascv-bitcoin-broadcast` | 28 | builder/broadcast/oracle/lifecycle/finality |
| `pqrascv-keyd` | 32 | ACL/audit/usage (unix-gated execution) |
| `verifier` | 24 | 58% adversarial |
| `pqrascv-sigstore-client` | 13 | Fulcio/Rekor client |
| `pqrascv-nonce-backends` | 8 | conformance + adversarial |
| `pqrascv-ffi` | 5 | pointer/tamper/null |
| `pqrascv-python` | 5 | dual-layer |
| `cli` | 0 | **no automated tests** |

Verification-assurance assets (preservation list): **4 Kani proofs**
(`kani_proofs.rs`), **7 fuzz targets** (`cbor_parser`, `pki_chain`, `policy_eval`,
`provenance_bundle`, `federation`, `quote_roundtrip`, `bitcoin_node`).

## Per-subsystem scorecard

| Subsystem | Technical | Security | Operational | Enterprise |
|---|---|---|---|---|
| ML-DSA cryptographic core | Production | Production | Pilot | **Production** |
| Verifier pipeline | Production | Production | Experimental | **Pilot** |
| Policy Engine v2 | Production | Production | Pilot | **Pilot** |
| VerifiedProvenance + Sigstore verify | Production | Production¹ | Pilot | **Pilot** |
| Sigstore client (Fulcio/Rekor) | Production | Pilot | Experimental | **Pilot** |
| PKI subsystem | Production | Production | Pilot² | **Pilot** |
| Hardware attestation (TPM/SEV-SNP/TDX) | Production³ | Production³ | Pilot | **Pilot** |
| Federation / distributed consensus | Production | Production⁴ | Pilot | **Pilot** |
| Replay protection (nonce + backends) | Production | Production | Pilot⁵ | **Pilot** |
| keyd (key daemon) | Pilot⁶ | Pilot | Pilot | **Pilot** |
| Bitcoin Trust Finality Layer | Production³ | Production³ | Pilot⁵ | **Pilot** |
| FFI (C ABI) | Production | Production | Pilot | **Pilot** |
| Python bindings | Pilot | Production | Pilot | **Pilot** |
| CLI | Pilot | Pilot | Experimental | **Experimental** |

¹ scoped (1-hop Fulcio, SET-based Rekor — documented). ² HSM is a trait + software
reference; real-HSM integration pending. ³ verification *logic* production-correct;
real-vendor-vector / live-node validation pending. ⁴ string-identity gap closed in
Phase 2. ⁵ live Redis/Postgres / Bitcoin-node round-trips contract-tested, not
exercised live here. ⁶ unix-only; tests execute on CI's Linux leg, not on the
Windows audit host.

---

## Subsystem detail

### ML-DSA cryptographic core (`pqrascv-core`: crypto, cose_sign, quote)
- **Strengths:** ML-DSA-65 (FIPS 204) with domain-separated signing contexts; COSE
  Sign1 envelopes; constant-time comparisons (`subtle`); zeroize-on-drop seeds;
  crypto-migration readiness locked by `crypto_migration_readiness.rs` (Phase 1);
  4 Kani proofs; algorithm-agnostic `pub_key_id`.
- **Blockers:** none material. Library has no logging by design.
- **Roadmap:** execute the documented migration compatibility matrix when a
  successor parameter set is adopted.

### Verifier pipeline (`verifier`)
- **Strengths:** complete multi-path verification (quote / PKI / trust-store /
  Sigstore), constant-time nonce check, 24 tests (58% adversarial), no stubs.
- **Blockers:** **no observability** (zero logging/metrics); **replay protection is
  the caller's responsibility** (verifier does not consume the nonce ledger) — a
  forgotten `consume()` silently permits replay.
- **Roadmap:** add structured tracing; document/scaffold the mandatory
  ledger-consume step; add CBOR/cert fuzzing.

### Policy Engine v2 (`pqrascv-hardware::policy`)
- **Strengths:** domain-separated evaluators; exhaustive rule coverage guarded by a
  defensive `unreachable!`; `policy_eval` fuzz target; production preset enforces
  protocol version, RoT, RTC, SLSA level.
- **Blockers:** operational config surface (rule authoring/versioning) is code-driven.
- **Roadmap:** externalized, signed policy bundles (a federation-anchored variant
  already exists via `policy_federation`).

### VerifiedProvenance + Sigstore verification (`pqrascv-core::provenance_v2`)
- **Strengths:** 8-condition Provenance Enforcement Invariant, all implemented
  (predicate hash + CI ECDSA, Fulcio chain + temporal validity, OIDC allowlist,
  Rekor body binding + SET + time bounds, artifact↔firmware binding);
  `provenance_bundle` fuzz target.
- **Blockers (documented):** Fulcio chain is **1-hop** (no intermediate CA); Rekor
  inclusion is **SET-based** (no Merkle tree path); artifact names canonicalized to
  `firmware`/`firmware.bin`.
- **Roadmap:** intermediate-CA support if Fulcio adopts it; optional Merkle-path
  verification for Rekor.

### Sigstore client (`pqrascv-sigstore-client`)
- **Strengths:** OIDC token CR/LF/NUL injection guard; strict PEM-type checking;
  clear error taxonomy; bounded HTTP timeouts; mockito-backed tests.
- **Blockers:** no retry/backoff, no rate limiting, no observability; this crate
  performs no signature/chain verification (correctly delegated to the verifier).
- **Roadmap:** retry/backoff + structured logging before high-volume CI use.

### PKI subsystem (`pqrascv-core::pki` + Phase 5)
- **Strengths:** ML-DSA cert chain + hardware-identity binding; **type-state CRL**
  (`verify()` → `VerifiedRevocationList`; deprecated unverified `is_revoked`);
  `KeyProvider`/HSM trait + software reference impl; CA key-rollover and
  trust-anchor-rotation with dual-trust overlap windows; revocation carry-forward;
  `PKI_OPERATIONS.md`; `pki_chain` fuzz target.
- **Blockers:** HSM is a trait + software provider — **no real PKCS#11 module**
  integrated (by design); software provider is not a security boundary.
- **Roadmap:** a `cryptoki`-backed `KeyProvider` validated against SoftHSM.

### Hardware attestation (`pqrascv-core::backends`, `pqrascv-hardware::tpm_verify`)
- **Strengths:** TPM AK-quote signature verified; SEV-SNP report ECDSA-P384 +
  ARK→ASK→VCEK RSA-PSS chain with constant-time root pin (Phase 3); TDX DCAP-v4
  quote + QE binding + PCK chain to Intel SGX Root (Phase 3); adversarial tests
  (forged/expired/wrong-root/broken-chain) for both.
- **Blockers (documented):** RSASSA-PSS params not parsed (assumed); cert extensions
  (BasicConstraints/KeyUsage, AMD TCB, Intel collateral) not checked; ABI offsets
  and PSS salt **need a real vendor attestation vector**; live `cert_data` is PEM
  (verifier standardizes on DER-concatenated).
- **Roadmap:** real-vector confirmation; extension + TCB/QE-identity checks.

### Federation / distributed consensus (`pqrascv-hardware`)
- **Strengths:** **cryptographic authentication of all trust mutations** (Phase 2):
  signed policy-epoch approvals, consensus votes, Byzantine quorum certificates,
  and temporal-ambiguity observer evidence — unsigned/forged/replayed/non-member
  mutations rejected; `federation` fuzz target.
- **Blockers:** none material at the subsystem boundary; observability is minimal.
- **Roadmap:** operator-facing audit surface for governance decisions.

### Replay protection (`pqrascv-core::nonce` + `pqrascv-nonce-backends`)
- **Strengths:** sync no_std `NonceLedger` trait with TTL + crash-recovery contract
  (Phase 4); Redis (`SET NX EX`) and Postgres (`INSERT … ON CONFLICT … WHERE
  expired`) reference backends with atomic single-use; contract suite run against an
  in-memory fake.
- **Blockers:** live Redis/Postgres atomicity, TTL reclaim, and distributed-replay
  behavior are exercised only behind `integration-tests` + env vars; crash recovery
  depends on backend durability.
- **Roadmap:** a CI lane with ephemeral Redis/Postgres.

### keyd (`pqrascv-keyd`)
- **Strengths:** per-key ACLs (default-deny), injectable append-only audit log,
  per-key usage tracking, socket-free `Authorizer` (unit-testable); Unix-socket-only,
  no network exposure; additive wire-compatible `Denied` status.
- **Blockers:** **unix-only** — tests execute on CI's Linux leg, not the Windows
  audit host (verified compile + clippy + test-compile cross-target).
- **Roadmap:** confirm test execution on the Linux CI leg; optional capability tokens
  beyond UID.

### Bitcoin Trust Finality Layer (`bitcoin-anchor` + `pqrascv-bitcoin-broadcast`)
- **Strengths:** full lifecycle (Phase 7) — non-custodial unsigned-tx `AnchorBuilder`,
  idempotent retrying `Broadcaster` (Core/Esplora/Electrum), `HeaderOracle` with local
  PoW/continuity/difficulty validation, `MultiSourceHeaderOracle` (quorum + eclipse +
  fail-closed), `AnchorLifecycle` whose `verify_anchor` binds proofs to the validated
  chain, and federation/provenance finality; rust-bitcoin for consensus math;
  `bitcoin_node` fuzz target; see `BITCOIN_FINALITY_ARCHITECTURE.md`.
- **Blockers (documented):** difficulty-retarget *value* not recomputed (only
  within-period stability); live backends contract-tested only; idempotency detection
  heuristic; no BIP157/158 oracle.
- **Roadmap:** live-node validation; full retarget verification; compact-filter oracle.

### FFI / Python / CLI
- **FFI:** exemplary pointer/length validation, no panics at the C boundary, adversarial
  tests (null/buffer/tamper). Gap: no C-side integration harness; `build.rs` cbindgen
  load can panic. **Pilot.**
- **Python:** dual-layer (pure-Rust inner testable), seeds `[REDACTED]` in Debug,
  `PyResult` error mapping. Gap: no Python-side tests. **Pilot.**
- **CLI:** complete subcommands, strong input validation (hex/nonce/injection-safe),
  capability gating (`--software-rot-acknowledged`). Gap: **0 automated tests**.
  **Experimental.**

---

## Program-level synthesis

### Top strengths (evidence-based)
1. **Cryptographic trust boundaries are now authenticated, not assumed.** Federation
   mutations (Phase 2) and hardware attestation chains (Phase 3) moved from "parsed"
   to "cryptographically verified," each with forged/replayed/expired/wrong-root tests.
2. **Deep, adversarial test suite** — 580+ unit tests, 58% adversarial in the verifier,
   plus 4 Kani proofs and 7 fuzz targets across the highest-risk parsers.
3. **Safe boundaries** — constant-time comparisons, zeroize, type-state CRL, validated
   FFI, non-custodial Bitcoin anchoring.
4. **Operational tooling added** — PKI rollover/rotation + `PKI_OPERATIONS.md`,
   distributed replay backends, keyd ACL/audit/usage, full Bitcoin anchor lifecycle.

### Top blockers (to reach uniform Production Ready)
1. **Operational observability** is the most common gap — verifier and Sigstore client
   have no structured logging/metrics; several subsystems are "operationally opaque."
2. **Live-environment validation** is pending for everything network/hardware-facing:
   real Redis/Postgres, real Bitcoin nodes, and real AMD/Intel attestation vectors.
   The *logic* is tested; the *wire/vendor fidelity* is not yet confirmed here.
3. **Replay protection is caller-enforced** in the verifier — a sharp edge that should
   be made harder to misuse.
4. **HSM is trait-only** — production CA key custody needs a real PKCS#11 backend.
5. **CLI has no tests**; FFI/Python lack cross-language integration tests.

### Next roadmap (priority order, from the evidence)
1. Add structured tracing + metrics to the verifier and Sigstore client; make the
   verifier's nonce-ledger consume non-optional or loudly guarded.
2. Stand up CI lanes that exercise the live paths: ephemeral Redis/Postgres for nonce
   backends, regtest/signet for the Bitcoin lifecycle, and (where obtainable) real
   AMD/Intel attestation vectors for SEV-SNP/TDX.
3. Harden hardware attestation: parse/assert PSS params, validate cert extensions and
   TCB/QE identity, support PEM `cert_data`.
4. Integrate a `cryptoki` `KeyProvider` and validate against SoftHSM.
5. Add a CLI test harness and FFI/Python integration tests.
6. Complete Bitcoin difficulty-retarget verification and add a BIP157/158 oracle.

### Verdict
The strategic core — ML-DSA cryptography, verifier pipeline, Policy Engine v2,
VerifiedProvenance, PKI, federation, hardware attestation, and the Bitcoin Trust
Finality Layer — is at **Production-Ready technical and security maturity in logic**,
backed by a substantial adversarial test suite. The gating work to reach uniform
**enterprise** Production Ready is predominantly **operational and empirical**
(observability + live-environment/vendor-vector validation), not architectural. The
preservation-list assets (ML-DSA core, verifier, Policy Engine, provenance, Sigstore,
Bitcoin anchoring, hardware abstraction, Kani, fuzzing, PKI) are all present and, where
this program touched them, materially hardened.
