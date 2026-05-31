# PQ-RASCV Tier-1 Enterprise Hardening & Bitcoin Finality — Program Coordination

> **For agentic workers:** This is a *coordination* document, not an implementation plan. It maps the 8-phase
> program into review-gated sessions and defines the sub-agent fan-out for each. Per-phase implementation plans
> (written with `superpowers:writing-plans`) are authored at the start of each session and executed with
> `superpowers:subagent-driven-development` / `superpowers:executing-plans`.

**Governing rule (from the program spec):** every phase ends with *"Stop and wait for review before proceeding."*
Therefore **sub-agents fan out *within* a session, never across a review gate.** No single autonomous run spans phases.

**Per-phase discipline (every phase, no exceptions):**
`Audit → produce evidence → identify exact files → smallest secure fix → adversarial tests → run affected suites → summarize → STOP for review.`

**Preservation list (never remove, only harden):** ML-DSA core · Verifier pipeline · Policy Engine v2 ·
VerifiedProvenance sealed-token · Sigstore/Rekor/Fulcio · Bitcoin anchoring · Hardware attestation layers ·
Kani suite · Fuzzing suite · PKI subsystem.

---

## Repo grounding (verified 2026-05-30)

| Phase | Primary files / crates | Current state |
|------|------------------------|---------------|
| P1 Crypto migration | `CRYPTO_MIGRATION_PLAN.md` (169 lines), `crates/pqrascv-core/tests/crypto_migration_readiness.rs` | **Already authored, untracked** — needs verify + commit, not authoring |
| P2 Federation auth | `crates/pqrascv-hardware/src/{policy_federation,distributed_consensus,byzantine_quorum,verifier_identity,temporal_ambiguity}.rs` | Present; authenticates by string identity |
| P3 Hardware attestation | `crates/pqrascv-hardware/src/{live_tpm,tpm_verify,tpm_structures}.rs` + SEV-SNP/TDX paths | Present; evidence parsed, not cryptographically verified |
| P4 Distributed replay | `crates/pqrascv-core/src/nonce/mod.rs` (`InMemoryNonceLedger`) | Single-node only |
| P5 PKI ops | PKI subsystem | Needs PKCS#11/HSM hooks, rollover workflows |
| P6 keyd | `crates/keyd` | Pilot-grade; Unix-socket model to preserve |
| P7 Bitcoin finality | `crates/bitcoin-anchor`, `crates/pqrascv-bitcoin-anchor` | Verify path done (SPV/PoW/Merkle/header); anchoring path missing |
| P8 Re-audit | all subsystems | Final, depends on all |

## Dependency graph

```
P1 ─┐
P2 ─┼─(independent subsystems)
P3 ─┤
P4 ─┤
P5 ─┤
P6 ─┘
        P2 + Provenance ──► P7 (7F federation finality, 7G provenance finality)
                                   │
   all of the above ───────────────┴──► P8 (re-audit, strictly last)
```

## Cadence: **Hybrid** (selected)

- **Serialized, careful review** — P2 and P3 (security-critical trust boundaries). One at a time, full review at each ✋.
- **Parallel worktrees** — P4, P5, P6 (independent, lower blast radius). Run concurrently in isolated git worktrees; each still stops at its own ✋.
- **P7** runs after P2 completes (needs federation signing for 7F). Multi-session, internal parallelism only.
- **P8** strictly last.

---

## Session map

### S0 — Pre-flight  *(read-only, ~1 agent)*
- 1 `Explore` agent confirms every phase's named files/symbols exist and reports current implementation state.
- **Gate:** map approved. No code changes.

### S1 — P1 verify & commit  *(no fan-out)*
- Run `cargo test -p pqrascv-core --test crypto_migration_readiness`; review `CRYPTO_MIGRATION_PLAN.md` for the required sections (artifact inventory · key migration · signature migration · rollback · compatibility matrix).
- **Gate ✋:** commit P1 deliverables.

### S2 — P2 Federation authentication  *(serialized)*
- **Audit:** 5 parallel `Explore` agents — one each for `policy_federation`, `distributed_consensus`, `byzantine_quorum`, `verifier_identity`, `temporal_ambiguity`. Each returns: where identity is trusted by string, where mutations are accepted unsigned.
- **Implement (sequential, shared types):** sign approvals · votes · epoch transitions · observer evidence using existing verifier public keys; verify before quorum counting / epoch finalization / ambiguity evaluation; reject unsigned mutations.
- **Adversarial tests:** 4 parallel agents — forged vote · forged approval · forged observer · replayed vote.
- **Gate ✋.**

### S3 — P3 Hardware attestation  *(serialized)*
> **S0 refinement:** TPM AK-signature verification **already exists** at `tpm_verify.rs:96` (behind `tpm-crypto`).
> Only SEV-SNP and TDX are parse-only. TPM agent scope shrinks to *verify/harden existing + add adversarial tests*.
- **3 parallel `general-purpose` agents (independent vendor chains):**
  - **TPM** → *verify existing* AK-signed quote path; add forged/wrong-root tests; confirm feature-gating is correct.
  - **SEV-SNP** → AMD chain ARK→ASK→VCEK/VLEK validation (currently parse-only, `crates/pqrascv-core/src/backends/sevsnp.rs`).
  - **TDX** → Intel quote + PCK chain validation (currently parse-only, `crates/pqrascv-core/src/backends/tdx.rs`).
- Each agent: evidence must be *cryptographically verified, not merely parsed*; adds forged-report · invalid-chain · expired-cert · wrong-root tests.
- **Integration:** I reconcile shared traits, run full `pqrascv-hardware` suite.
- **Gate ✋.**

### S4 — P4 Distributed replay  *(parallel worktree)*
> **S0 refinement:** `NonceLedger` trait **already exists** (`nonce/mod.rs:102-174`, `register`/`consume`). Eviction is
> FIFO-bounded, **not true TTL**. Scope = add TTL semantics + crash-recovery contract to the trait, then backends.
- Extend the existing trait (sequential) — add TTL/expiry + crash-recovery semantics; keep `InMemoryNonceLedger` compatible.
- **2 parallel agents:** Redis backend · PostgreSQL backend. Plus distributed-replay adversarial tests.
- **Gate ✋.**

### S5 — P5 PKI ops + P6 keyd  *(parallel worktrees, 2 branches)*
- **P5 agent:** PKCS#11 abstraction · HSM hooks · key-rollover & trust-anchor-rotation workflows · `PKI_OPERATIONS.md` · tests (root rollover, intermediate rollover, revocation continuity). Do not redesign cert formats.
- **P6 agent:** per-key ACLs · operation audit logs · key-usage tracking · configurable authz; preserve Unix-socket model, **no network exposure**; adversarial tests.
- **Gate ✋ each branch independently.**

### S6 — P7 stages 7A + 7B  *(after P2)*
- `AnchorBuilder` first (sequential): deterministic commitment · OP_RETURN · commitment versioning · CBOR compat; anchor attestation / provenance / federation-checkpoint / trust-anchor-rollover artifacts.
- Then **3 parallel agents:** Bitcoin Core RPC · Electrum · Esplora broadcasters (idempotent submit, retry, fee-estimation hooks; **no wallet, no custody**).
- **Gate ✋.**

### S7 — P7 stages 7C + 7D
- `HeaderOracle` trait + reference impls (Core · Electrum · BIP157/158 · Esplora) — local PoW/difficulty/continuity validation; verification no longer trusts caller-supplied headers.
- `MultiSourceHeaderOracle` — cross-check height/tip/continuity, detect inconsistent sources & eclipse indicators, **fail closed**.
- **Gate ✋.**

### S8 — P7 stages 7E + 7F + 7G
- Lifecycle API (sequential): `create_anchor` · `broadcast_anchor` · `track_anchor` · `verify_anchor` · `wait_for_confirmations`.
- Then 2 parallel agents: federation-checkpoint anchoring (7F) · VerifiedProvenance anchoring (7G).
- **Gate ✋.**

### S9 — P7 stage 7H
- 1 author agent writes `BITCOIN_FINALITY_ARCHITECTURE.md` (verification path · anchoring path · trust assumptions · attack surfaces · operational model; benchmark vs OpenTimestamps / Sigstore transparency / Certificate Transparency / evidence-retention).
- 1 reviewer agent audits the doc against source. **Gate ✋.**

### S10 — P8 Enterprise re-audit  *(read-only fan-out)*
- **N parallel `Explore` agents, one per subsystem.** Each scores Technical / Security / Operational / Enterprise maturity (Production / Pilot / Experimental / Research) **from source code and tests only** — no speculation.
- I assemble `ENTERPRISE_READINESS_V2.md`: per-subsystem scores · top strengths · top blockers · next roadmap.
- **Gate ✋:** final report.

---

## Sub-agent fan-out rule (applies to every session)

Every phase has the same shape, so parallelize the read-only bookends and serialize the middle:

| Step | Mode | Agent type |
|------|------|-----------|
| Audit | **parallel**, one per file/subsystem (no shared state) | `Explore` (read-only) |
| Implementation | **sequential** for shared types, then **parallel** one-agent-per-independent-file | `general-purpose` |
| Adversarial tests | **parallel**, one per attack class (forged/replayed/expired/wrong-root) | `general-purpose` |
| Run suites + summarize | inline (coordinator) | — |
| Stop for review | inline | — |

**Constraints in every agent brief:** self-contained context (no inherited history) · explicit scope (named files only) · "do not touch other subsystems" · required return = root-cause + changes + test results. Agents never cross a ✋ gate.

## Progress tracker

- [x] S0 Pre-flight map — **done 2026-05-30.** All 5 baseline assumptions confirmed. Refinements: P3 TPM already verified (SEV-SNP/TDX remain); P4 trait already exists (needs TTL + backends). New risks logged: P5 zero PKI ops tooling, P6 keyd UID-only + no audit log.
- [x] S1 P1 verify & commit — **done 2026-05-30.** 7 readiness tests pass; plan has all 5 required sections. Committed as `051a32a`.
- [x] S2 P2 Federation auth ✋ — **done 2026-05-30.** New `federation_auth` module (ML-DSA-65 verify + domain-separated canonical payloads) threaded into all 5 modules. Additive signed path: unsigned mutations never count. Adversarial tests (forged/wrong-key/replayed/unsigned) across approvals, votes, quorum certs, observer evidence. Full hardware suite 211 pass; workspace check clean. Pre-existing clippy debt in 4 unrelated files flagged (not introduced here).
- [x] S3 P3 Hardware attestation ✋ — **done.** All three vendor paths now cryptographically verify (not just parse): **TPM** AK-quote sig pre-existing (S0); **SEV-SNP** report ECDSA-P384 sig (`11cad3e`) + VCEK→ASK→ARK chain with ARK pin / RSA-PSS-SHA384 / validity (`b684cd1`), 21 tests; **TDX** DCAP v4 quote sig + QE binding + PCK chain→Intel SGX Root CA with root pin (`d0f3e9c`), 17 tests. All clippy-clean. Synthetic vendor PKIs, no new deps for TDX (p384/rsa added for SEV-SNP). Documented production follow-ups (per vendor): parse/assert PSS params; PEM cert_data armor-stripping for real Intel quotes; TCB/QE-identity + cert-extension checks; real-vector ABI/offset confirmation. These are flagged for the Phase 8 re-audit.
- [ ] S4 P4 Distributed replay ✋
- [ ] S5 P5 PKI + P6 keyd ✋✋
- [ ] S6 P7 7A+7B ✋
- [ ] S7 P7 7C+7D ✋
- [ ] S8 P7 7E+7F+7G ✋
- [ ] S9 P7 7H ✋
- [ ] S10 P8 Re-audit ✋
