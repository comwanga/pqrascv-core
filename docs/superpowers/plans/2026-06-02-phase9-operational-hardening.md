# Phase 9 — Operational & Empirical Production Sign-off

> Follows the completed 8-phase Tier-1 program (merged to `main`). The
> `ENTERPRISE_READINESS_V2.md` audit established that the strategic core is
> Production-Ready in *logic and security*; the remaining gap to uniform
> **enterprise** readiness is **operational and empirical, not architectural**.
> This phase closes it. Branch: `feat/operational-hardening`.

## Goal

Lift each subsystem's **Operational** and **Enterprise** maturity from
Pilot/Experimental → Production by adding observability and live-environment
validation. No new architecture.

## Workstreams

| # | Workstream | Host-feasibility | Status |
|---|-----------|------------------|--------|
| 1 | **Observability + replay-safe verifier** — `tracing` in verifier & sigstore client; verifier consumes the nonce ledger so replay can't be skipped | Windows-feasible | **✅ done** |
| 2 | **Live CI lanes** — ephemeral Redis/Postgres for `pqrascv-nonce-backends`; Bitcoin regtest/signet for the anchor lifecycle | needs Linux + services | pending |
| 3 | **Hardware-attestation fidelity** — parse/assert RSASSA-PSS params; validate cert extensions (BasicConstraints/KeyUsage, AMD TCB, Intel QE); PEM `cert_data`; confirm ABI vs a real vendor vector | code/synthetic: Windows-feasible; real-vector: blocked | pending |
| 4 | **HSM** — a `cryptoki` (PKCS#11) `KeyProvider` validated against SoftHSM | needs SoftHSM | pending |
| 5 | **Test-coverage gaps** — CLI test harness (0 tests today); FFI/Python cross-language integration tests | CLI: Windows-feasible; bindings: partial | pending |
| 6 | **Bitcoin completeness** — full difficulty-retarget recomputation; BIP157/158 oracle | Windows-feasible | pending |

## Sequencing notes

- #1 and #3-code are highest-leverage (close the two most-cited V2 gaps —
  opacity and vendor fidelity) and are mostly independent.
- #2/#4 require infra/CI provisioning; #5/#6 are lower-risk.
- **Execution-environment caveat:** #2-#4 (and parts of #5) need Linux/live
  environments and real vendor vectors — the exact lanes the Windows dev/audit
  host cannot exercise (which is how the keyd / fuzz / cargo-deny CI breaks in
  the previous phase slipped past local checks). These should run with execution
  on a Linux CI runner from the start, not Windows-host verification.

## Workstream #1 — done

- `verify_cbor_consuming` / `verify_with_challenge_consuming<L: NonceLedger>` —
  verify then consume the nonce in one call; consume runs only after a
  successful verify; a replay fails closed (`InvalidNonce`). Non-consuming docs
  steer callers to the safe variants. (commit: replay-safe verifier)
- `tracing` instrumentation: verifier's central `verify_quote`
  (`instrument(skip_all, err)` + success debug; replay warn in the consuming
  path) and the sigstore client's four request functions. (commit: observability)
- Verified: verifier 26 tests, sigstore 13 tests, clippy clean, fmt clean.

## Progress tracker

- [x] #1 Observability + replay-safe verifier
- [ ] #2 Live CI lanes (Redis/Postgres/Bitcoin)
- [~] #3 Hardware-attestation vendor fidelity — **partial.** TDX PEM `cert_data` support **done** (real Intel quotes parse). Still pending: SEV-SNP RSASSA-PSS param parsing/assertion; BasicConstraints/KeyUsage + AMD-TCB/Intel-QE-identity extension checks; real-vendor-vector confirmation (blocked on a real AMD/Intel quote).
- [ ] #4 HSM (cryptoki/SoftHSM)
- [ ] #5 CLI + binding test coverage
- [ ] #6 Bitcoin retarget + BIP157/158
