# Cryptographic Migration Plan

**Status:** Migration-readiness baseline (Phase 1 of the Enterprise Hardening Program)
**Scope:** Readiness only. This document does **not** change any algorithm. It records
the exact migration-sensitive surface so that a future move off release-candidate
post-quantum crates (or to a new parameter set) is a controlled, auditable, reversible
operation rather than a breaking change.

**Primary driver:** The attestation trust root depends on two pre-1.0 / release-candidate
crates:

| Crate | Pinned version | Role | Stable target |
|-------|----------------|------|---------------|
| `ml-dsa` | `=0.1.0-rc.8` | ML-DSA-65 (FIPS 204) sign/verify/keygen — **trust root** | first stable `ml-dsa` ≥ `0.1.0` |
| `ml-kem` | `=0.3.2` | ML-KEM-1024 (FIPS 203) federation transport KEM — **not** the attestation root | stable `ml-kem` ≥ `1.0` |

Both are **exact-pinned** (`=`) in `Cargo.toml`, which already prevents silent upgrades.
The algorithms themselves (ML-DSA-65, ML-KEM-1024) are FIPS-final; only the *implementation
crates* are pre-stable. A migration is therefore expected to be an **implementation swap at
the same parameter set**, with the rarer possibility of a parameter-set change.

---

## 1. Artifact Inventory

Every artifact that is persisted, transmitted, or signed, and whether it can be
distinguished and migrated.

### 1.1 Signed wire artifacts

| Artifact | Source | Format | Version field | Algorithm discriminator | Migration class |
|----------|--------|--------|---------------|-------------------------|-----------------|
| `QuoteBody` / `AttestationQuote` | `crates/pqrascv-core/src/quote.rs` | CBOR | `version: u16` = `PROTOCOL_VERSION` (2), verifier-enforced | **implicit only** (signature length 3309, VK id) | A — re-issuable |
| `DeviceCertificate` | `crates/pqrascv-core/src/pki/mod.rs` | CBOR | `version: u8` = `CERT_VERSION` (3) | **implicit only** (subject_key length 1952) | B — re-issued by CA |
| `RevocationList` (CRL) | `crates/pqrascv-core/src/pki/revocation.rs` | CBOR | inherits CRL version | **implicit only** | B — re-issued by CA |
| `CoseSign1` | `crates/pqrascv-core/src/cose_sign.rs` | CBOR (RFC 9052 shape) | protected header | **explicit**: `ML_DSA_65_ALG_ID = -48` | A — best-positioned |

### 1.2 Key material at rest

| Artifact | Source | Format | Version / algorithm header | Migration class |
|----------|--------|--------|----------------------------|-----------------|
| keyd keypair blob | `crates/keyd/src/keystore.rs` | `[seed(32) ‖ vk(1952)] = 1984 B` raw | **NONE** — fixed-length, no header | C — most fragile |
| `SigningKeySeed` (in-memory) | `crates/pqrascv-core/src/crypto.rs` | 32-byte zeroizing wrapper | n/a (ephemeral) | — |

### 1.3 Algorithm-agnostic anchors (migration-stable by construction)

| Mechanism | Source | Why it survives migration |
|-----------|--------|---------------------------|
| `pub_key_id(vk)` | `crypto.rs:128` | `SHA3-256(vk_bytes)` — a fingerprint over *whatever* the key bytes are; stable identity primitive independent of signature algorithm |
| Signing-context domain separation | `crypto.rs` (`SIGNING_CONTEXT_*`) | Contexts are algorithm-independent strings; carry forward unchanged |
| Bitcoin OP_RETURN anchor | `bitcoin-anchor/src/lib.rs` | Commits `SHA3-256` Merkle roots, not signatures; algorithm-neutral |

---

## 2. Key Migration Plan

**Goal:** rotate every signing key from the RC-implementation key to a stable-implementation
key **at the same parameter set**, so key *bytes* are unchanged and only the producing/
consuming crate changes.

ML-DSA-65 is a deterministic, standardized encoding (FIPS 204). A stable `ml-dsa` release at
the same parameter set is expected to produce **byte-identical** seeds, verifying keys, and
signatures. The migration is therefore a **library swap, not a key re-generation**, in the
common case.

Procedure (per CA / per device / per keyd store):

1. **Freeze** — record current pinned versions and run the compatibility test suite
   (§ "Tests", below) to capture a golden baseline of sizes and discriminators.
2. **Dual-build verify** — build with the candidate stable crate behind a temporary feature
   and assert: (a) `generate_ml_dsa_keypair` byte-sizes unchanged; (b) a signature produced
   by the RC crate verifies under the stable crate and vice-versa (cross-verification gate).
3. **Roll forward** — bump the pin; the trust root only touches `crypto.rs`, so the blast
   radius is one file plus `kani_proofs.rs`.
4. **Key custody unchanged** — because key bytes are identical at the same parameter set, no
   re-enrollment is required for the byte-compatible case. Re-enrollment is required **only**
   if a parameter set changes (see § 4 rollback / § 5 matrix).

If cross-verification in step 2 fails (encoding drift), the migration escalates to the
**re-issuance path**: CA re-signs device certs (class B), devices re-issue quotes (class A),
keyd re-wraps blobs (class C, see § 3).

---

## 3. Signature & Key-at-Rest Migration Plan

### 3.1 Signatures (classes A/B)

Quotes and certificates carry a **format** version but no explicit **algorithm** ID. Today the
*implicit* discriminator is the signature length (3309 for ML-DSA-65) and VK length (1952).
For a same-parameter-set library swap this is sufficient. For a parameter-set change, the
controlled path is:

- Bump `CERT_VERSION` (u8) and `PROTOCOL_VERSION` (u16) — the verifier already rejects
  mismatched versions (no silent downgrade), so old and new artifacts are cleanly separable.
- The CA issues new-version certificates; verifiers accept both versions during the overlap
  window, then drop the old version.
- `CoseSign1` already carries `ML_DSA_65_ALG_ID`; a new algorithm gets a new alg ID and the
  two coexist without ambiguity. **COSE is the template the other formats should follow if a
  parameter-set migration is ever required.**

### 3.2 Key-at-rest (class C — keyd blob)

The keyd blob (`[seed‖vk] = 1984 B`) is the **only** artifact with no version header. For
migration readiness:

- The fixed length `1984` is currently a load-time invariant (`BLOB_LEN`). A future format
  that prepends a 1-byte version/algorithm tag would change the length, which a loader can
  detect (old length 1984 vs new length 1985). This is the documented, reversible upgrade path.
- **No format change is made in this phase.** The migration plan only requires that the loader
  treat `1984` as "v0 / ML-DSA-65" so a future `1985`-byte "v1" blob is unambiguously
  distinguishable. The regression test added in this phase locks the `1984` invariant so any
  accidental format drift fails loudly.

---

## 4. Rollback Plan

Every step above is reversible:

| Forward step | Rollback |
|--------------|----------|
| Bump `ml-dsa` pin | Revert pin to `=0.1.0-rc.8`; key bytes identical at same parameter set → no data rollback needed |
| Cross-verification gate fails | Abort; do not change the pin; artifacts unchanged |
| Bump `PROTOCOL_VERSION` / `CERT_VERSION` for parameter-set change | Verifier accepts the prior version during the overlap window; revert by re-pointing issuance at the old version (old artifacts still validate) |
| keyd blob v1 (tagged) introduced | v0 (1984 B) loader retained; v1 loader is additive; downgrade = stop issuing v1, keep reading v0 |

**Rollback safety property:** because `pub_key_id` is a SHA3-256 fingerprint independent of
the signature algorithm, device *identity* is stable across any rollback — a rolled-back
verifier still recognizes the same devices.

---

## 5. Compatibility Matrix

| Migration scenario | Key bytes change? | Re-enrollment? | Wire version bump? | Blast radius | Reversible? |
|--------------------|-------------------|----------------|--------------------|--------------|-------------|
| RC → stable `ml-dsa`, **same** parameter set, byte-identical | No | No | No | `crypto.rs`, `kani_proofs.rs` | Yes (revert pin) |
| RC → stable `ml-dsa`, encoding drift | Possibly | Quotes re-issued (A), certs re-signed (B), blobs re-wrapped (C) | Recommended | + CA + keyd | Yes (overlap window) |
| Parameter-set change (e.g. ML-DSA-87) | Yes | Yes (all classes) | **Required** (`PROTOCOL_VERSION`, `CERT_VERSION`, new COSE alg ID) | core + CA + keyd + devices | Yes (dual-version overlap) |
| `ml-kem` swap (transport only) | Transport ephemeral keys only | No (no persisted KEM material in trust root) | No | `pq_transport.rs`, `noise_pqx.rs` | Yes |

**Interpretation:** the expected (and lowest-risk) migration — RC→stable at the same parameter
set — is a one-file dependency bump gated by a cross-verification test, with no key
re-generation and full reversibility. The project is structurally well-positioned for it
because the crypto surface is tiny and isolated.

---

## 6. Readiness Gaps Closed by This Phase

1. **Documented** the full migration-sensitive artifact surface (above).
2. **Locked** the migration-relevant invariants with regression tests (sizes, discriminators,
   algorithm-agnostic identity, COSE alg ID presence, keyd blob length) so any future change
   that would break migration assumptions fails CI immediately — see
   `crates/pqrascv-core/tests/crypto_migration_readiness.rs`.

## 7. Remaining Work (future phases — not done here)

- Optional: add an explicit algorithm-ID byte to `QuoteBody`/`DeviceCertificate` if a
  parameter-set migration is ever scheduled (currently implicit-by-length; deferred to avoid
  architectural churn while no migration is active).
- Optional: introduce a 1-byte versioned keyd blob header (`v1`) when the first format change
  is actually required.

These are intentionally **not** implemented now: there is no active migration, and adding
discriminators preemptively would be churn without a driver. The tests below make the
*current* implicit discriminators explicit and enforced, which is the correct
migration-readiness posture.
