# Cryptographic Stability & Migration Risk

This document covers the stability status of cryptographic dependencies, the
artifacts that are sensitive to breaking changes, and the operational
consequences of upgrading to stable releases.

---

## Status Summary

| Dependency | Pinned version | Upstream status | Stable? |
|------------|---------------|-----------------|---------|
| `ml-dsa`   | `=0.1.0-rc.8` | RustCrypto RC   | **No**  |
| `ml-kem`   | `=0.3.2`      | RustCrypto      | Yes (stable semver) |
| `ciborium` | `0.2`         | CBOR / serde    | Yes     |
| `serde`    | `1`           | stable          | Yes     |

---

## ML-DSA Dependency (`ml-dsa = "=0.1.0-rc.8"`)

### What it is

`ml-dsa` is the RustCrypto implementation of FIPS 204 (ML-DSA, lattice-based
digital signatures). The workspace pins an exact release-candidate version
(`=0.1.0-rc.8`) to ensure reproducible builds.

### Why the RC pin matters

Release candidates are not semver-stable. The RustCrypto project may make
breaking changes — including changes to serialization formats, key encoding, or
API names — between RC versions and the `1.0.0` stable release.

**If the `ml-dsa` crate changes its key or signature encoding between
`0.1.0-rc.8` and `1.0.0`, keys and signatures generated under the RC will
fail to deserialize under the stable release.**

### Migration-sensitive artifacts

The following artifacts are binary-serialized using `ml-dsa` types and would
need re-generation or migration if key/signature encoding changes:

| Artifact | Where produced | Risk |
|----------|---------------|------|
| Verifying key bytes (`[u8; 1952]`) | `generate_ml_dsa_keypair()` in `crypto.rs` | Persisted keys become unreadable |
| Signature bytes (`[u8; 3309]`) | `MlDsaBackend::sign()` in `crypto.rs` | Stored quotes become unverifiable |
| CBOR-encoded `AttestationQuote` | `generate_quote()` | Quote archives span key/sig encoding |
| `VerifierIdentity::public_key` | Any serialized federation state | Federation config would need re-keying |
| `SignatureBytes` in governance records | `GovernanceLog` | Audit trail breaks if sig bytes change |

Sizes as of `ml-dsa = 0.1.0-rc.8`:

```
ML_DSA_65_SEED_SIZE         =   32 bytes
ML_DSA_65_VERIFYING_KEY_SIZE= 1952 bytes
ML_DSA_65_SIGNATURE_SIZE    = 3309 bytes
```

If these constants change in a future release, all binary blobs sized to the
old constants will become structurally invalid.

### What is NOT migration-sensitive

- In-memory computation: signing and verification during a session are not
  affected if the session starts and ends under the same library version.
- The `SigningKeySeed` (32-byte seed) is passed into `MlDsa65::from_seed()`.
  The seed format itself is standard; the risk is in the derived key encoding.

---

## ML-KEM Dependency (`ml-kem = "=0.3.2"`)

`ml-kem` 0.3.x follows standard semver and is considered stable for the
current feature set. The `VerifierIdentity::ml_kem_public_key` field stores
raw key bytes; if the KEM key format changes in a future semver-breaking
release (0.4.x+), stored keys would need migration.

Current exposure is lower than ML-DSA because ML-KEM public keys are used
for session key encapsulation (ephemeral), not long-term identity.

---

## CBOR Serialization (`ciborium = "0.2"`)

All over-the-wire and stored formats (quotes, governance records, federation
state) use CBOR via `ciborium`. The `ciborium` 0.2 series is stable. A
future `ciborium 0.3` with breaking encoding changes would invalidate stored
CBOR blobs, but this risk is low in the near term.

---

## Operational Consequences

### Before deploying in a persistent context

1. **Do not persist ML-DSA keys or signatures** across a `ml-dsa` version
   boundary without a planned migration procedure.
2. **Track the ml-dsa RustCrypto changelog** before upgrading. The upgrade
   path from RC to stable is currently unknown. Encoding stability is not
   guaranteed.
3. **Plan for re-keying:** if the encoding changes, every device that holds a
   long-term ML-DSA signing key must regenerate its key pair and re-enroll
   with the federation.
4. **Quote archive compatibility:** stored CBOR quotes contain raw signature
   bytes. If the `ML_DSA_65_SIGNATURE_SIZE` constant or encoding changes,
   historical quotes cannot be re-verified without a format migration.

### Version pinning strategy

The workspace currently uses exact pinning (`=0.1.0-rc.8`). This is correct
for RC-stage dependencies. When upgrading:

- Change the pin in the workspace `Cargo.toml`.
- Run `cargo test --workspace` to catch API breaks.
- Manually verify that a key generated under the old version is rejected (not
  silently misread) under the new version.
- Regenerate all test fixtures that embed raw key or signature bytes.

---

## Explicit Uncertainty

The following questions are **unanswered** as of this writing:

1. Will the RustCrypto `ml-dsa 1.0.0` stable release maintain binary
   compatibility with `0.1.0-rc.8` serialized keys and signatures?
2. Is there an official migration guide from the RustCrypto project for RC
   users?
3. Are the constants `ML_DSA_65_VERIFYING_KEY_SIZE = 1952` and
   `ML_DSA_65_SIGNATURE_SIZE = 3309` fixed by FIPS 204 (and therefore
   stable across all conforming implementations), or are they implementation
   choices that could change?

**Assessment:** The constants are defined by FIPS 204 and are not subject to
implementation discretion. However, the internal encoding of the byte arrays
(field ordering, padding, domain separation bytes) could differ between RC
and stable if the RustCrypto team updates their FIPS 204 implementation to
match a corrigendum or clarification. This risk is non-zero and cannot be
dismissed without a statement from the RustCrypto maintainers or a tested
round-trip across the version boundary.

---

## Recommended Deployment Boundaries

| Scenario | Recommendation |
|----------|---------------|
| Short-lived development or CI testing | Safe — no persistence concerns |
| Long-term key storage (HSM, secure enclave) | **Defer** until ml-dsa stabilizes or migration path is confirmed |
| Quote archives for compliance audit | **Defer** or version-tag all stored blobs with the `ml-dsa` version used |
| Federation with re-keying capability | Acceptable with documented upgrade procedure |
| Regulated environment (FIPS, Common Criteria) | Requires stable `ml-dsa 1.0.0` and third-party validation |
