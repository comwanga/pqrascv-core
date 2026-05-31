# PQ-RASCV PKI Operations Guide

Operational runbook for the PQ-RASCV device PKI: CA lifecycle, HSM/PKCS#11
integration, key rollover, trust-anchor rotation, and revocation continuity.

All types referenced here live in `pqrascv-core::pki` and are gated behind the
`alloc` feature. The PKI uses a CBOR-native certificate format (not X.509) and
**ML-DSA-65 (FIPS 204)** signatures with domain-separation contexts
(`SIGNING_CONTEXT_CERT` for certificates, `SIGNING_CONTEXT_CRL` for CRLs). This
guide does not change those formats; it documents the operational workflows
built on top of them.

---

## 1. Trust hierarchy & CA lifecycle

```text
Offline Root CA (air-gapped, key in HSM/offline vault)
  └── Manufacturer Intermediate CA (HSM-protected, online)
        └── DeviceCertificate (leaf, max_path_length = Some(0))
```

| Stage | Action | Key custody |
|-------|--------|-------------|
| **Genesis** | Generate Root CA keypair in an air-gapped ceremony. Distribute the verifying key out-of-band (burned into firmware, or via secure channel). | Root private key: offline HSM / vault. Never on a networked host. |
| **Intermediate issuance** | Root signs the intermediate CA certificate. | Intermediate private key: online HSM. |
| **Device enrollment** | Intermediate signs `DeviceCertificate`s binding an ML-DSA-65 device key to a `HardwareIdentity`. | Device key: device keystore. |
| **Revocation** | Issuing CA signs a `RevocationList` (CRL) listing revoked serials. | Same CA key that signs certs. |
| **Rollover / rotation** | Replace a CA signing key or the trust anchor with an overlap window (sections 3–4). | New key generated in HSM via `KeyProvider::rotate`. |
| **Retirement** | After the overlap window closes, destroy the old key (`KeyProvider::destroy`). | — |

`validate_chain` / `validate_chain_with_store` enforce: cert version, issuer-ID
binding, per-cert signature under the parent key, temporal validity,
`max_path_length` path constraints, and termination at a trusted anchor.

---

## 2. HSM / PKCS#11 integration via the `KeyProvider` trait

PQ-RASCV takes **no dependency** on `cryptoki`/`pkcs11` or any HSM SDK. HSM
integration is a *trait-only* abstraction: operators implement `KeyProvider`
against their own PKCS#11 module. This keeps the core `no_std`-capable and lets
each deployment bind its own vendor library.

### Trait surface (`pqrascv-core::pki::key_provider::KeyProvider`)

| Method | PKCS#11 analogue | Notes |
|--------|------------------|-------|
| `open_session(&mut self)` | `C_OpenSession` + `C_Login` | Required before any key op. |
| `close_session(&mut self)` | `C_CloseSession` | Releases device resources. |
| `generate_keypair(&mut self) -> KeyHandle` | `C_GenerateKeyPair` | Private key created on-device, never leaves it. |
| `import_keypair(&mut self, seed) -> KeyHandle` | `C_UnwrapKey` / `C_CreateObject` | Load a seed from an air-gapped ceremony. |
| `public_key(&self, handle) -> [u8; 1952]` | `C_GetAttributeValue` (public) | **Only** public material is ever exported. |
| `sign(&self, handle, message, context) -> SignatureBytes` | `C_Sign` | On-device signing; private bytes never exposed. |
| `rotate(&mut self, handle) -> KeyHandle` | generate successor | Old key **retained** for the overlap window. |
| `destroy(&mut self, handle)` | `C_DestroyObject` | Permanent; call only after overlap closes. |

Key invariant: **no method returns private key bytes.** A compliant HSM impl
keeps the private key non-extractable and performs `sign` on-device. `KeyHandle`
is an opaque, non-secret index (like a PKCS#11 object handle).

### Reference implementation: `SoftwareKeyProvider`

A pure-software `KeyProvider` backed by the existing `MlDsaBackend` /
`SigningKeySeed`. Seeds live in process memory (zeroized on drop). **Not a
security boundary** — use it for tests, CI, and non-HSM deployments only. For
production CA keys, implement `KeyProvider` against a real PKCS#11 module.

```rust,ignore
use pqrascv_core::pki::{KeyProvider, SoftwareKeyProvider};
use pqrascv_core::crypto::SIGNING_CONTEXT_CERT;

let mut hsm = SoftwareKeyProvider::new(); // ← swap for your PKCS#11 impl
hsm.open_session()?;
let ca = hsm.generate_keypair()?;            // CA private key lives in the provider
let ca_vk = hsm.public_key(ca)?;             // 1952-byte ML-DSA-65 verifying key
let sig = hsm.sign(ca, &cert_tbs, SIGNING_CONTEXT_CERT)?; // sign a cert TBS
hsm.close_session()?;
```

> **Note on `no_std`:** `generate_keypair`/`rotate` need an OS RNG and therefore
> require the `std` feature. On `no_std`+`alloc` targets, generate the seed
> out-of-band and load it with `import_keypair`.

---

## 3. CA key rollover (overlap window)

Rolling a CA *signing key* replaces the private key while keeping the same
logical CA identity (`ca_id`). Certificates signed under the old key must remain
verifiable until they expire or are re-issued. This is achieved with an
**overlap window** during which both keys are trusted.

```text
old key:  [────────────── valid ──────────────]
new key:                 [────────── valid ──────────── … ]
                         └── overlap ──┘   (both trusted)
```

`OverlapWindow::new(old_nb, old_na, new_nb, new_na)` constructs and validates the
window. It **rejects** configurations that would leave a verification gap:
the new key must come online *before* the old key retires
(`new_not_before < old_not_after`) and outlive it
(`new_not_after >= old_not_after`).

### Procedure

1. `let new_handle = hsm.rotate(old_handle)?;` — provisions the successor key.
   The old key is **retained**.
2. `let new_vk = hsm.public_key(new_handle)?;`
3. Build the successor CA public key with the new validity span:
   `rolled_over_ca_key(ca_id, new_vk, &window)`.
4. Issue new certificates under `new_handle`; existing certs continue to verify
   under the old key for the rest of the overlap.
5. When `OverlapWindow::old_is_retired(now)` is `true`, call
   `hsm.destroy(old_handle)?` and remove the old anchor/key from distribution.

Helpers: `OverlapWindow::is_in_overlap(now)`, `old_key_valid_at(now)`,
`new_key_valid_at(now)`, `old_is_retired(now)`.

---

## 4. Trust-anchor (root) rotation

Rotating the *trust anchor* (root CA) introduces a new anchor with continuity:
the new anchor is added while the old is retained for an overlap, then the old
is retired — with **no verification gap** for in-flight certs.

The `TrustStore` holds multiple anchors and
`validate_chain_with_store` tries every temporally valid anchor, accepting a
chain on the first match. Rotation therefore reduces to managing the anchor set.

### Procedure

1. Generate the successor root in an air-gapped ceremony (or
   `hsm.rotate(old_root_handle)`), export `new_root_vk`.
2. Define the rotation window: `OverlapWindow::new(old_nb, old_na, new_nb, new_na)`.
3. Build the successor anchor with the new-key span (`new_nb..=new_na`) and add
   it:

   ```rust,ignore
   let store = begin_trust_anchor_rotation(store, successor_anchor, &window)?;
   ```

   `begin_trust_anchor_rotation` checks the successor anchor's validity matches
   `window`'s new-key span; otherwise it returns `CertificateInvalid` (a
   guardrail against accidentally creating a gap).
4. **During overlap** (`new_nb..old_na`): both anchors are valid; certs under
   either root validate.
5. **After `old_na`**: the old anchor is no longer temporally valid; only the
   new anchor validates new chains. Distribute firmware/clients carrying the new
   anchor before this point.
6. Retire: drop the old anchor and `hsm.destroy(old_root_handle)`.

---

## 5. Revocation continuity across a rollover

A certificate revoked under the **old** CA must stay revoked under the **new**
CA. CRLs are signed by the issuing CA key, so after a key rollover a fresh CRL
must be signed with the new key — but it must still list everything the old CRL
did.

`carry_forward_revocations(old_entries, successor_entries)` merges the two entry
sets, de-duplicating by `serial` (the successor entry wins on collision) and
returning a serial-sorted, deterministic list ready to sign.

### Procedure

1. Collect the old CRL's `entries` (verified under the old key via
   `RevocationList::verify(&old_vk, now)`).
2. `let carried = carry_forward_revocations(&old_entries, &new_entries);`
3. Assemble a new `RevocationList` with `entries = carried`, fresh
   `this_update`/`next_update`.
4. Sign its `tbs_cbor()` with the **new** key and `SIGNING_CONTEXT_CRL`
   (`hsm.sign(new_handle, &tbs, SIGNING_CONTEXT_CRL)`).
5. Publish. Verifiers now check the new CRL under the new key; previously
   revoked serials remain revoked.

CRL freshness (`next_update`) is enforced by `RevocationList::verify`; keep
publishing on schedule across the rollover so the CRL never goes stale.

---

## 6. Quick reference — public API

| Item | Path |
|------|------|
| `KeyProvider` trait | `pki::key_provider::KeyProvider` |
| `SoftwareKeyProvider` | `pki::key_provider::SoftwareKeyProvider` |
| `KeyHandle` | `pki::key_provider::KeyHandle` |
| `OverlapWindow` | `pki::rotation::OverlapWindow` |
| `rolled_over_ca_key` | `pki::rotation::rolled_over_ca_key` |
| `begin_trust_anchor_rotation` | `pki::rotation::begin_trust_anchor_rotation` |
| `carry_forward_revocations` | `pki::rotation::carry_forward_revocations` |
| `TrustStore` / `TrustAnchor` | `pki::trust_store` / `pki` |
| `validate_chain_with_store` | `pki::validate_chain_with_store` |

---

## 7. Caveats — what a real HSM integration still needs

- **`SoftwareKeyProvider` is not a security boundary.** It holds raw seeds in
  process memory. Production CA keys belong in an HSM behind a real
  `KeyProvider` impl.
- **ML-DSA-65 in PKCS#11.** As of writing, ML-DSA (FIPS 204) mechanism support
  in PKCS#11 modules is still rolling out (PKCS#11 v3.2). A real integration
  must confirm the module exposes an ML-DSA-65 sign mechanism with the same
  deterministic, context-separated semantics PQ-RASCV expects; otherwise the
  `sign` impl must adapt (e.g. context prefixing) to match `MlDsaBackend`.
- **Session/auth lifecycle.** The reference impl models a single boolean
  session. Real modules need slot selection, PIN/login handling, session
  pooling, and re-login on token events — all inside your `KeyProvider` impl.
- **Atomic rollover/destroy.** `rotate`/`destroy` here are simple map
  operations. A real deployment must coordinate anchor distribution, CRL
  re-signing, and key destruction so no verifier is left without a valid anchor
  mid-rotation. The `OverlapWindow` guardrails help but do not orchestrate
  distribution.
- **Clock trust.** All temporal checks assume a trustworthy `now_secs`.
  Verifiers without an RTC must obtain trusted time out-of-band.
- **Hardware-identity enrollment** (TPM EK cert / DICE CDI binding) is performed
  at issuance time and is out of scope for this rollover machinery.
