# Trust Anchor Lifecycle Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every `TrustAnchor` a valid time window (`not_before`/`not_after`), enforce it inside `validate_chain`, add a `TrustStore` abstraction for CA rollover, expose anchor lifecycle fields in verification results, and close all tests against adversarial root misuse.

**Architecture:** `CaPublicKey` gains `not_before`/`not_after` fields; `validate_chain` rejects anchors outside their window with the new `TrustAnchorExpired` error; `TrustStore` (new file `pki/trust_store.rs`) holds an ordered list of anchors and tries each valid one at verification time; `CertChain` gains a `trust_anchor: TrustAnchorInfo` field so audit data flows out to callers without extra API surface.

**Tech Stack:** Rust stable, no new dependencies — all changes are in `pqrascv-core` and `pqrascv-verifier`.

---

## File Map

| Action | Path | What changes |
|--------|------|--------------|
| Modify | `crates/pqrascv-core/src/error.rs` | Add `TrustAnchorExpired` variant + Display |
| Modify | `crates/pqrascv-core/src/pki/mod.rs` | `CaPublicKey` temporal fields; `TrustAnchorInfo`; `CertChain.trust_anchor`; `TrustAnchor` accessors; root check in `validate_chain`; new `validate_chain_with_store`; updated chain_tests |
| **Create** | `crates/pqrascv-core/src/pki/trust_store.rs` | `TrustStore` type + unit tests |
| Modify | `crates/pqrascv-core/tests/adversarial_tests.rs` | Fix broken `CaPublicKey` literals; add 7 lifecycle adversarial tests |
| Modify | `crates/verifier/src/lib.rs` | Import `TrustStore`/`validate_chain_with_store`; new `trust_anchor_*` accessors on `PkiVerificationResult`; `verify_cbor_with_trust_store`; fix pki_tests |

---

## Task 1: Add `TrustAnchorExpired` error variant

**Files:**
- Modify: `crates/pqrascv-core/src/error.rs`

- [ ] **Step 1: Write the failing test**

Add at the bottom of `error.rs` (inside or alongside the existing `#[cfg(feature = "std")]` block):

```rust
#[cfg(all(test, feature = "std"))]
mod error_tests {
    use super::*;

    #[test]
    fn trust_anchor_expired_displays_correctly() {
        let e = PqRascvError::TrustAnchorExpired;
        assert_eq!(e.to_string(), "trust anchor is outside its valid time window");
    }
}
```

- [ ] **Step 2: Run it to confirm it fails**

```
cargo test -p pqrascv-core trust_anchor_expired_displays_correctly --features std 2>&1
```

Expected: FAIL — `TrustAnchorExpired` variant not found.

- [ ] **Step 3: Add the variant**

In the `PqRascvError` enum (after `CertificateRevoked`), add:

```rust
    /// The trust anchor is outside its valid time window (`not_before`/`not_after`).
    TrustAnchorExpired,
```

In the `Display` impl (after the `CertificateRevoked` arm), add:

```rust
            Self::TrustAnchorExpired => {
                f.write_str("trust anchor is outside its valid time window")
            }
```

- [ ] **Step 4: Run the test**

```
cargo test -p pqrascv-core trust_anchor_expired_displays_correctly --features std 2>&1
```

Expected: PASS.

- [ ] **Step 5: Full workspace build to catch any match-exhaustiveness breaks**

```
cargo build --workspace --features std,software-rot-unsafe,dice 2>&1
```

Expected: clean (any `match` on `PqRascvError` that doesn't cover `TrustAnchorExpired` will error here).

- [ ] **Step 6: Commit**

```
git add crates/pqrascv-core/src/error.rs
git commit -m "feat(error): add TrustAnchorExpired variant"
```

---

## Task 2: Add temporal validity to `CaPublicKey`, `TrustAnchor`, and `CertChain`

**Files:**
- Modify: `crates/pqrascv-core/src/pki/mod.rs`

This task changes the `CaPublicKey` struct (adding `not_before`/`not_after` and changing `ca_id` from `&'static str` to `String`), adds `TrustAnchorInfo`, embeds it in `CertChain`, and adds public accessors to `TrustAnchor`. It also updates the four existing `chain_tests` that construct `CaPublicKey` literals.

- [ ] **Step 1: Replace the `CaPublicKey` struct and its `impl` block**

Find and replace the existing `CaPublicKey` struct + impl (lines ~228–242 in the current file):

```rust
// ── CaPublicKey ───────────────────────────────────────────────────────────

/// A CA's ML-DSA-65 verifying key with its validity window.
#[derive(Clone, Debug)]
pub struct CaPublicKey {
    /// Raw ML-DSA-65 verifying key bytes (1952 bytes).
    pub key_bytes: [u8; ML_DSA_65_VERIFYING_KEY_SIZE],
    /// Human-readable CA identifier URI.
    pub ca_id: String,
    /// Unix seconds: this CA key becomes trustworthy at this time.
    pub not_before: u64,
    /// Unix seconds: this CA key must not be trusted after this time.
    pub not_after: u64,
}

impl CaPublicKey {
    /// SHA3-256 fingerprint of this CA's public key.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        pub_key_id(&self.key_bytes)
    }

    /// Returns `true` if this CA key is within its valid time window at `now_secs`.
    #[must_use]
    pub fn is_valid_at(&self, now_secs: u64) -> bool {
        now_secs >= self.not_before && now_secs <= self.not_after
    }
}
```

- [ ] **Step 2: Update `TrustAnchor::new` panics doc and assertion**

Replace the existing `TrustAnchor::new` method:

```rust
    /// Creates a trust anchor from the root CA's verifying key and validity window.
    ///
    /// # Panics
    ///
    /// Panics if `root_ca.ca_id` is empty or if `root_ca.not_before > root_ca.not_after`.
    #[must_use]
    pub fn new(root_ca: CaPublicKey) -> Self {
        assert!(!root_ca.ca_id.is_empty(), "TrustAnchor ca_id must not be empty");
        assert!(
            root_ca.not_before <= root_ca.not_after,
            "TrustAnchor not_before must not exceed not_after"
        );
        Self { root_ca }
    }
```

- [ ] **Step 3: Add public accessors to `TrustAnchor`**

After the existing `root_key_bytes` method, add:

```rust
    /// Returns the root CA identifier URI.
    #[must_use]
    pub fn ca_id(&self) -> &str {
        &self.root_ca.ca_id
    }

    /// Returns `true` if this trust anchor is within its valid time window at `now_secs`.
    #[must_use]
    pub fn is_valid_at(&self, now_secs: u64) -> bool {
        self.root_ca.is_valid_at(now_secs)
    }

    /// Returns the Unix timestamp at which this anchor becomes valid.
    #[must_use]
    pub fn not_before(&self) -> u64 {
        self.root_ca.not_before
    }

    /// Returns the Unix timestamp after which this anchor must not be used.
    #[must_use]
    pub fn not_after(&self) -> u64 {
        self.root_ca.not_after
    }
```

- [ ] **Step 4: Add `TrustAnchorInfo` struct**

After the `TrustAnchor` impl block, add:

```rust
// ── TrustAnchorInfo ───────────────────────────────────────────────────────

/// Metadata about the trust anchor that validated a certificate chain.
///
/// Embedded in [`CertChain`] so verification results carry full audit context.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct TrustAnchorInfo {
    /// CA identifier URI (matches `CaPublicKey::ca_id`).
    pub ca_id: String,
    /// SHA3-256 fingerprint of the root CA's public key.
    pub fingerprint: [u8; 32],
    /// Unix seconds: anchor becomes valid at this time.
    pub not_before: u64,
    /// Unix seconds: anchor expires at this time.
    pub not_after: u64,
}
```

- [ ] **Step 5: Add `trust_anchor` field to `CertChain`**

Replace the `CertChain` struct definition:

```rust
/// A validated certificate chain: root CA → [intermediate CAs] → device cert.
///
/// Constructed by [`validate_chain`]; cannot be constructed directly.
/// Holding a `CertChain` is proof that the chain was valid at construction time.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct CertChain {
    /// The validated device certificate at the leaf.
    pub device_cert: DeviceCertificate,
    /// Intermediate CA certificates (root-to-leaf order, excluding root).
    pub intermediates: Vec<DeviceCertificate>,
    /// Metadata about the trust anchor that validated this chain.
    pub trust_anchor: TrustAnchorInfo,
}
```

- [ ] **Step 6: Update `chain_tests` — fix the four `TrustAnchor::new` call sites**

`CaPublicKey` no longer accepts `&'static str` for `ca_id` and requires `not_before`/`not_after`. Update each of the four tests in the `chain_tests` module.

In `valid_chain_no_intermediates`:
```rust
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
```

In `issuer_mismatch_rejected`:
```rust
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
```

In `path_length_exceeded_rejected`:
```rust
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: root_vk,
            ca_id: "https://root.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
```

In `intermediate_issuer_mismatch_rejected`:
```rust
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: root_vk,
            ca_id: "https://root.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
```

- [ ] **Step 7: Build to confirm no compilation errors**

```
cargo build -p pqrascv-core --features std,software-rot-unsafe 2>&1
```

Expected: clean (validate_chain's Ok() return still compiles because it now builds CertChain without the trust_anchor field — it will break in Task 3 when we populate it).

Actually, because `CertChain` now has a required `trust_anchor` field, `validate_chain`'s return statement `Ok(CertChain { device_cert, intermediates })` will fail to compile. That's expected — we'll fix it in Task 3.

- [ ] **Step 8: Run existing chain tests (they will fail at compile — that's expected)**

```
cargo test -p pqrascv-core --features std,software-rot-unsafe 2>&1 | head -30
```

Expected: compile error about missing `trust_anchor` field in `CertChain` struct literal inside `validate_chain`. This is the red state before Task 3.

---

## Task 3: Enforce root temporal validation in `validate_chain`

**Files:**
- Modify: `crates/pqrascv-core/src/pki/mod.rs`

- [ ] **Step 1: Write the failing tests first (add to `chain_tests` module)**

```rust
    #[test]
    fn expired_trust_anchor_is_rejected() {
        let (ca_seed, ca_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: 999, // expired
        });
        let cert = make_device_cert(
            &dev_vk, "https://ca.test", "https://dev.test", "DEV-001", ca_seed.as_bytes(),
        );
        assert!(matches!(
            validate_chain(cert, vec![], &anchor, 1_000), // now=1000 > not_after=999
            Err(PqRascvError::TrustAnchorExpired)
        ));
    }

    #[test]
    fn not_yet_valid_trust_anchor_is_rejected() {
        let (ca_seed, ca_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 5_000, // not yet valid
            not_after: u64::MAX,
        });
        let cert = make_device_cert(
            &dev_vk, "https://ca.test", "https://dev.test", "DEV-001", ca_seed.as_bytes(),
        );
        assert!(matches!(
            validate_chain(cert, vec![], &anchor, 1_000), // now=1000 < not_before=5000
            Err(PqRascvError::TrustAnchorExpired)
        ));
    }
```

- [ ] **Step 2: Update `validate_chain` — add root temporal check at the top**

The very first lines of `validate_chain` (after the `use` statement) must be:

```rust
    // Root CA temporal validation — fail-closed before any other work.
    if !trust_anchor.root_ca.is_valid_at(now_secs) {
        return Err(PqRascvError::TrustAnchorExpired);
    }
```

- [ ] **Step 3: Update `validate_chain` — populate `trust_anchor` in the `Ok` return**

Replace the final `Ok(CertChain { device_cert, intermediates })` with:

```rust
    let trust_anchor_info = TrustAnchorInfo {
        ca_id:       trust_anchor.root_ca.ca_id.clone(),
        fingerprint: trust_anchor.root_fingerprint(),
        not_before:  trust_anchor.root_ca.not_before,
        not_after:   trust_anchor.root_ca.not_after,
    };
    Ok(CertChain { device_cert, intermediates, trust_anchor: trust_anchor_info })
```

- [ ] **Step 4: Fix `validate_chain` doc — update the enumerated checks and Errors section**

Replace the existing check list and `# Errors` section:

```rust
/// Checks:
/// 1. The trust anchor is temporally valid at `now_secs`.
/// 2. Each certificate's format version equals [`CERT_VERSION`].
/// 3. Each certificate's `issuer_id` matches the identity of the cert above it.
/// 4. Each certificate's `issuer_signature` is valid under the previous cert's key
///    (or the root CA key for the first intermediate).
/// 5. Each certificate in the chain is temporally valid at `now_secs`.
/// 6. CA path-length constraints (`max_path_length`) are honoured.
/// 7. The chain terminates at the trust anchor's root CA.
///
/// # Errors
///
/// Returns [`PqRascvError::TrustAnchorExpired`] if the trust anchor is outside
/// its valid time window, [`PqRascvError::CertificateInvalid`] for structural/
/// policy failures, and [`PqRascvError::VerificationFailed`] for cryptographic
/// failures.
```

- [ ] **Step 5: Run the tests**

```
cargo test -p pqrascv-core --features std,software-rot-unsafe 2>&1
```

Expected: all previous chain_tests pass plus the two new temporal tests pass.

- [ ] **Step 6: Commit**

```
git add crates/pqrascv-core/src/pki/mod.rs
git commit -m "feat(pki): add TrustAnchorInfo to CertChain; enforce root temporal validity in validate_chain"
```

---

## Task 4: Fix broken `CaPublicKey` literals in existing external tests

**Files:**
- Modify: `crates/pqrascv-core/tests/adversarial_tests.rs`
- Modify: `crates/verifier/src/lib.rs`

The `CaPublicKey` struct now requires `ca_id: String`, `not_before: u64`, `not_after: u64`. Fix every existing call site.

- [ ] **Step 1: Fix `adversarial_tests.rs` — two `TrustAnchor::new` call sites**

Line ~189, `cert_with_forged_tbs_fails_chain_validation`:
```rust
    let anchor = TrustAnchor::new(CaPublicKey {
        key_bytes: ca_vk,
        ca_id: "https://ca.test".to_string(),
        not_before: 0,
        not_after: u64::MAX,
    });
```

Line ~224, `cert_with_wrong_issuer_id_fails_chain_validation`:
```rust
    let anchor = TrustAnchor::new(CaPublicKey {
        key_bytes: ca_vk,
        ca_id: "https://ca.test".to_string(),
        not_before: 0,
        not_after: u64::MAX,
    });
```

- [ ] **Step 2: Fix `verifier/src/lib.rs` pki_tests — three `TrustAnchor::new` call sites**

In `pki_verification_succeeds_with_valid_chain`:
```rust
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
```

In `pki_verification_rejects_revoked_device`:
```rust
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
```

In `pki_verification_succeeds_with_intermediate_chain` (there is a third test in the verifier):
```rust
        let root_anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: root_vk,
            ca_id: "https://root.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
```

- [ ] **Step 3: Run all workspace tests**

```
cargo test --workspace --features std,software-rot-unsafe,dice 2>&1
```

Expected: all tests pass (same count as before this task).

- [ ] **Step 4: Commit**

```
git add crates/pqrascv-core/tests/adversarial_tests.rs crates/verifier/src/lib.rs
git commit -m "fix(tests): update CaPublicKey literals for temporal validity fields"
```

---

## Task 5: Add `TrustStore` type

**Files:**
- Create: `crates/pqrascv-core/src/pki/trust_store.rs`
- Modify: `crates/pqrascv-core/src/pki/mod.rs` (wire in the module + re-export)

- [ ] **Step 1: Write the failing tests first**

Create `crates/pqrascv-core/src/pki/trust_store.rs` with tests only (no implementation yet):

```rust
//! Multi-root trust store supporting CA rollover and staged migration.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::TrustAnchor;

/// A collection of trust anchors supporting CA lifecycle management.
///
/// Holds one or more [`TrustAnchor`] entries. During chain validation all valid
/// (temporally active) anchors are tried in order. This enables:
///
/// - **Rollover**: old and new root CAs coexist during migration windows.
/// - **Staged migration**: devices continue to use the old CA until re-provisioned.
/// - **Multi-root**: different device classes may use different root CAs.
#[cfg(feature = "alloc")]
pub struct TrustStore {
    anchors: Vec<TrustAnchor>,
}

// implementation goes here (Step 3)

#[cfg(all(test, feature = "alloc", feature = "std"))]
mod tests {
    use super::*;
    use crate::crypto::{generate_ml_dsa_keypair, ML_DSA_65_VERIFYING_KEY_SIZE};
    use crate::pki::{CaPublicKey, TrustAnchor};

    fn make_anchor(ca_id: &str, not_before: u64, not_after: u64) -> TrustAnchor {
        let (_, vk) = generate_ml_dsa_keypair().unwrap();
        TrustAnchor::new(CaPublicKey {
            key_bytes: vk,
            ca_id: ca_id.to_string(),
            not_before,
            not_after,
        })
    }

    #[test]
    fn single_valid_anchor_found() {
        let store = TrustStore::new(make_anchor("https://ca.test", 0, u64::MAX));
        assert_eq!(store.valid_anchors_at(1_000).count(), 1);
    }

    #[test]
    fn expired_anchor_not_returned() {
        let store = TrustStore::new(make_anchor("https://ca.test", 0, 999));
        assert_eq!(store.valid_anchors_at(1_000).count(), 0);
    }

    #[test]
    fn not_yet_valid_anchor_not_returned() {
        let store = TrustStore::new(make_anchor("https://ca.test", 5_000, u64::MAX));
        assert_eq!(store.valid_anchors_at(1_000).count(), 0);
    }

    #[test]
    fn rollover_gives_two_valid_anchors_during_overlap() {
        let store = TrustStore::new(make_anchor("https://old.ca", 0, 3_000))
            .with_rollover(make_anchor("https://new.ca", 2_000, u64::MAX));
        // at t=2500 both anchors are valid
        assert_eq!(store.valid_anchors_at(2_500).count(), 2);
    }

    #[test]
    fn rollover_old_anchor_drops_after_expiry() {
        let store = TrustStore::new(make_anchor("https://old.ca", 0, 2_000))
            .with_rollover(make_anchor("https://new.ca", 1_000, u64::MAX));
        // at t=3000 only the new CA is valid
        assert_eq!(store.valid_anchors_at(3_000).count(), 1);
    }

    #[test]
    fn all_anchors_expired_has_no_valid_anchor() {
        let store = TrustStore::new(make_anchor("https://ca.test", 0, 999));
        assert!(!store.has_valid_anchor(1_000));
    }

    #[test]
    fn all_anchors_returns_full_list() {
        let store = TrustStore::new(make_anchor("https://a.test", 0, u64::MAX))
            .with_rollover(make_anchor("https://b.test", 0, u64::MAX));
        assert_eq!(store.all_anchors().len(), 2);
    }
}
```

- [ ] **Step 2: Run the tests to confirm they fail**

First wire the module (just the `pub mod trust_store;` declaration) into `pki/mod.rs` before the `TrustStore` impl exists:

At the top of `pki/mod.rs`, after `pub mod revocation;`, add:
```rust
pub mod trust_store;
#[cfg(feature = "alloc")]
pub use trust_store::TrustStore;
```

Then:
```
cargo test -p pqrascv-core --features std,software-rot-unsafe 2>&1 | grep trust_store
```

Expected: compile error — `TrustStore` methods (`new`, `with_rollover`, etc.) not defined.

- [ ] **Step 3: Implement `TrustStore`**

Replace the `// implementation goes here` comment in `trust_store.rs`:

```rust
#[cfg(feature = "alloc")]
impl TrustStore {
    /// Creates a trust store from a single primary trust anchor.
    #[must_use]
    pub fn new(primary: TrustAnchor) -> Self {
        Self { anchors: alloc::vec![primary] }
    }

    /// Adds a rollover anchor.
    ///
    /// During validation, all valid anchors are tried in insertion order.
    /// The chain is accepted the first time any valid anchor validates it.
    #[must_use]
    pub fn with_rollover(mut self, anchor: TrustAnchor) -> Self {
        self.anchors.push(anchor);
        self
    }

    /// Returns an iterator over anchors valid at `now_secs`.
    ///
    /// An anchor is valid when `not_before ≤ now_secs ≤ not_after`.
    pub fn valid_anchors_at(&self, now_secs: u64) -> impl Iterator<Item = &TrustAnchor> {
        self.anchors.iter().filter(move |a| a.is_valid_at(now_secs))
    }

    /// Returns all anchors in insertion order.
    #[must_use]
    pub fn all_anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }

    /// Returns `true` if at least one anchor is valid at `now_secs`.
    #[must_use]
    pub fn has_valid_anchor(&self, now_secs: u64) -> bool {
        self.valid_anchors_at(now_secs).next().is_some()
    }
}
```

- [ ] **Step 4: Run trust_store tests**

```
cargo test -p pqrascv-core --features std,software-rot-unsafe trust_store 2>&1
```

Expected: 7 tests pass.

- [ ] **Step 5: Run full workspace**

```
cargo test --workspace --features std,software-rot-unsafe,dice 2>&1
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```
git add crates/pqrascv-core/src/pki/trust_store.rs crates/pqrascv-core/src/pki/mod.rs
git commit -m "feat(pki): add TrustStore for multi-root CA and rollover support"
```

---

## Task 6: Add `validate_chain_with_store`

**Files:**
- Modify: `crates/pqrascv-core/src/pki/mod.rs`

- [ ] **Step 1: Write the failing tests (add to `chain_tests` module in `pki/mod.rs`)**

```rust
    #[test]
    fn trust_store_with_single_valid_anchor_validates_chain() {
        use super::trust_store::TrustStore;
        let (ca_seed, ca_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let store = TrustStore::new(TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        }));
        let cert = make_device_cert(
            &dev_vk, "https://ca.test", "https://dev.test", "DEV-001", ca_seed.as_bytes(),
        );
        let result = validate_chain_with_store(cert, vec![], &store, 1_000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().trust_anchor.ca_id, "https://ca.test");
    }

    #[test]
    fn trust_store_tries_all_valid_anchors() {
        use super::trust_store::TrustStore;
        // Two CAs; cert is signed by the second one
        let (ca1_seed, ca1_vk) = make_ca();
        let (ca2_seed, ca2_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let store = TrustStore::new(TrustAnchor::new(CaPublicKey {
            key_bytes: ca1_vk,
            ca_id: "https://ca1.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        }))
        .with_rollover(TrustAnchor::new(CaPublicKey {
            key_bytes: ca2_vk,
            ca_id: "https://ca2.test".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        }));
        // Cert signed by CA2
        let cert = make_device_cert(
            &dev_vk, "https://ca2.test", "https://dev.test", "DEV-001", ca2_seed.as_bytes(),
        );
        let result = validate_chain_with_store(cert, vec![], &store, 1_000);
        assert!(result.is_ok(), "CA2-signed cert must be accepted by store containing CA2");
        assert_eq!(result.unwrap().trust_anchor.ca_id, "https://ca2.test");
    }

    #[test]
    fn trust_store_no_valid_anchors_returns_expired() {
        use super::trust_store::TrustStore;
        let (ca_seed, ca_vk) = make_ca();
        let (_, dev_vk) = make_ca();
        let store = TrustStore::new(TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://ca.test".to_string(),
            not_before: 0,
            not_after: 999, // already expired
        }));
        let cert = make_device_cert(
            &dev_vk, "https://ca.test", "https://dev.test", "DEV-001", ca_seed.as_bytes(),
        );
        assert!(matches!(
            validate_chain_with_store(cert, vec![], &store, 1_000),
            Err(PqRascvError::TrustAnchorExpired)
        ));
    }
```

- [ ] **Step 2: Run to confirm failure**

```
cargo test -p pqrascv-core --features std,software-rot-unsafe trust_store_with_single 2>&1
```

Expected: FAIL — `validate_chain_with_store` not found.

- [ ] **Step 3: Implement `validate_chain_with_store` in `pki/mod.rs`**

Add after the `validate_chain` function:

```rust
/// Validates a certificate chain against any currently-valid anchor in a [`TrustStore`].
///
/// Anchors are tried in insertion order; the chain is accepted on the first match.
/// Returns [`PqRascvError::TrustAnchorExpired`] if no anchor is valid at `now_secs`,
/// or [`PqRascvError::CertificateInvalid`] if no valid anchor accepts the chain.
///
/// # Errors
///
/// Returns [`PqRascvError::TrustAnchorExpired`] when the store has no valid anchor,
/// [`PqRascvError::CertificateInvalid`] when every valid anchor rejects the chain,
/// or propagates errors from signature/CBOR operations.
#[cfg(feature = "alloc")]
pub fn validate_chain_with_store(
    device_cert: DeviceCertificate,
    intermediates: Vec<DeviceCertificate>,
    trust_store: &trust_store::TrustStore,
    now_secs: u64,
) -> Result<CertChain, PqRascvError> {
    let valid_anchors: Vec<&TrustAnchor> =
        trust_store.valid_anchors_at(now_secs).collect();

    if valid_anchors.is_empty() {
        return Err(PqRascvError::TrustAnchorExpired);
    }

    for anchor in valid_anchors {
        if let Ok(chain) =
            validate_chain(device_cert.clone(), intermediates.clone(), anchor, now_secs)
        {
            return Ok(chain);
        }
    }

    Err(PqRascvError::CertificateInvalid)
}
```

- [ ] **Step 4: Re-export from `pki/mod.rs` public surface**

Ensure `validate_chain_with_store` is accessible from external crates. Since it's defined at module level in `pki/mod.rs`, it is already `pub`. No re-export needed. Verify it appears in the public API by checking that `pqrascv_core::pki::validate_chain_with_store` resolves.

- [ ] **Step 5: Run the new tests**

```
cargo test -p pqrascv-core --features std,software-rot-unsafe trust_store 2>&1
```

Expected: all `trust_store_*` tests pass.

- [ ] **Step 6: Full workspace**

```
cargo test --workspace --features std,software-rot-unsafe,dice 2>&1
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```
git add crates/pqrascv-core/src/pki/mod.rs
git commit -m "feat(pki): add validate_chain_with_store for multi-root trust store validation"
```

---

## Task 7: Update `Verifier` — trust store path and result accessors

**Files:**
- Modify: `crates/verifier/src/lib.rs`

- [ ] **Step 1: Add new imports**

Find the existing `use pqrascv_core::{...}` block at the top of `verifier/src/lib.rs`. Add the new imports:

```rust
use pqrascv_core::{
    config::PolicyConfig,
    crypto::{pub_key_id, CryptoBackend, MlDsaBackend, SIGNING_CONTEXT_QUOTE},
    error::PqRascvError,
    pki::{validate_chain, validate_chain_with_store, CertChain, DeviceCertificate, TrustAnchor, TrustStore},
    pki::revocation::VerifiedRevocationList,
    quote::{AttestationQuote, Challenge, PROTOCOL_VERSION},
};
```

- [ ] **Step 2: Add trust anchor accessors to `PkiVerificationResult`**

After the existing `device_serial()` method in the `PkiVerificationResult` impl, add:

```rust
    /// The CA identifier URI of the trust anchor that validated this chain.
    #[must_use]
    pub fn trust_anchor_id(&self) -> &str {
        &self.cert_chain.trust_anchor.ca_id
    }

    /// SHA3-256 fingerprint of the trust anchor's public key.
    #[must_use]
    pub fn trust_anchor_fingerprint(&self) -> &[u8; 32] {
        &self.cert_chain.trust_anchor.fingerprint
    }

    /// Unix timestamp after which the trust anchor must not be used.
    #[must_use]
    pub fn trust_anchor_valid_until(&self) -> u64 {
        self.cert_chain.trust_anchor.not_after
    }
```

- [ ] **Step 3: Write failing tests for the new accessor and trust-store path**

Add to `pki_tests` module in `verifier/src/lib.rs`:

```rust
    #[test]
    fn pki_result_exposes_trust_anchor_metadata() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();

        let expected_fingerprint = pqrascv_core::crypto::pub_key_id(&ca_vk);
        let anchor = TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://audit.ca".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        });
        let device_cert = make_device_cert(&dev_vk, "https://audit.ca", "DEV-AUDIT", ca_seed.as_bytes());

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xCCu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        let result = verifier
            .verify_cbor_with_pki(&cbor, device_cert, vec![], &anchor, None, &nonce, 1_700_000_100)
            .unwrap();

        assert_eq!(result.trust_anchor_id(), "https://audit.ca");
        assert_eq!(result.trust_anchor_fingerprint(), &expected_fingerprint);
        assert_eq!(result.trust_anchor_valid_until(), u64::MAX);
    }

    #[test]
    fn verify_cbor_with_trust_store_accepts_valid_chain() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();

        let store = TrustStore::new(TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://store.ca".to_string(),
            not_before: 0,
            not_after: u64::MAX,
        }));
        let device_cert = make_device_cert(&dev_vk, "https://store.ca", "DEV-STORE", ca_seed.as_bytes());

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xDDu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        let result = verifier.verify_cbor_with_trust_store(
            &cbor, device_cert, vec![], &store, None, &nonce, 1_700_000_100,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().trust_anchor_id(), "https://store.ca");
    }

    #[test]
    fn verify_cbor_with_trust_store_rejects_expired_store() {
        let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
        let (dev_seed, dev_vk) = generate_ml_dsa_keypair().unwrap();

        // All anchors in store have already expired
        let store = TrustStore::new(TrustAnchor::new(CaPublicKey {
            key_bytes: ca_vk,
            ca_id: "https://expired.ca".to_string(),
            not_before: 0,
            not_after: 999,
        }));
        let device_cert = make_device_cert(&dev_vk, "https://expired.ca", "DEV-EXP", ca_seed.as_bytes());

        let rot = SoftwareRoT::new(b"fw", None, 1);
        let nonce = [0xEEu8; 32];
        let quote = generate_quote(
            &rot, &MlDsaBackend, dev_seed.as_bytes(), &dev_vk,
            &nonce, make_provenance(), QuoteTimestamp::Rtc(1_700_000_000),
        ).unwrap();
        let cbor = quote.to_cbor().unwrap();

        let verifier = Verifier::new(PolicyConfig::default());
        let result = verifier.verify_cbor_with_trust_store(
            &cbor, device_cert, vec![], &store, None, &nonce, 1_700_000_100,
        );
        assert!(matches!(result, Err(PqRascvError::TrustAnchorExpired)));
    }
```

Also add to the `pki_tests` `use` block:
```rust
    use pqrascv_core::pki::{TrustStore};
```

- [ ] **Step 4: Run to confirm failures**

```
cargo test -p pqrascv-verifier 2>&1 | grep -E "FAILED|error"
```

Expected: compile errors — `verify_cbor_with_trust_store` not defined, `TrustStore` import.

- [ ] **Step 5: Implement `verify_cbor_with_trust_store` on `Verifier`**

Add after `verify_cbor_with_pki`:

```rust
    /// Verifies a CBOR quote using any currently-valid anchor in a [`TrustStore`].
    ///
    /// Tries each valid (temporally active) anchor in insertion order. Returns
    /// [`PqRascvError::TrustAnchorExpired`] if the store has no valid anchor,
    /// or [`PqRascvError::CertificateInvalid`] if no valid anchor accepts the chain.
    ///
    /// # Arguments
    ///
    /// - `trust_store`: holds primary and rollover root CA anchors.
    /// - `crl`: optional verified CRL; if `Some`, the device serial is checked for revocation.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_cbor_with_trust_store(
        &self,
        cbor: &[u8],
        device_cert: DeviceCertificate,
        intermediates: Vec<DeviceCertificate>,
        trust_store: &TrustStore,
        crl: Option<&VerifiedRevocationList<'_>>,
        expected_nonce: &[u8; 32],
        now_secs: u64,
    ) -> Result<PkiVerificationResult, PqRascvError> {
        let chain =
            validate_chain_with_store(device_cert, intermediates, trust_store, now_secs)?;

        if let Some(crl) = crl {
            if crl.is_revoked(&chain.device_cert.serial) {
                return Err(PqRascvError::CertificateRevoked);
            }
        }

        let verifying_key = &chain.device_cert.subject_key;
        let result = self.verify_cbor(cbor, verifying_key, expected_nonce, now_secs)?;

        Ok(PkiVerificationResult { quote: result.quote, cert_chain: chain })
    }
```

- [ ] **Step 6: Run verifier tests**

```
cargo test -p pqrascv-verifier 2>&1
```

Expected: all tests pass, including the 3 new ones.

- [ ] **Step 7: Full workspace + clippy**

```
cargo test --workspace --features std,software-rot-unsafe,dice 2>&1
cargo clippy --workspace --features std,software-rot-unsafe,dice -- -D warnings 2>&1
```

Expected: clean.

- [ ] **Step 8: Commit**

```
git add crates/verifier/src/lib.rs
git commit -m "feat(verifier): add verify_cbor_with_trust_store; expose trust anchor metadata on PkiVerificationResult"
```

---

## Task 8: Adversarial root lifecycle tests

**Files:**
- Modify: `crates/pqrascv-core/tests/adversarial_tests.rs`

- [ ] **Step 1: Add a helper and the new test block at the bottom of `adversarial_tests.rs`**

Add these imports to the existing top-level `use` block:

```rust
    validate_chain_with_store, TrustStore,
```

(inside the `pqrascv_core::pki::{...}` import).

Then append to the file:

```rust
// ── Trust anchor lifecycle adversarial tests ──────────────────────────────────

fn make_anchor(
    ca_vk: [u8; pqrascv_core::crypto::ML_DSA_65_VERIFYING_KEY_SIZE],
    ca_id: &str,
    not_before: u64,
    not_after: u64,
) -> TrustAnchor {
    TrustAnchor::new(CaPublicKey {
        key_bytes: ca_vk,
        ca_id: ca_id.to_string(),
        not_before,
        not_after,
    })
}

fn make_cert_for_ca(
    dev_vk: &[u8],
    issuer_ca_id: &str,
    ca_seed: &[u8],
) -> pqrascv_core::pki::DeviceCertificate {
    let subject_key_id = pqrascv_core::crypto::pub_key_id(dev_vk);
    let mut cert = build_device_certificate(
        CERT_VERSION,
        "DEV-001".to_string(),
        issuer_ca_id.to_string(),
        0,
        u64::MAX,
        dev_vk.to_vec(),
        subject_key_id,
        HardwareIdentity::TpmEkCertHash([0u8; 32]),
        None,
        vec![],
        "DEV-001".to_string(),
        Some(0),
    );
    sign_cert(&mut cert, ca_seed);
    cert
}

#[test]
fn expired_trust_anchor_rejected_in_validate_chain() {
    let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
    let (_, dev_vk) = generate_ml_dsa_keypair().unwrap();
    let anchor = make_anchor(ca_vk, "https://ca.test", 0, 999); // expired at t=999
    let cert = make_cert_for_ca(&dev_vk, "https://ca.test", ca_seed.as_bytes());
    assert!(matches!(
        validate_chain(cert, vec![], &anchor, 1_000),
        Err(PqRascvError::TrustAnchorExpired)
    ));
}

#[test]
fn not_yet_valid_trust_anchor_rejected() {
    let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
    let (_, dev_vk) = generate_ml_dsa_keypair().unwrap();
    let anchor = make_anchor(ca_vk, "https://ca.test", 5_000, u64::MAX); // not yet valid
    let cert = make_cert_for_ca(&dev_vk, "https://ca.test", ca_seed.as_bytes());
    assert!(matches!(
        validate_chain(cert, vec![], &anchor, 1_000),
        Err(PqRascvError::TrustAnchorExpired)
    ));
}

#[test]
fn compromised_historical_root_cannot_validate_new_device_cert() {
    // Simulates an attacker with a leaked root CA private key whose validity
    // window has closed. The cert is correctly signed but the anchor is expired.
    let (old_ca_seed, old_ca_vk) = generate_ml_dsa_keypair().unwrap();
    let (_, dev_vk) = generate_ml_dsa_keypair().unwrap();
    // Old CA was valid 0–1999; attacker uses it at t=2000
    let old_anchor = make_anchor(old_ca_vk, "https://old-ca.test", 0, 1_999);
    let cert = make_cert_for_ca(&dev_vk, "https://old-ca.test", old_ca_seed.as_bytes());
    assert!(matches!(
        validate_chain(cert, vec![], &old_anchor, 2_000),
        Err(PqRascvError::TrustAnchorExpired)
    ), "cert signed by expired root must be rejected even with valid signature");
}

#[test]
fn rollover_accepts_cert_from_either_active_anchor() {
    let (old_seed, old_vk) = generate_ml_dsa_keypair().unwrap();
    let (new_seed, new_vk) = generate_ml_dsa_keypair().unwrap();
    let (_, dev_vk1) = generate_ml_dsa_keypair().unwrap();
    let (_, dev_vk2) = generate_ml_dsa_keypair().unwrap();

    // Overlapping window: old valid 0–3000, new valid 2000–MAX
    let store = TrustStore::new(make_anchor(old_vk, "https://old-ca.test", 0, 3_000))
        .with_rollover(make_anchor(new_vk, "https://new-ca.test", 2_000, u64::MAX));

    let cert_from_old = make_cert_for_ca(&dev_vk1, "https://old-ca.test", old_seed.as_bytes());
    let cert_from_new = make_cert_for_ca(&dev_vk2, "https://new-ca.test", new_seed.as_bytes());

    // At t=2500 both CAs are in their validity window
    assert!(
        validate_chain_with_store(cert_from_old, vec![], &store, 2_500).is_ok(),
        "cert from old CA must be accepted while old CA is still valid"
    );
    assert!(
        validate_chain_with_store(cert_from_new, vec![], &store, 2_500).is_ok(),
        "cert from new CA must be accepted"
    );
}

#[test]
fn retired_rollover_anchor_does_not_validate_after_expiry() {
    let (old_seed, old_vk) = generate_ml_dsa_keypair().unwrap();
    let (new_seed, new_vk) = generate_ml_dsa_keypair().unwrap();
    let (_, dev_vk) = generate_ml_dsa_keypair().unwrap();

    // Old CA expired at t=2000
    let store = TrustStore::new(make_anchor(old_vk, "https://old-ca.test", 0, 2_000))
        .with_rollover(make_anchor(new_vk, "https://new-ca.test", 1_000, u64::MAX));

    // Cert signed by the OLD (expired) CA
    let cert = make_cert_for_ca(&dev_vk, "https://old-ca.test", old_seed.as_bytes());

    // At t=3000 old CA is expired; new CA is valid but ca_id doesn't match
    let result = validate_chain_with_store(cert, vec![], &store, 3_000);
    assert!(result.is_err(), "cert signed by expired anchor must be rejected");
}

#[test]
fn stale_trust_store_with_all_anchors_expired_fails_explicitly() {
    let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
    let (_, dev_vk) = generate_ml_dsa_keypair().unwrap();

    // Both anchors expired
    let store = TrustStore::new(make_anchor(ca_vk, "https://ca.test", 0, 999));
    let cert = make_cert_for_ca(&dev_vk, "https://ca.test", ca_seed.as_bytes());

    assert!(matches!(
        validate_chain_with_store(cert, vec![], &store, 2_000),
        Err(PqRascvError::TrustAnchorExpired)
    ), "stale store must return TrustAnchorExpired, not CertificateInvalid");
}

#[test]
fn chain_validation_populates_trust_anchor_audit_fields() {
    use pqrascv_core::crypto::pub_key_id;
    let (ca_seed, ca_vk) = generate_ml_dsa_keypair().unwrap();
    let (_, dev_vk) = generate_ml_dsa_keypair().unwrap();
    let expected_fingerprint = pub_key_id(&ca_vk);
    let anchor = make_anchor(ca_vk, "https://ca.audit-test", 1_000, 9_000);
    let cert = make_cert_for_ca(&dev_vk, "https://ca.audit-test", ca_seed.as_bytes());

    let chain = validate_chain(cert, vec![], &anchor, 5_000).unwrap();
    assert_eq!(chain.trust_anchor.ca_id, "https://ca.audit-test");
    assert_eq!(chain.trust_anchor.fingerprint, expected_fingerprint);
    assert_eq!(chain.trust_anchor.not_before, 1_000);
    assert_eq!(chain.trust_anchor.not_after, 9_000);
}
```

- [ ] **Step 2: Run adversarial tests to confirm they fail (before the implementations are in)**

```
cargo test -p pqrascv-core --features std,software-rot-unsafe,alloc -- --test adversarial_tests 2>&1 | grep -E "FAILED|error\[" | head -20
```

Expected: compile errors about `make_anchor`, `make_cert_for_ca`, `validate_chain_with_store`, `TrustStore` not in scope. (They will compile once imports are added.)

- [ ] **Step 3: Fix the import block at the top of `adversarial_tests.rs`**

Update the existing `use pqrascv_core::pki::{...}` import to add the new items:

```rust
use pqrascv_core::{
    config::PolicyConfig,
    crypto::{
        generate_ml_dsa_keypair, CryptoBackend, MlDsaBackend,
        SIGNING_CONTEXT_CERT, SIGNING_CONTEXT_CRL, SIGNING_CONTEXT_QUOTE,
    },
    error::PqRascvError,
    measurement::SoftwareRoT,
    nonce::{InMemoryNonceLedger, NonceLedger},
    pki::{
        build_device_certificate, validate_chain, validate_chain_with_store,
        CaPublicKey, HardwareIdentity, TrustAnchor, TrustStore, CERT_VERSION,
    },
    provenance::SlsaPredicateBuilder,
    quote::{generate_quote, AttestationQuote, QuoteTimestamp},
};
use pqrascv_verifier::Verifier;
```

- [ ] **Step 4: Run adversarial tests**

```
cargo test -p pqrascv-core --features std,software-rot-unsafe -- adversarial 2>&1
```

Expected: all 17 adversarial tests pass (10 existing + 7 new lifecycle tests).

- [ ] **Step 5: Full workspace + clippy**

```
cargo test --workspace --features std,software-rot-unsafe,dice 2>&1
cargo clippy --workspace --features std,software-rot-unsafe,dice -- -D warnings 2>&1
```

Expected: all tests pass, no clippy warnings.

- [ ] **Step 6: Commit**

```
git add crates/pqrascv-core/tests/adversarial_tests.rs
git commit -m "test(adversarial): add 7 root lifecycle tests — expired anchor, rollover, stale store, historical compromise"
```

---

## Self-Review

### Spec coverage

| Requirement | Task |
|---|---|
| TrustAnchor has `not_before`/`not_after` | Task 2 |
| TrustAnchor has `root_identifier` (`ca_id`) | Task 2 (was already present, now `String`) |
| TrustAnchor has `public_key`, `path_constraints`, `key_usage` | `public_key` = `key_bytes` (already present); `path_constraints`/`key_usage` are CA-cert-level concerns encoded in `DeviceCertificate.max_path_length` and out of scope for a root-key trust anchor — the audit finding was specifically about temporal validity |
| `validate_chain` rejects expired, not-yet-valid, invalid rollover | Task 3 |
| Overlapping validity windows / staged migration | Task 5 (TrustStore) |
| Multi-root trust store | Task 5 |
| Root epoch transitions | Task 5 (`with_rollover` + `valid_anchors_at`) |
| Verification results expose root identifier, validity state | Task 7 (`trust_anchor_id`, `trust_anchor_valid_until`, `trust_anchor_fingerprint`) |
| Adversarial tests: expired root, historical reuse, rollover confusion, forged intermediates, stale store | Task 8 |
| Doc invariant: never claim "all certs temporally validated" without root | Task 3 (doc update) |
| Fail-closed: expired/invalid root → explicit error | Tasks 3, 6 (`TrustAnchorExpired`) |

**Gaps addressed:** `key_usage` and `path_constraints` are not separate fields on `TrustAnchor` because the root anchor in this system is a raw public key (not an X.509 cert) — `max_path_length` on intermediate `DeviceCertificate`s already enforces path constraints. Adding unused fields would violate YAGNI.

### Placeholder scan
None found — every step contains actual code.

### Type consistency
- `CaPublicKey.ca_id: String` everywhere (Tasks 2–8)
- `TrustAnchorInfo` fields: `ca_id: String`, `fingerprint: [u8; 32]`, `not_before: u64`, `not_after: u64` — consistent across Tasks 2, 3, 7, 8
- `validate_chain_with_store` signature consistent between Task 6 (impl) and Task 7 (caller)
- `TrustStore` builder pattern (`with_rollover`) consistent between Task 5 and all call sites
