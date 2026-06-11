//! CA key rollover and trust-anchor rotation workflows.
//!
//! Enterprise PKI must rotate signing keys and trust anchors *without* a
//! verification gap for certificates already in the field. This module
//! expresses those workflows as testable logic over the existing
//! [`TrustAnchor`](super::TrustAnchor), [`TrustStore`](super::TrustStore),
//! [`CaPublicKey`](super::CaPublicKey), and
//! [`RevocationList`](super::RevocationList) types. It introduces **no** new
//! certificate format.
//!
//! # The overlap window
//!
//! Rotation is never instantaneous. Both the old and the new key/anchor must be
//! simultaneously trusted for an *overlap window* so that:
//!
//! - certificates signed under the **old** key remain verifiable until every
//!   such cert has expired or been re-issued, and
//! - certificates signed under the **new** key are accepted immediately.
//!
//! ```text
//! old anchor:  [────────────── valid ──────────────]
//! new anchor:                 [────────── valid ──────────── … ]
//!                             └── overlap ──┘
//!                          (both trusted here)
//! ```
//!
//! An [`OverlapWindow`] captures `[overlap_start, overlap_end)` and the two
//! key validity spans. After `overlap_end` the old key is *retired*
//! (its `not_after` has passed) and only the new key validates new chains.
//!
//! # Trust-anchor rotation
//!
//! [`begin_trust_anchor_rotation`] takes an existing [`TrustStore`] and adds a
//! successor anchor whose validity starts inside the predecessor's window,
//! yielding a store where both anchors are valid during the overlap. The
//! existing [`validate_chain_with_store`](super::validate_chain_with_store)
//! already tries every valid anchor, so in-flight chains never see a gap.
//!
//! # Revocation continuity
//!
//! When a CA rolls over, a certificate revoked under the *old* CA must stay
//! revoked under the *new* CA. [`carry_forward_revocations`] merges the old
//! CRL's entries into the successor CRL's entry set (de-duplicated by serial),
//! so the operator can publish a fresh CRL under the new key that still lists
//! everything the old CRL did.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::revocation::RevocationEntry;
use super::{CaPublicKey, TrustAnchor, TrustStore};
use crate::error::PqRascvError;

/// A rotation overlap window during which both the old and new key are trusted.
///
/// Construct with [`OverlapWindow::new`]. Use [`OverlapWindow::is_in_overlap`]
/// to check whether a timestamp falls inside the dual-trust period, and
/// [`OverlapWindow::old_is_retired`] to check whether the old key has been
/// retired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlapWindow {
    /// Unix seconds: old key becomes valid.
    pub old_not_before: u64,
    /// Unix seconds: old key is retired (its `not_after`).
    pub old_not_after: u64,
    /// Unix seconds: new key becomes valid.
    pub new_not_before: u64,
    /// Unix seconds: new key expires.
    pub new_not_after: u64,
}

impl OverlapWindow {
    /// Builds an overlap window for a rotation.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::CertificateInvalid`] if:
    /// - either key span is inverted (`not_before > not_after`), or
    /// - the new key starts at-or-after the old key retires (no overlap), which
    ///   would leave a verification gap.
    pub fn new(
        old_not_before: u64,
        old_not_after: u64,
        new_not_before: u64,
        new_not_after: u64,
    ) -> Result<Self, PqRascvError> {
        if old_not_before > old_not_after || new_not_before > new_not_after {
            return Err(PqRascvError::CertificateInvalid);
        }
        // The new key must come online before the old one retires, otherwise
        // chains in flight at the boundary would have no valid anchor.
        if new_not_before >= old_not_after {
            return Err(PqRascvError::CertificateInvalid);
        }
        // The new key must outlive the old key's retirement for continuity.
        if new_not_after < old_not_after {
            return Err(PqRascvError::CertificateInvalid);
        }
        Ok(Self {
            old_not_before,
            old_not_after,
            new_not_before,
            new_not_after,
        })
    }

    /// Returns the `[start, end)` of the dual-trust overlap period.
    #[must_use]
    pub fn overlap_bounds(&self) -> (u64, u64) {
        (self.new_not_before, self.old_not_after)
    }

    /// Returns `true` if `now_secs` is within the dual-trust overlap, i.e. both
    /// the old and new key are valid.
    #[must_use]
    pub fn is_in_overlap(&self, now_secs: u64) -> bool {
        self.old_key_valid_at(now_secs) && self.new_key_valid_at(now_secs)
    }

    /// Returns `true` if the old key is valid at `now_secs`.
    #[must_use]
    pub fn old_key_valid_at(&self, now_secs: u64) -> bool {
        now_secs >= self.old_not_before && now_secs <= self.old_not_after
    }

    /// Returns `true` if the new key is valid at `now_secs`.
    #[must_use]
    pub fn new_key_valid_at(&self, now_secs: u64) -> bool {
        now_secs >= self.new_not_before && now_secs <= self.new_not_after
    }

    /// Returns `true` once the old key has been retired (`now_secs` past its
    /// `not_after`). After this point only the new key should validate chains.
    #[must_use]
    pub fn old_is_retired(&self, now_secs: u64) -> bool {
        now_secs > self.old_not_after
    }
}

/// Builds the successor [`CaPublicKey`] for a CA key rollover.
///
/// The successor shares the same logical CA identity (`ca_id`) but carries a new
/// public key and the new validity span from `window`. Certificates issued
/// before the rollover were signed by the predecessor key and continue to
/// validate against the predecessor anchor during the overlap; certificates
/// issued after are signed by the successor key.
///
/// `new_key_bytes` is the verifying key exported from the
/// [`KeyProvider`](super::key_provider::KeyProvider) successor handle (see
/// [`KeyProvider::rotate`](super::key_provider::KeyProvider::rotate)).
#[must_use]
pub fn rolled_over_ca_key(
    ca_id: String,
    new_key_bytes: [u8; crate::crypto::ML_DSA_65_VERIFYING_KEY_SIZE],
    window: &OverlapWindow,
) -> CaPublicKey {
    CaPublicKey {
        key_bytes: new_key_bytes,
        ca_id,
        not_before: window.new_not_before,
        not_after: window.new_not_after,
    }
}

/// Begins a trust-anchor rotation by adding a successor anchor to the store.
///
/// The successor anchor is appended; during the overlap window
/// [`TrustStore::valid_anchors_at`](super::TrustStore::valid_anchors_at) returns
/// both anchors, and
/// [`validate_chain_with_store`](super::validate_chain_with_store) accepts
/// chains rooted at either. This provides continuity: in-flight certs signed
/// under the old anchor keep validating until the old anchor's `not_after`
/// passes, while certs under the new anchor are accepted immediately.
///
/// # Errors
///
/// Returns [`PqRascvError::CertificateInvalid`] if `successor`'s validity span
/// does not overlap the predecessor window (i.e. it would create a gap). The
/// caller supplies `window` describing the intended rotation; this function
/// checks the successor anchor matches the new-key span in `window`.
pub fn begin_trust_anchor_rotation(
    store: TrustStore,
    successor: TrustAnchor,
    window: &OverlapWindow,
) -> Result<TrustStore, PqRascvError> {
    // The successor anchor must line up with the new-key span of the window so
    // that the dual-trust overlap actually holds.
    if successor.not_before() != window.new_not_before
        || successor.not_after() != window.new_not_after
    {
        return Err(PqRascvError::CertificateInvalid);
    }
    Ok(store.with_rollover(successor))
}

/// Merges the old CRL's entries forward into the successor CRL entry set.
///
/// Guarantees **revocation continuity**: any serial revoked under the old CA
/// remains present after a rollover. Entries are de-duplicated by `serial`;
/// when a serial appears in both lists the entry from `successor_entries` wins
/// (it is assumed at-least-as-recent). The result is sorted by serial for a
/// deterministic, signable CRL body.
///
/// The operator signs the returned entry list with the **new** CA key to
/// publish a fresh CRL that still lists everything the old CRL did.
#[must_use]
pub fn carry_forward_revocations(
    old_entries: &[RevocationEntry],
    successor_entries: &[RevocationEntry],
) -> Vec<RevocationEntry> {
    use alloc::collections::BTreeMap;

    let mut merged: BTreeMap<String, RevocationEntry> = BTreeMap::new();
    // Seed with old entries first…
    for e in old_entries {
        merged.insert(e.serial.clone(), e.clone());
    }
    // …then let successor entries override on serial collision.
    for e in successor_entries {
        merged.insert(e.serial.clone(), e.clone());
    }
    merged.into_values().collect()
}

#[cfg(all(test, feature = "alloc", feature = "std"))]
mod tests {
    use super::*;
    use crate::crypto::{generate_ml_dsa_keypair, SIGNING_CONTEXT_CERT};
    use crate::pki::key_provider::{KeyProvider, SoftwareKeyProvider};
    use crate::pki::revocation::{RevocationList, RevocationReason};
    use crate::pki::{
        validate_chain_with_store, CaPublicKey, DeviceCertificate, HardwareIdentity, TrustAnchor,
        TrustStore, CERT_VERSION,
    };

    fn anchor(ca_id: &str, key: &[u8; 1952], not_before: u64, not_after: u64) -> TrustAnchor {
        TrustAnchor::new(CaPublicKey {
            key_bytes: *key,
            ca_id: ca_id.to_string(),
            not_before,
            not_after,
        })
        .unwrap()
    }

    fn sign_cert_with(provider: &SoftwareKeyProvider, handle: u64, cert: &mut DeviceCertificate) {
        let tbs = cert.tbs_cbor().unwrap();
        let sig = provider.sign(handle, &tbs, SIGNING_CONTEXT_CERT).unwrap();
        cert.issuer_signature = sig.as_ref().to_vec();
    }

    fn device_cert(
        provider: &SoftwareKeyProvider,
        signer: u64,
        dev_vk: &[u8],
        issuer_id: &str,
        serial: &str,
        not_before: u64,
        not_after: u64,
    ) -> DeviceCertificate {
        let subject_key_id = crate::crypto::pub_key_id(dev_vk);
        let mut cert = DeviceCertificate {
            version: CERT_VERSION,
            serial: serial.to_string(),
            issuer_id: issuer_id.to_string(),
            not_before,
            not_after,
            subject_key: dev_vk.to_vec(),
            subject_key_id,
            hardware_identity: HardwareIdentity::TpmEkCertHash([0u8; 32]),
            fw_policy: None,
            issuer_signature: alloc::vec![],
            self_id: "https://dev.test".to_string(),
            max_path_length: Some(0),
        };
        sign_cert_with(provider, signer, &mut cert);
        cert
    }

    #[test]
    fn overlap_window_rejects_gap() {
        // new starts after old retires → gap → rejected.
        assert!(matches!(
            OverlapWindow::new(0, 1_000, 2_000, u64::MAX),
            Err(PqRascvError::CertificateInvalid)
        ));
    }

    #[test]
    fn overlap_window_rejects_inverted_span() {
        assert!(OverlapWindow::new(1_000, 0, 500, u64::MAX).is_err());
    }

    #[test]
    fn overlap_window_detects_dual_trust_period() {
        let w = OverlapWindow::new(0, 3_000, 2_000, u64::MAX).unwrap();
        assert!(!w.is_in_overlap(1_000)); // only old
        assert!(w.is_in_overlap(2_500)); // both
        assert!(!w.is_in_overlap(4_000)); // only new
        assert!(!w.old_is_retired(3_000));
        assert!(w.old_is_retired(3_001));
    }

    #[test]
    fn root_rollover_both_anchors_trusted_during_overlap() {
        let mut prov = SoftwareKeyProvider::new();
        prov.open_session().unwrap();
        let old_h = prov.generate_keypair().unwrap();
        let old_vk = prov.public_key(old_h).unwrap();

        let window = OverlapWindow::new(0, 3_000, 2_000, u64::MAX).unwrap();
        let store = TrustStore::new(anchor("https://root.ca", &old_vk, 0, 3_000));

        // Rotate the root key via the provider, derive successor anchor.
        let new_h = prov.rotate(old_h).unwrap();
        let new_vk = prov.public_key(new_h).unwrap();
        let successor = anchor("https://root.ca", &new_vk, 2_000, u64::MAX);
        let store = begin_trust_anchor_rotation(store, successor, &window).unwrap();

        // A device cert signed under the OLD root, validated mid-overlap.
        let (_, dev_vk) = generate_ml_dsa_keypair().unwrap();
        let old_cert = device_cert(
            &prov,
            old_h,
            &dev_vk,
            "https://root.ca",
            "DEV-OLD",
            0,
            u64::MAX,
        );
        // A device cert signed under the NEW root.
        let (_, dev_vk2) = generate_ml_dsa_keypair().unwrap();
        let new_cert = device_cert(
            &prov,
            new_h,
            &dev_vk2,
            "https://root.ca",
            "DEV-NEW",
            0,
            u64::MAX,
        );

        assert!(
            validate_chain_with_store(&old_cert, &[], &store, 2_500).is_ok(),
            "old-CA cert must validate during overlap"
        );
        assert!(
            validate_chain_with_store(&new_cert, &[], &store, 2_500).is_ok(),
            "new-CA cert must validate during overlap"
        );
    }

    #[test]
    fn root_rollover_old_retired_after_window() {
        let mut prov = SoftwareKeyProvider::new();
        prov.open_session().unwrap();
        let old_h = prov.generate_keypair().unwrap();
        let old_vk = prov.public_key(old_h).unwrap();
        let window = OverlapWindow::new(0, 3_000, 2_000, u64::MAX).unwrap();
        let store = TrustStore::new(anchor("https://root.ca", &old_vk, 0, 3_000));
        let new_h = prov.rotate(old_h).unwrap();
        let new_vk = prov.public_key(new_h).unwrap();
        let successor = anchor("https://root.ca", &new_vk, 2_000, u64::MAX);
        let store = begin_trust_anchor_rotation(store, successor, &window).unwrap();

        let (_, dev_vk) = generate_ml_dsa_keypair().unwrap();
        let old_cert = device_cert(
            &prov,
            old_h,
            &dev_vk,
            "https://root.ca",
            "DEV-OLD",
            0,
            u64::MAX,
        );
        let (_, dev_vk2) = generate_ml_dsa_keypair().unwrap();
        let new_cert = device_cert(
            &prov,
            new_h,
            &dev_vk2,
            "https://root.ca",
            "DEV-NEW",
            0,
            u64::MAX,
        );

        // After the old anchor's not_after (3000), only the new anchor is live.
        assert!(
            validate_chain_with_store(&old_cert, &[], &store, 4_000).is_err(),
            "old-CA cert must be rejected after old anchor retires"
        );
        assert!(
            validate_chain_with_store(&new_cert, &[], &store, 4_000).is_ok(),
            "new-CA cert must still validate after old anchor retires"
        );
    }

    #[test]
    fn begin_rotation_rejects_mismatched_successor_window() {
        let (_, vk) = generate_ml_dsa_keypair().unwrap();
        let store = TrustStore::new(anchor("https://root.ca", &vk, 0, 3_000));
        let (_, vk2) = generate_ml_dsa_keypair().unwrap();
        let window = OverlapWindow::new(0, 3_000, 2_000, u64::MAX).unwrap();
        // Successor anchor not_before (1234) does not match window.new_not_before (2000).
        let bad_successor = anchor("https://root.ca", &vk2, 1_234, u64::MAX);
        assert!(matches!(
            begin_trust_anchor_rotation(store, bad_successor, &window),
            Err(PqRascvError::CertificateInvalid)
        ));
    }

    #[test]
    fn intermediate_rollover_old_and_new_intermediates_validate() {
        // Root signs two intermediates (old + new) sharing the same self_id.
        // Device certs under each intermediate must both validate during overlap.
        let mut prov = SoftwareKeyProvider::new();
        prov.open_session().unwrap();
        let root_h = prov.generate_keypair().unwrap();
        let root_vk = prov.public_key(root_h).unwrap();
        let store = TrustStore::new(anchor("https://root.ca", &root_vk, 0, u64::MAX));

        // Old intermediate key + new intermediate key (the rollover).
        let int_old_h = prov.generate_keypair().unwrap();
        let int_old_vk = prov.public_key(int_old_h).unwrap();
        let int_new_h = prov.rotate(int_old_h).unwrap();
        let int_new_vk = prov.public_key(int_new_h).unwrap();

        let window = OverlapWindow::new(0, 3_000, 2_000, u64::MAX).unwrap();

        // Build old + new intermediate certs (issued by root), same self_id.
        let mut int_old = device_cert(
            &prov,
            root_h,
            &int_old_vk,
            "https://root.ca",
            "INT-OLD",
            window.old_not_before,
            window.old_not_after,
        );
        int_old.self_id = "https://mfr.int".to_string();
        int_old.max_path_length = Some(1);
        sign_cert_with(&prov, root_h, &mut int_old);

        let mut int_new = device_cert(
            &prov,
            root_h,
            &int_new_vk,
            "https://root.ca",
            "INT-NEW",
            window.new_not_before,
            window.new_not_after,
        );
        int_new.self_id = "https://mfr.int".to_string();
        int_new.max_path_length = Some(1);
        sign_cert_with(&prov, root_h, &mut int_new);

        // Device certs: one under the old intermediate, one under the new.
        let (_, dev_vk_a) = generate_ml_dsa_keypair().unwrap();
        let dev_a = device_cert(
            &prov,
            int_old_h,
            &dev_vk_a,
            "https://mfr.int",
            "DEV-A",
            0,
            u64::MAX,
        );
        let (_, dev_vk_b) = generate_ml_dsa_keypair().unwrap();
        let dev_b = device_cert(
            &prov,
            int_new_h,
            &dev_vk_b,
            "https://mfr.int",
            "DEV-B",
            0,
            u64::MAX,
        );

        // Mid-overlap: both intermediates are temporally valid.
        assert!(
            validate_chain_with_store(&dev_a, &[int_old.clone()], &store, 2_500).is_ok(),
            "device under OLD intermediate must validate during overlap"
        );
        assert!(
            validate_chain_with_store(&dev_b, &[int_new.clone()], &store, 2_500).is_ok(),
            "device under NEW intermediate must validate during overlap"
        );

        // After the old intermediate retires, only the new chain validates.
        assert!(
            validate_chain_with_store(&dev_a, &[int_old], &store, 4_000).is_err(),
            "device under OLD intermediate must fail after it retires"
        );
        assert!(
            validate_chain_with_store(&dev_b, &[int_new], &store, 4_000).is_ok(),
            "device under NEW intermediate must validate after old retires"
        );
    }

    #[test]
    fn carry_forward_preserves_old_revocations() {
        let old = alloc::vec![
            RevocationEntry {
                serial: "DEV-COMPROMISED".to_string(),
                revoked_at: 1_000,
                reason: RevocationReason::KeyCompromise,
            },
            RevocationEntry {
                serial: "DEV-DECOM".to_string(),
                revoked_at: 1_100,
                reason: RevocationReason::Decommissioned,
            },
        ];
        let new = alloc::vec![RevocationEntry {
            serial: "DEV-NEWLY-BAD".to_string(),
            revoked_at: 2_000,
            reason: RevocationReason::KeyCompromise,
        }];
        let merged = carry_forward_revocations(&old, &new);
        let serials: Vec<&str> = merged.iter().map(|e| e.serial.as_str()).collect();
        assert!(serials.contains(&"DEV-COMPROMISED"));
        assert!(serials.contains(&"DEV-DECOM"));
        assert!(serials.contains(&"DEV-NEWLY-BAD"));
        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn carry_forward_dedups_by_serial_successor_wins() {
        let old = alloc::vec![RevocationEntry {
            serial: "DUP".to_string(),
            revoked_at: 1_000,
            reason: RevocationReason::Superseded,
        }];
        let new = alloc::vec![RevocationEntry {
            serial: "DUP".to_string(),
            revoked_at: 2_000,
            reason: RevocationReason::KeyCompromise,
        }];
        let merged = carry_forward_revocations(&old, &new);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].reason, RevocationReason::KeyCompromise);
        assert_eq!(merged[0].revoked_at, 2_000);
    }

    #[test]
    fn revoked_cert_stays_revoked_across_rollover() {
        // A cert revoked under the OLD CA must remain revoked after the CA's key
        // rolls over and a fresh CRL is signed with the NEW key.
        let mut prov = SoftwareKeyProvider::new();
        prov.open_session().unwrap();
        let old_h = prov.generate_keypair().unwrap();
        let old_vk = prov.public_key(old_h).unwrap();
        let new_h = prov.rotate(old_h).unwrap();
        let new_vk = prov.public_key(new_h).unwrap();

        // OLD CRL signed by the old key (via the provider), listing DEV-BAD.
        let old_crl_entries = alloc::vec![RevocationEntry {
            serial: "DEV-BAD".to_string(),
            revoked_at: 1_000,
            reason: RevocationReason::KeyCompromise,
        }];
        let mut old_crl = RevocationList {
            issuer_id: "https://ca.test".to_string(),
            this_update: 1_000,
            next_update: 9_999_999,
            entries: old_crl_entries.clone(),
            issuer_signature: alloc::vec![],
        };
        let old_tbs = old_crl.tbs_cbor().unwrap();
        old_crl.issuer_signature = prov
            .sign(old_h, &old_tbs, crate::crypto::SIGNING_CONTEXT_CRL)
            .unwrap()
            .as_ref()
            .to_vec();

        // Verify old CRL under the OLD key — DEV-BAD is revoked.
        let verified_old = old_crl.verify(&old_vk, 2_000).unwrap();
        assert!(verified_old.is_revoked("DEV-BAD"));

        // Roll over: carry old entries forward, sign a NEW CRL with the new key.
        let successor_new_entries: Vec<RevocationEntry> = alloc::vec![];
        let carried = carry_forward_revocations(&old_crl_entries, &successor_new_entries);
        let mut new_crl = RevocationList {
            issuer_id: "https://ca.test".to_string(),
            this_update: 3_000,
            next_update: 9_999_999,
            entries: carried,
            issuer_signature: alloc::vec![],
        };
        let new_tbs = new_crl.tbs_cbor().unwrap();
        new_crl.issuer_signature = prov
            .sign(new_h, &new_tbs, crate::crypto::SIGNING_CONTEXT_CRL)
            .unwrap()
            .as_ref()
            .to_vec();

        // The NEW CRL verifies under the NEW key and still revokes DEV-BAD.
        let verified_new = new_crl.verify(&new_vk, 3_500).unwrap();
        assert!(
            verified_new.is_revoked("DEV-BAD"),
            "cert revoked under old CA must remain revoked after rollover"
        );
        // Sanity: the new CRL does NOT verify under the old key.
        assert!(new_crl.verify(&old_vk, 3_500).is_err());
    }

    #[test]
    fn rolled_over_ca_key_carries_new_window() {
        let (_, vk) = generate_ml_dsa_keypair().unwrap();
        let window = OverlapWindow::new(0, 3_000, 2_000, 9_000).unwrap();
        let ca = rolled_over_ca_key("https://root.ca".to_string(), vk, &window);
        assert_eq!(ca.not_before, 2_000);
        assert_eq!(ca.not_after, 9_000);
        assert_eq!(ca.ca_id, "https://root.ca");
    }
}
