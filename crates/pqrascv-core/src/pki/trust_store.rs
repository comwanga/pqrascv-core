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

#[cfg(feature = "alloc")]
impl TrustStore {
    /// Creates a trust store from a single primary trust anchor.
    #[must_use]
    pub fn new(primary: TrustAnchor) -> Self {
        Self {
            anchors: alloc::vec![primary],
        }
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

#[cfg(all(test, feature = "alloc", feature = "std"))]
mod tests {
    use super::*;
    use crate::crypto::generate_ml_dsa_keypair;
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
