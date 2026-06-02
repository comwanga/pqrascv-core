//! Federation and provenance finality anchoring (Phase 7F + 7G).
//!
//! The [`AnchorBuilder`](crate::builder::AnchorBuilder) is artifact-agnostic:
//! anything that reduces to a 32-byte root can be anchored. This module provides
//! the two governance/identity artifact types the program calls out, with a
//! canonical, deterministic commitment so they can be timestamped on Bitcoin:
//!
//! - **7F** [`FederationCheckpoint`] — a federation governance checkpoint
//!   (policy / membership / quorum state at an epoch), chained to its
//!   predecessor to form an immutable governance history.
//! - **7G** [`ProvenanceAnchor`] — a `VerifiedProvenance` finality record, so a
//!   firmware identity survives PKI changes, vendor disappearance, and
//!   infrastructure migration.
//!
//! Both implement [`Anchorable`], so `lifecycle.create_anchor_for(&item, …)`
//! turns them into an OP_RETURN anchor transaction.
//!
//! Commitments use SHA3-256 over a length-delimited canonical encoding, matching
//! the core aggregator's quote-hash convention. The provenance crate is *not* a
//! dependency: a `VerifiedProvenance` is anchored via its already-computed
//! canonical digest, keeping this crate decoupled from `pqrascv-core`.

use pqrascv_bitcoin_anchor::AnchorCommitment;
use sha3::{Digest as _, Sha3_256};

/// Domain tags keep the two artifact kinds in disjoint commitment spaces so a
/// federation root can never collide with a provenance root.
const TAG_FEDERATION: &[u8] = b"pqrascv-fed-checkpoint-v1";
const TAG_PROVENANCE: &[u8] = b"pqrascv-provenance-v1";

/// Anything that can be reduced to a Bitcoin anchor commitment.
pub trait Anchorable {
    /// The 32-byte canonical commitment root for this artifact.
    fn commitment_root(&self) -> [u8; 32];

    /// The [`AnchorCommitment`] (OP_RETURN payload) for this artifact.
    fn anchor_commitment(&self) -> AnchorCommitment {
        AnchorCommitment::new(self.commitment_root())
    }
}

/// Appends a length-prefixed field to a canonical encoding buffer.
fn put(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
    buf.extend_from_slice(field);
}

// ── 7F: Federation checkpoint ──────────────────────────────────────────────

/// A federation governance checkpoint: the policy, membership, and quorum state
/// at a given epoch, chained to its predecessor.
///
/// Anchoring successive checkpoints — each committing to `previous` — yields an
/// immutable, Bitcoin-timestamped governance history: policy changes, membership
/// changes, and quorum transitions cannot be silently rewritten.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationCheckpoint {
    /// Monotonic governance epoch.
    pub epoch: u64,
    /// Commitment of the previous checkpoint (`None` for the genesis checkpoint).
    pub previous: Option<[u8; 32]>,
    /// Root committing to the active policy set.
    pub policy_root: [u8; 32],
    /// Root committing to the federation membership set.
    pub membership_root: [u8; 32],
    /// Canonical encoding of the quorum descriptor (e.g. threshold parameters).
    pub quorum_descriptor: Vec<u8>,
}

impl Anchorable for FederationCheckpoint {
    fn commitment_root(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        put(&mut buf, TAG_FEDERATION);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        // Presence byte + value so genesis (None) and a zero-root predecessor differ.
        match &self.previous {
            Some(p) => {
                buf.push(1);
                put(&mut buf, p);
            }
            None => buf.push(0),
        }
        put(&mut buf, &self.policy_root);
        put(&mut buf, &self.membership_root);
        put(&mut buf, &self.quorum_descriptor);
        Sha3_256::digest(&buf).into()
    }
}

// ── 7G: Provenance finality ────────────────────────────────────────────────

/// A finality record for a `VerifiedProvenance`, anchored so a firmware identity
/// survives PKI changes, vendor disappearance, and infrastructure migration.
///
/// Constructed from the provenance's already-computed canonical digest (the
/// caller hashes their `VerifiedProvenance`) plus the firmware identity it binds,
/// keeping this crate independent of `pqrascv-core`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceAnchor {
    /// Canonical digest of the `VerifiedProvenance` (e.g. SHA3-256 of its CBOR).
    pub provenance_digest: [u8; 32],
    /// The firmware identity the provenance attests.
    pub firmware_id: [u8; 32],
}

impl ProvenanceAnchor {
    /// Builds a provenance anchor from a provenance digest and firmware id.
    #[must_use]
    pub fn new(provenance_digest: [u8; 32], firmware_id: [u8; 32]) -> Self {
        Self {
            provenance_digest,
            firmware_id,
        }
    }
}

impl Anchorable for ProvenanceAnchor {
    fn commitment_root(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        put(&mut buf, TAG_PROVENANCE);
        put(&mut buf, &self.provenance_digest);
        put(&mut buf, &self.firmware_id);
        Sha3_256::digest(&buf).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(epoch: u64, previous: Option<[u8; 32]>) -> FederationCheckpoint {
        FederationCheckpoint {
            epoch,
            previous,
            policy_root: [0x11; 32],
            membership_root: [0x22; 32],
            quorum_descriptor: vec![0x03, 0x05], // e.g. 3-of-5
        }
    }

    #[test]
    fn federation_commitment_is_deterministic() {
        let a = checkpoint(1, None).commitment_root();
        let b = checkpoint(1, None).commitment_root();
        assert_eq!(a, b);
    }

    #[test]
    fn federation_checkpoints_chain_into_distinct_commitments() {
        let genesis = checkpoint(0, None);
        let groot = genesis.commitment_root();
        let next = checkpoint(1, Some(groot));
        // Different epoch + predecessor ⇒ different commitment.
        assert_ne!(genesis.commitment_root(), next.commitment_root());
    }

    #[test]
    fn genesis_differs_from_zero_predecessor() {
        // None (genesis) must not collide with an all-zero predecessor.
        let genesis = checkpoint(1, None);
        let zero_prev = checkpoint(1, Some([0u8; 32]));
        assert_ne!(genesis.commitment_root(), zero_prev.commitment_root());
    }

    #[test]
    fn membership_change_changes_the_commitment() {
        let base = checkpoint(5, None);
        let mut changed = base.clone();
        changed.membership_root = [0x99; 32];
        assert_ne!(base.commitment_root(), changed.commitment_root());
    }

    #[test]
    fn provenance_commitment_is_deterministic_and_binds_firmware() {
        let a = ProvenanceAnchor::new([0xAB; 32], [0xCD; 32]).commitment_root();
        let b = ProvenanceAnchor::new([0xAB; 32], [0xCD; 32]).commitment_root();
        assert_eq!(a, b);
        // Different firmware id ⇒ different commitment.
        let c = ProvenanceAnchor::new([0xAB; 32], [0xEF; 32]).commitment_root();
        assert_ne!(a, c);
    }

    #[test]
    fn federation_and_provenance_spaces_are_disjoint() {
        // A federation checkpoint and a provenance anchor that happen to share
        // input bytes must not produce the same root (domain separation).
        let fed = FederationCheckpoint {
            epoch: 0,
            previous: None,
            policy_root: [0; 32],
            membership_root: [0; 32],
            quorum_descriptor: vec![],
        };
        let prov = ProvenanceAnchor::new([0; 32], [0; 32]);
        assert_ne!(fed.commitment_root(), prov.commitment_root());
    }

    #[test]
    fn anchor_commitment_carries_the_root() {
        let cp = checkpoint(7, None);
        let commitment = cp.anchor_commitment();
        assert_eq!(commitment.merkle_root, cp.commitment_root());
    }
}
