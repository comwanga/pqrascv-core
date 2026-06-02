//! Federated Policy Epoch Management
//!
//! A [`FederatedPolicyEpoch`] is a versioned policy commitment that requires
//! quorum approval before it can govern any attestation evaluation.
//!
//! # Immutability After Finalization
//!
//! Once `try_finalize` succeeds and `quorum_reached == true`, the epoch is
//! considered **immutable**. Any further attempt to finalize it returns
//! [`FederatedPolicyError::EpochAlreadyFinalized`].
//!
//! # Split-Brain Rejection
//!
//! The [`FederatedPolicyRegistry`] rejects proposals that would introduce
//! two competing non-finalized epochs at the same `epoch_id`, and rejects
//! non-monotonic epoch proposals (a new epoch must have a strictly higher
//! `epoch_id` than any existing finalized epoch).
//!
//! # Fail-Closed
//!
//! An epoch that has not reached quorum MUST NOT be used as the basis for
//! policy decisions. The [`HardwarePolicyRule::RequireFederatedPolicyApproval`]
//! rule enforces this at evaluation time.
//!
//! # Approval Identity and Membership Validation
//!
//! Cryptographically authenticated approvals are recorded via
//! [`FederatedPolicyEpoch::add_signed_approval`]: each [`SignedApproval`] carries
//! an ML-DSA-65 signature over the canonical approval payload, verified against
//! the member's `public_key` before it is recorded, and **re-verified** in
//! `try_finalize`. Only signature-verified member approvals count toward quorum
//! — unsigned approvals recorded via the legacy [`FederatedPolicyEpoch::add_approval`]
//! never count. Phantom (non-member) IDs are excluded regardless. See
//! [`crate::federation_auth`] for the signing scheme.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::federation_auth::{approval_payload, verify_ml_dsa, CTX_APPROVAL};
use crate::verifier_federation::VerifierFederation;

// ── SignedApproval ────────────────────────────────────────────────────────

/// A cryptographically authenticated approval of a policy epoch.
///
/// The `signature` is an ML-DSA-65 signature, produced by the approving
/// verifier's signing key, over the canonical
/// [`approval_payload`](crate::federation_auth::approval_payload) binding the
/// federation id, epoch id, and predecessor epoch. Only approvals whose
/// signature verifies against the member's `public_key` are counted toward
/// quorum; see [`FederatedPolicyEpoch::try_finalize`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedApproval {
    /// The verifier that produced this approval.
    pub verifier_id: String,
    /// ML-DSA-65 signature over the canonical approval payload.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

// ── FederatedPolicyEpoch ──────────────────────────────────────────────────

/// A versioned policy epoch that requires quorum approval to become active.
///
/// # Lifecycle
///
/// 1. Created via `FederatedPolicyEpoch::new(epoch_id, created_at, previous_epoch)`.
/// 2. Each approving verifier calls `add_approval(verifier_id)`.
/// 3. When enough approvals accumulate, call `try_finalize(federation)`.
/// 4. Once finalized (`quorum_reached == true`), the epoch is immutable.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FederatedPolicyEpoch {
    /// Monotonically increasing epoch identifier.
    pub epoch_id: u64,
    /// Verifier IDs that have approved this epoch.
    ///
    /// Maintained for audit display and backward compatibility. Presence here
    /// does **not** imply the approval was authenticated — only entries with a
    /// matching, signature-verified [`SignedApproval`] count toward quorum.
    pub approved_by: Vec<String>,
    /// Cryptographically authenticated approvals.
    ///
    /// Defaults to empty when deserializing legacy epochs that predate signed
    /// approvals; such epochs simply have no counting approvals until re-approved.
    #[serde(default)]
    pub signed_approvals: Vec<SignedApproval>,
    /// `true` iff quorum approval has been confirmed and the epoch is immutable.
    pub quorum_reached: bool,
    /// Unix seconds when this epoch was proposed.
    pub created_at: u64,
    /// The `epoch_id` of the preceding epoch, if any.
    pub previous_epoch: Option<u64>,
}

impl FederatedPolicyEpoch {
    /// Creates a new, un-finalized epoch proposal.
    #[must_use]
    pub fn new(epoch_id: u64, created_at: u64, previous_epoch: Option<u64>) -> Self {
        Self {
            epoch_id,
            approved_by: Vec::new(),
            signed_approvals: Vec::new(),
            quorum_reached: false,
            created_at,
            previous_epoch,
        }
    }

    /// Records an approval from the given verifier.
    ///
    /// Duplicate approvals from the same verifier are silently deduplicated.
    pub fn add_approval(&mut self, verifier_id: String) -> Result<(), FederatedPolicyError> {
        if self.quorum_reached {
            return Err(FederatedPolicyError::EpochAlreadyFinalized {
                epoch_id: self.epoch_id,
            });
        }
        if !self.approved_by.contains(&verifier_id) {
            self.approved_by.push(verifier_id);
        }
        Ok(())
    }

    /// Records a cryptographically authenticated approval from a federation member.
    ///
    /// The approval's signature is verified against the claimed member's
    /// `public_key` over the canonical approval payload *before* it is recorded.
    /// Duplicate approvals from the same verifier are deduplicated.
    ///
    /// # Errors
    ///
    /// - [`FederatedPolicyError::EpochAlreadyFinalized`] if the epoch is immutable.
    /// - [`FederatedPolicyError::UnknownApprover`] if `verifier_id` is not a member.
    /// - [`FederatedPolicyError::InvalidApprovalSignature`] if the signature does
    ///   not verify against the member's public key.
    pub fn add_signed_approval(
        &mut self,
        approval: SignedApproval,
        federation: &VerifierFederation,
    ) -> Result<(), FederatedPolicyError> {
        if self.quorum_reached {
            return Err(FederatedPolicyError::EpochAlreadyFinalized {
                epoch_id: self.epoch_id,
            });
        }
        let member = federation
            .members
            .iter()
            .find(|m| m.verifier_id == approval.verifier_id)
            .ok_or_else(|| FederatedPolicyError::UnknownApprover {
                verifier_id: approval.verifier_id.clone(),
            })?;
        let payload = approval_payload(
            &federation.federation_id,
            self.epoch_id,
            self.previous_epoch,
            &approval.verifier_id,
        );
        if !verify_ml_dsa(
            &payload,
            CTX_APPROVAL,
            &member.public_key,
            &approval.signature,
        ) {
            return Err(FederatedPolicyError::InvalidApprovalSignature {
                verifier_id: approval.verifier_id.clone(),
            });
        }
        if !self
            .signed_approvals
            .iter()
            .any(|a| a.verifier_id == approval.verifier_id)
        {
            if !self.approved_by.contains(&approval.verifier_id) {
                self.approved_by.push(approval.verifier_id.clone());
            }
            self.signed_approvals.push(approval);
        }
        Ok(())
    }

    /// Attempts to finalize the epoch by checking if quorum has been reached.
    ///
    /// Only approvals that (a) belong to a current federation member and (b)
    /// carry a signature that re-verifies against that member's `public_key`
    /// are counted. Unsigned approvals recorded via [`Self::add_approval`] never
    /// count — federation finalization is fail-closed against unauthenticated
    /// mutations. Signatures are re-verified here (not merely trusted from
    /// admission time) so a membership change between approval and finalization
    /// cannot admit a stale or non-member approval.
    ///
    /// Sets `quorum_reached = true` and makes the epoch immutable on success.
    pub fn try_finalize(
        &mut self,
        federation: &VerifierFederation,
    ) -> Result<(), FederatedPolicyError> {
        if self.quorum_reached {
            return Err(FederatedPolicyError::EpochAlreadyFinalized {
                epoch_id: self.epoch_id,
            });
        }
        let member_keys: BTreeMap<&str, &[u8]> = federation
            .members
            .iter()
            .map(|m| (m.verifier_id.as_str(), m.public_key.as_slice()))
            .collect();
        let mut counted: BTreeSet<&str> = BTreeSet::new();
        for approval in &self.signed_approvals {
            if let Some(public_key) = member_keys.get(approval.verifier_id.as_str()) {
                let payload = approval_payload(
                    &federation.federation_id,
                    self.epoch_id,
                    self.previous_epoch,
                    &approval.verifier_id,
                );
                if verify_ml_dsa(&payload, CTX_APPROVAL, public_key, &approval.signature) {
                    counted.insert(approval.verifier_id.as_str());
                }
            }
        }
        let approval_count = counted.len();
        let required = federation.quorum_required();
        if approval_count < required {
            return Err(FederatedPolicyError::QuorumNotReached {
                approvals: approval_count,
                required,
            });
        }
        self.quorum_reached = true;
        Ok(())
    }
}

// ── FederatedPolicyRegistry ───────────────────────────────────────────────

/// A registry of federated policy epochs enforcing monotonicity and
/// split-brain rejection.
///
/// The registry maintains an ordered history of epochs. At most one
/// non-finalized epoch may exist at a time. New proposals must have a
/// strictly higher `epoch_id` than the last finalized epoch.
#[derive(Debug, Default)]
pub struct FederatedPolicyRegistry {
    epochs: Vec<FederatedPolicyEpoch>,
}

impl FederatedPolicyRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Proposes a new epoch.
    ///
    /// # Errors
    ///
    /// - [`FederatedPolicyError::NonMonotonicEpoch`] if `epoch_id` is not
    ///   greater than the last finalized epoch's id.
    /// - [`FederatedPolicyError::SplitBrainDetected`] if a non-finalized
    ///   epoch already exists.
    pub fn propose(&mut self, epoch: FederatedPolicyEpoch) -> Result<(), FederatedPolicyError> {
        // Reject if a non-finalized epoch already exists (split-brain guard)
        if self.epochs.iter().any(|e| !e.quorum_reached) {
            return Err(FederatedPolicyError::SplitBrainDetected);
        }
        // Monotonicity: new epoch_id must exceed the highest finalized epoch_id
        if let Some(last) = self.epochs.last() {
            if epoch.epoch_id <= last.epoch_id {
                return Err(FederatedPolicyError::NonMonotonicEpoch {
                    previous: last.epoch_id,
                    proposed: epoch.epoch_id,
                });
            }
        }
        self.epochs.push(epoch);
        Ok(())
    }

    /// Returns the currently active (latest finalized) epoch, if any.
    #[must_use]
    pub fn active_epoch(&self) -> Option<&FederatedPolicyEpoch> {
        self.epochs.iter().rev().find(|e| e.quorum_reached)
    }

    /// Returns the pending (non-finalized) epoch, if any.
    #[must_use]
    pub fn pending_epoch(&self) -> Option<&FederatedPolicyEpoch> {
        self.epochs.iter().find(|e| !e.quorum_reached)
    }

    /// Returns the pending epoch mutably, if any.
    pub fn pending_epoch_mut(&mut self) -> Option<&mut FederatedPolicyEpoch> {
        self.epochs.iter_mut().find(|e| !e.quorum_reached)
    }
}

// ── FederatedPolicyError ──────────────────────────────────────────────────

/// Errors from federated policy epoch management.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FederatedPolicyError {
    /// The epoch has not received enough approvals.
    QuorumNotReached { approvals: usize, required: usize },
    /// Two epochs with conflicting IDs would coexist.
    ConflictingEpoch { existing: u64, proposed: u64 },
    /// A non-finalized epoch already exists; split-brain is not permitted.
    SplitBrainDetected,
    /// The epoch was already finalized and is immutable.
    EpochAlreadyFinalized { epoch_id: u64 },
    /// The proposed `epoch_id` is not strictly greater than the last finalized epoch.
    NonMonotonicEpoch { previous: u64, proposed: u64 },
    /// A signed approval named a verifier that is not a federation member.
    UnknownApprover { verifier_id: String },
    /// A signed approval's signature failed to verify against the member's key.
    InvalidApprovalSignature { verifier_id: String },
}

impl core::fmt::Display for FederatedPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::QuorumNotReached {
                approvals,
                required,
            } => write!(
                f,
                "epoch quorum not reached: {approvals} approvals, {required} required"
            ),
            Self::ConflictingEpoch { existing, proposed } => write!(
                f,
                "conflicting epoch: existing={existing}, proposed={proposed}"
            ),
            Self::SplitBrainDetected => {
                f.write_str("split-brain detected: a non-finalized epoch already exists")
            }
            Self::EpochAlreadyFinalized { epoch_id } => {
                write!(f, "epoch {epoch_id} is already finalized and immutable")
            }
            Self::NonMonotonicEpoch { previous, proposed } => write!(
                f,
                "non-monotonic epoch proposal: previous={previous}, proposed={proposed}"
            ),
            Self::UnknownApprover { verifier_id } => {
                write!(f, "approval from non-member verifier: {verifier_id}")
            }
            Self::InvalidApprovalSignature { verifier_id } => {
                write!(f, "invalid approval signature from verifier: {verifier_id}")
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation_auth::{sign_ml_dsa, test_keys::keypair};
    use crate::verifier_federation::QuorumPolicy;
    use crate::verifier_identity::VerifierIdentity;
    use alloc::vec;

    /// Builds a Majority federation of `n` members, each with a real ML-DSA-65
    /// keypair, returning the federation and the per-member signing seeds.
    fn make_signed_federation(n: usize) -> (VerifierFederation, Vec<[u8; 32]>) {
        let mut members = Vec::new();
        let mut seeds = Vec::new();
        for i in 0..n {
            let (seed, vk) = keypair();
            members.push(VerifierIdentity {
                verifier_id: alloc::format!("v{i}"),
                organization: "Org".into(),
                public_key: vk,
                ml_kem_public_key: None,
                capabilities: vec![],
            });
            seeds.push(seed);
        }
        let fed = VerifierFederation {
            federation_id: "fed".into(),
            members,
            quorum_policy: QuorumPolicy::Majority,
        };
        (fed, seeds)
    }

    /// Produces a valid signed approval from member `idx` for `epoch`.
    fn signed_approval_for(
        fed: &VerifierFederation,
        seeds: &[[u8; 32]],
        idx: usize,
        epoch: &FederatedPolicyEpoch,
    ) -> SignedApproval {
        let verifier_id = fed.members[idx].verifier_id.clone();
        let payload = approval_payload(
            &fed.federation_id,
            epoch.epoch_id,
            epoch.previous_epoch,
            &verifier_id,
        );
        let signature = sign_ml_dsa(&payload, CTX_APPROVAL, &seeds[idx]).unwrap();
        SignedApproval {
            verifier_id,
            signature,
        }
    }

    /// Convenience: sign and record an approval from member `idx`.
    fn approve(
        epoch: &mut FederatedPolicyEpoch,
        fed: &VerifierFederation,
        seeds: &[[u8; 32]],
        idx: usize,
    ) -> Result<(), FederatedPolicyError> {
        let approval = signed_approval_for(fed, seeds, idx, epoch);
        epoch.add_signed_approval(approval, fed)
    }

    #[test]
    fn epoch_finalize_majority() {
        let (fed, seeds) = make_signed_federation(5); // requires 3
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        approve(&mut epoch, &fed, &seeds, 0).unwrap();
        approve(&mut epoch, &fed, &seeds, 1).unwrap();
        // 2 approvals < 3 required
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::QuorumNotReached {
                approvals: 2,
                required: 3
            }
        ));
        approve(&mut epoch, &fed, &seeds, 2).unwrap();
        assert!(epoch.try_finalize(&fed).is_ok());
        assert!(epoch.quorum_reached);
    }

    #[test]
    fn epoch_already_finalized_is_immutable() {
        let (fed, seeds) = make_signed_federation(3); // requires 2
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        approve(&mut epoch, &fed, &seeds, 0).unwrap();
        approve(&mut epoch, &fed, &seeds, 1).unwrap();
        epoch.try_finalize(&fed).unwrap();
        // Second finalize attempt
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::EpochAlreadyFinalized { epoch_id: 1 }
        ));
        // Signed approval after finalization is rejected
        assert!(matches!(
            approve(&mut epoch, &fed, &seeds, 2).unwrap_err(),
            FederatedPolicyError::EpochAlreadyFinalized { epoch_id: 1 }
        ));
    }

    #[test]
    fn duplicate_approvals_deduplicated() {
        let (fed, seeds) = make_signed_federation(5);
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        approve(&mut epoch, &fed, &seeds, 0).unwrap();
        approve(&mut epoch, &fed, &seeds, 0).unwrap(); // duplicate
        approve(&mut epoch, &fed, &seeds, 0).unwrap(); // duplicate again
        assert_eq!(epoch.approved_by.len(), 1);
        assert_eq!(epoch.signed_approvals.len(), 1);
        // still insufficient (1 < 3)
        assert!(epoch.try_finalize(&fed).is_err());
    }

    #[test]
    fn registry_rejects_split_brain() {
        let mut reg = FederatedPolicyRegistry::new();
        let e1 = FederatedPolicyEpoch::new(1, 1000, None);
        reg.propose(e1).unwrap();
        // e1 is not finalized; proposing e2 is split-brain
        let e2 = FederatedPolicyEpoch::new(2, 2000, Some(1));
        assert!(matches!(
            reg.propose(e2).unwrap_err(),
            FederatedPolicyError::SplitBrainDetected
        ));
    }

    #[test]
    fn registry_rejects_non_monotonic_epoch() {
        let (fed, seeds) = make_signed_federation(3);
        let mut reg = FederatedPolicyRegistry::new();
        let mut e1 = FederatedPolicyEpoch::new(5, 1000, None);
        approve(&mut e1, &fed, &seeds, 0).unwrap();
        approve(&mut e1, &fed, &seeds, 1).unwrap();
        e1.try_finalize(&fed).unwrap();
        reg.propose(e1).unwrap();

        let e_old = FederatedPolicyEpoch::new(3, 2000, Some(5)); // id 3 < 5
        assert!(matches!(
            reg.propose(e_old).unwrap_err(),
            FederatedPolicyError::NonMonotonicEpoch {
                previous: 5,
                proposed: 3
            }
        ));
    }

    #[test]
    fn registry_active_epoch() {
        let (fed, seeds) = make_signed_federation(3);
        let mut reg = FederatedPolicyRegistry::new();
        assert!(reg.active_epoch().is_none());

        let mut e1 = FederatedPolicyEpoch::new(1, 1000, None);
        approve(&mut e1, &fed, &seeds, 0).unwrap();
        approve(&mut e1, &fed, &seeds, 1).unwrap();
        e1.try_finalize(&fed).unwrap();
        reg.propose(e1).unwrap();

        assert_eq!(reg.active_epoch().unwrap().epoch_id, 1);
    }

    // ── Adversarial tests ────────────────────────────────────────────────────

    // Forged approval: an attacker signs the WRONG payload (a different epoch id)
    // but claims it approves this epoch. The signature does not verify against the
    // canonical payload for this epoch, so the approval is rejected and never
    // contributes to quorum.
    #[test]
    fn forged_approval_signature_is_rejected() {
        let (fed, seeds) = make_signed_federation(3); // requires 2
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        // Sign a payload for epoch 999 while claiming to approve epoch 1.
        let bad_payload = approval_payload(&fed.federation_id, 999, None, "v0");
        let signature = sign_ml_dsa(&bad_payload, CTX_APPROVAL, &seeds[0]).unwrap();
        let forged = SignedApproval {
            verifier_id: "v0".into(),
            signature,
        };
        assert!(matches!(
            epoch.add_signed_approval(forged, &fed).unwrap_err(),
            FederatedPolicyError::InvalidApprovalSignature { .. }
        ));
        assert!(epoch.signed_approvals.is_empty());
    }

    // Wrong-key approval: the approval claims to be from v0 but is signed with
    // v1's key. Verification uses v0's public key, so it fails closed.
    #[test]
    fn approval_signed_by_wrong_member_key_is_rejected() {
        let (fed, seeds) = make_signed_federation(3);
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        let payload = approval_payload(&fed.federation_id, 1, None, "v0");
        // Sign with v1's seed (index 1) but claim verifier_id v0.
        let signature = sign_ml_dsa(&payload, CTX_APPROVAL, &seeds[1]).unwrap();
        let impersonated = SignedApproval {
            verifier_id: "v0".into(),
            signature,
        };
        assert!(matches!(
            epoch.add_signed_approval(impersonated, &fed).unwrap_err(),
            FederatedPolicyError::InvalidApprovalSignature { .. }
        ));
    }

    // Non-member approval: even with a structurally valid signature, an approval
    // from an identity that is not a federation member is rejected outright.
    #[test]
    fn non_member_signed_approval_is_rejected() {
        let (fed, seeds) = make_signed_federation(3); // requires 2
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        let payload = approval_payload(&fed.federation_id, 1, None, "ghost");
        let signature = sign_ml_dsa(&payload, CTX_APPROVAL, &seeds[0]).unwrap();
        let ghost = SignedApproval {
            verifier_id: "ghost".into(),
            signature,
        };
        assert!(matches!(
            epoch.add_signed_approval(ghost, &fed).unwrap_err(),
            FederatedPolicyError::UnknownApprover { .. }
        ));
        // No valid approvals ⇒ finalization fails closed.
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::QuorumNotReached {
                approvals: 0,
                required: 2,
            }
        ));
    }

    // One real signed approval plus a rejected phantom yields a count of exactly
    // one — below the quorum of two.
    fn one_real_plus_phantom_counts_one() -> FederatedPolicyEpoch {
        let (fed, seeds) = make_signed_federation(3);
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        approve(&mut epoch, &fed, &seeds, 0).unwrap(); // real
        let payload = approval_payload(&fed.federation_id, 1, None, "ghost");
        let signature = sign_ml_dsa(&payload, CTX_APPROVAL, &seeds[0]).unwrap();
        let _ = epoch.add_signed_approval(
            SignedApproval {
                verifier_id: "ghost".into(),
                signature,
            },
            &fed,
        );
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::QuorumNotReached {
                approvals: 1,
                required: 2,
            }
        ));
        epoch
    }

    #[test]
    fn quorum_partial_real_plus_phantom_is_rejected() {
        let epoch = one_real_plus_phantom_counts_one();
        assert!(!epoch.quorum_reached);
    }

    // Unsigned approvals (recorded via the legacy string API) never count toward
    // quorum: finalization is fail-closed against unauthenticated mutations.
    #[test]
    fn unsigned_approvals_do_not_count_toward_quorum() {
        let (fed, _seeds) = make_signed_federation(3); // requires 2
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        epoch.add_approval("v0".into()).unwrap(); // unsigned
        epoch.add_approval("v1".into()).unwrap(); // unsigned
                                                  // Both are members and would satisfy quorum if counted — but they aren't.
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::QuorumNotReached {
                approvals: 0,
                required: 2,
            }
        ));
        assert!(!epoch.quorum_reached);
    }

    // Replay across epochs: an approval validly signed for epoch 1 cannot be
    // replayed onto epoch 2, because the epoch id is bound into the payload.
    #[test]
    fn approval_replayed_across_epochs_is_rejected() {
        let (fed, seeds) = make_signed_federation(3);
        let e1 = FederatedPolicyEpoch::new(1, 1000, None);
        let approval = signed_approval_for(&fed, &seeds, 0, &e1);

        let mut e2 = FederatedPolicyEpoch::new(2, 2000, Some(1));
        assert!(matches!(
            e2.add_signed_approval(approval, &fed).unwrap_err(),
            FederatedPolicyError::InvalidApprovalSignature { .. }
        ));
    }

    // Proposing an epoch with epoch_id equal to the last finalized epoch_id
    // must be rejected as non-monotonic (the check is <=, not <).
    #[test]
    fn registry_rejects_epoch_id_equal_to_finalized() {
        let (fed, seeds) = make_signed_federation(3);
        let mut reg = FederatedPolicyRegistry::new();

        let mut e1 = FederatedPolicyEpoch::new(10, 1000, None);
        approve(&mut e1, &fed, &seeds, 0).unwrap();
        approve(&mut e1, &fed, &seeds, 1).unwrap();
        e1.try_finalize(&fed).unwrap();
        reg.propose(e1).unwrap();

        // Same epoch_id as the finalized one — must be rejected
        let e_same = FederatedPolicyEpoch::new(10, 2000, Some(10));
        assert!(matches!(
            reg.propose(e_same).unwrap_err(),
            FederatedPolicyError::NonMonotonicEpoch {
                previous: 10,
                proposed: 10,
            }
        ));
    }

    // After a pending epoch is finalized, pending_epoch() returns None and a
    // higher-ID epoch can be proposed without triggering split-brain.
    #[test]
    fn registry_pending_cleared_after_finalization_and_accepts_next() {
        let (fed, seeds) = make_signed_federation(3);
        let mut reg = FederatedPolicyRegistry::new();

        let mut e1 = FederatedPolicyEpoch::new(1, 1000, None);
        approve(&mut e1, &fed, &seeds, 0).unwrap();
        approve(&mut e1, &fed, &seeds, 1).unwrap();
        reg.propose(e1).unwrap();

        // Finalize via pending_epoch_mut
        reg.pending_epoch_mut().unwrap().try_finalize(&fed).unwrap();

        assert!(reg.pending_epoch().is_none());

        // A new epoch with a higher ID must be accepted
        let e2 = FederatedPolicyEpoch::new(2, 2000, Some(1));
        assert!(reg.propose(e2).is_ok());
    }

    // N=1 federation with Majority requires exactly 1 approval (n/2 + 1 = 1).
    #[test]
    fn quorum_edge_single_member_requires_one_approval() {
        let (fed, seeds) = make_signed_federation(1);
        assert_eq!(fed.quorum_required(), 1);

        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::QuorumNotReached {
                approvals: 0,
                required: 1,
            }
        ));
        approve(&mut epoch, &fed, &seeds, 0).unwrap();
        assert!(epoch.try_finalize(&fed).is_ok());
    }

    // N=2 federation with Majority requires both members (n/2 + 1 = 2).
    // A single approval is insufficient.
    #[test]
    fn quorum_edge_two_members_requires_both() {
        let (fed, seeds) = make_signed_federation(2);
        assert_eq!(fed.quorum_required(), 2);

        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        approve(&mut epoch, &fed, &seeds, 0).unwrap();
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::QuorumNotReached {
                approvals: 1,
                required: 2,
            }
        ));
        approve(&mut epoch, &fed, &seeds, 1).unwrap();
        assert!(epoch.try_finalize(&fed).is_ok());
    }

    // Proposing two different epochs to the same registry without finalizing
    // the first is always split-brain, regardless of epoch IDs.
    #[test]
    fn registry_second_pending_proposal_always_split_brain() {
        let mut reg = FederatedPolicyRegistry::new();
        let e1 = FederatedPolicyEpoch::new(1, 1000, None);
        let e2 = FederatedPolicyEpoch::new(99, 9000, Some(1)); // much higher ID
        reg.propose(e1).unwrap();
        assert!(matches!(
            reg.propose(e2).unwrap_err(),
            FederatedPolicyError::SplitBrainDetected
        ));
    }
}
