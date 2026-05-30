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
//! `add_approval` accepts any string — **no cryptographic proof** is required
//! that the caller actually controls the identity they claim. However,
//! `try_finalize` validates that all counted approvals belong to registered
//! federation members; approvals from IDs not present in `federation.members`
//! are ignored when computing the approval count. Cryptographic approval
//! signatures (e.g., each verifier signs the epoch ID with its ML-DSA key)
//! remain a future hardening step.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::verifier_federation::VerifierFederation;

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
    pub approved_by: Vec<String>,
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

    /// Attempts to finalize the epoch by checking if quorum has been reached.
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
        let member_ids: BTreeSet<&str> = federation
            .members
            .iter()
            .map(|m| m.verifier_id.as_str())
            .collect();
        let approval_count = self
            .approved_by
            .iter()
            .filter(|id| member_ids.contains(id.as_str()))
            .count();
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
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier_federation::QuorumPolicy;
    use crate::verifier_identity::VerifierIdentity;
    use alloc::vec;

    fn make_federation(n: usize) -> VerifierFederation {
        VerifierFederation {
            federation_id: "fed".into(),
            members: (0..n)
                .map(|i| VerifierIdentity {
                    verifier_id: alloc::format!("v{i}"),
                    organization: "Org".into(),
                    public_key: vec![1],
                    ml_kem_public_key: None,
                    capabilities: vec![],
                })
                .collect(),
            quorum_policy: QuorumPolicy::Majority,
        }
    }

    #[test]
    fn epoch_finalize_majority() {
        let fed = make_federation(5); // requires 3
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        epoch.add_approval("v0".into()).unwrap();
        epoch.add_approval("v1".into()).unwrap();
        // 2 approvals < 3 required
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::QuorumNotReached {
                approvals: 2,
                required: 3
            }
        ));
        epoch.add_approval("v2".into()).unwrap();
        assert!(epoch.try_finalize(&fed).is_ok());
        assert!(epoch.quorum_reached);
    }

    #[test]
    fn epoch_already_finalized_is_immutable() {
        let fed = make_federation(3); // requires 2
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        epoch.add_approval("v0".into()).unwrap();
        epoch.add_approval("v1".into()).unwrap();
        epoch.try_finalize(&fed).unwrap();
        // Second finalize attempt
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::EpochAlreadyFinalized { epoch_id: 1 }
        ));
        // Approval after finalization
        assert!(matches!(
            epoch.add_approval("v2".into()).unwrap_err(),
            FederatedPolicyError::EpochAlreadyFinalized { epoch_id: 1 }
        ));
    }

    #[test]
    fn duplicate_approvals_deduplicated() {
        let fed = make_federation(5);
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        epoch.add_approval("v0".into()).unwrap();
        epoch.add_approval("v0".into()).unwrap(); // duplicate
        epoch.add_approval("v0".into()).unwrap(); // duplicate again
        assert_eq!(epoch.approved_by.len(), 1);
        // still insufficient
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
        let fed = make_federation(3);
        let mut reg = FederatedPolicyRegistry::new();
        let mut e1 = FederatedPolicyEpoch::new(5, 1000, None);
        e1.add_approval("v0".into()).unwrap();
        e1.add_approval("v1".into()).unwrap();
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
        let fed = make_federation(3);
        let mut reg = FederatedPolicyRegistry::new();
        assert!(reg.active_epoch().is_none());

        let mut e1 = FederatedPolicyEpoch::new(1, 1000, None);
        e1.add_approval("v0".into()).unwrap();
        e1.add_approval("v1".into()).unwrap();
        e1.try_finalize(&fed).unwrap();
        reg.propose(e1).unwrap();

        assert_eq!(reg.active_epoch().unwrap().epoch_id, 1);
    }

    // ── Adversarial tests ────────────────────────────────────────────────────

    // FIXED: try_finalize now validates that approver IDs are actual federation
    // members before counting them toward quorum. Phantom IDs (strings that are
    // not in federation.members) are excluded from the approval count, so an
    // attacker cannot satisfy quorum by injecting arbitrary strings.
    #[test]
    fn quorum_phantom_verifier_ids_satisfy_count_check() {
        let fed = make_federation(3); // Majority requires 2
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        // "attacker" and "ghost" are not members of the federation
        epoch.add_approval("attacker".into()).unwrap();
        epoch.add_approval("ghost".into()).unwrap();
        // Phantom IDs are not in federation.members — no valid approvals count
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::QuorumNotReached {
                approvals: 0,
                required: 2,
            }
        ));
        assert!(!epoch.quorum_reached);
    }

    #[test]
    fn quorum_partial_real_plus_phantom_is_rejected() {
        // fed has 3 members (v0, v1, v2); Majority requires 2.
        let fed = make_federation(3);
        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        // One real member approval + one phantom — the phantom must not count
        epoch.add_approval("v0".into()).unwrap(); // real member
        epoch.add_approval("ghost".into()).unwrap(); // phantom — not in federation
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::QuorumNotReached {
                approvals: 1,
                required: 2,
            }
        ));
        assert!(!epoch.quorum_reached);
    }

    // Proposing an epoch with epoch_id equal to the last finalized epoch_id
    // must be rejected as non-monotonic (the check is <=, not <).
    #[test]
    fn registry_rejects_epoch_id_equal_to_finalized() {
        let fed = make_federation(3);
        let mut reg = FederatedPolicyRegistry::new();

        let mut e1 = FederatedPolicyEpoch::new(10, 1000, None);
        e1.add_approval("v0".into()).unwrap();
        e1.add_approval("v1".into()).unwrap();
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
        let fed = make_federation(3);
        let mut reg = FederatedPolicyRegistry::new();

        let mut e1 = FederatedPolicyEpoch::new(1, 1000, None);
        e1.add_approval("v0".into()).unwrap();
        e1.add_approval("v1".into()).unwrap();
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
        let fed = make_federation(1);
        assert_eq!(fed.quorum_required(), 1);

        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::QuorumNotReached {
                approvals: 0,
                required: 1,
            }
        ));
        epoch.add_approval("v0".into()).unwrap();
        assert!(epoch.try_finalize(&fed).is_ok());
    }

    // N=2 federation with Majority requires both members (n/2 + 1 = 2).
    // A single approval is insufficient.
    #[test]
    fn quorum_edge_two_members_requires_both() {
        let fed = make_federation(2);
        assert_eq!(fed.quorum_required(), 2);

        let mut epoch = FederatedPolicyEpoch::new(1, 1000, None);
        epoch.add_approval("v0".into()).unwrap();
        assert!(matches!(
            epoch.try_finalize(&fed).unwrap_err(),
            FederatedPolicyError::QuorumNotReached {
                approvals: 1,
                required: 2,
            }
        ));
        epoch.add_approval("v1".into()).unwrap();
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
