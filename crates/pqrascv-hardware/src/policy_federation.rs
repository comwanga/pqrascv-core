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
        let approval_count = self.approved_by.len();
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
}
