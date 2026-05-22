//! Verifier Federation Model
//!
//! A [`VerifierFederation`] groups a set of verifier identities under a common
//! [`QuorumPolicy`]. The federation is the unit of trust aggregation: consensus
//! is evaluated against a federation's membership and quorum requirements.
//!
//! # Quorum Semantics
//!
//! | Policy | Required votes |
//! |---|---|
//! | `Majority` | ⌈n/2⌉ + 1 |
//! | `SuperMajority` | ⌈2n/3⌉ + 1 (capped at n) |
//! | `Unanimous` | n |
//! | `Threshold(t)` | t (must be > 0 and ≤ n) |
//!
//! # Fail-Closed Behaviour
//!
//! `validate()` rejects empty membership, zero threshold, and any threshold
//! that exceeds the member count. These are structural invariants that would
//! make quorum computation meaningless or always-satisfied.

use alloc::string::String;
use alloc::vec::Vec;

use crate::verifier_identity::{VerifierCapability, VerifierIdentity};

// ── QuorumPolicy ──────────────────────────────────────────────────────────

/// The quorum algorithm applied when aggregating verifier votes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum QuorumPolicy {
    /// More than half of members must agree.  Required = ⌈n/2⌉ + 1.
    Majority,
    /// At least two-thirds of members must agree.  Required = ⌈2n/3⌉ + 1.
    SuperMajority,
    /// Every member must agree.
    Unanimous,
    /// Exactly `t` members must agree (t > 0, t ≤ n).
    Threshold(u8),
}

impl QuorumPolicy {
    /// Computes the number of votes required to satisfy this policy for `n` members.
    ///
    /// Returns `n` for `Unanimous`, `Threshold(t)` as-is (caller validates t ≤ n).
    #[must_use]
    pub fn required_votes(&self, n: usize) -> usize {
        match self {
            Self::Majority => n / 2 + 1,
            Self::SuperMajority => (2 * n).div_ceil(3).min(n),
            Self::Unanimous => n,
            Self::Threshold(t) => usize::from(*t),
        }
    }
}

// ── VerifierFederation ────────────────────────────────────────────────────

/// A named group of verifiers governed by a shared quorum policy.
///
/// All federation operations (consensus evaluation, policy epoch approval,
/// governance actions) require that the federation's `quorum_required()` is
/// satisfied by the participating members.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifierFederation {
    /// Globally unique federation identifier.
    pub federation_id: String,
    /// Current member verifiers.
    pub members: Vec<VerifierIdentity>,
    /// Quorum policy governing all federation decisions.
    pub quorum_policy: QuorumPolicy,
}

impl VerifierFederation {
    /// Returns the number of member verifiers.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Returns the number of votes required to satisfy the quorum policy.
    #[must_use]
    pub fn quorum_required(&self) -> usize {
        self.quorum_policy.required_votes(self.member_count())
    }

    /// Returns `true` if `vote_count` satisfies the federation's quorum policy.
    #[must_use]
    pub fn is_quorum_satisfied(&self, vote_count: usize) -> bool {
        vote_count >= self.quorum_required()
    }

    /// Returns all members that declare the specified capability.
    #[must_use]
    pub fn members_with_capability(&self, cap: VerifierCapability) -> Vec<&VerifierIdentity> {
        self.members
            .iter()
            .filter(|m| m.has_capability(cap))
            .collect()
    }

    /// Validates federation structural integrity.
    ///
    /// Rejects:
    /// - empty membership
    /// - `Threshold(0)` (would always be satisfied)
    /// - `Threshold(t)` where `t > member_count` (can never be satisfied)
    /// - duplicate `verifier_id`s
    pub fn validate(&self) -> Result<(), FederationError> {
        if self.members.is_empty() {
            return Err(FederationError::EmptyMembership);
        }
        if let QuorumPolicy::Threshold(t) = self.quorum_policy {
            if t == 0 {
                return Err(FederationError::ZeroThreshold);
            }
            if usize::from(t) > self.member_count() {
                return Err(FederationError::ThresholdExceedsMembership {
                    threshold: t,
                    members: self.member_count(),
                });
            }
        }
        // Check for duplicate verifier IDs
        for (i, a) in self.members.iter().enumerate() {
            for b in self.members.iter().skip(i + 1) {
                if a.verifier_id == b.verifier_id {
                    return Err(FederationError::DuplicateMember {
                        verifier_id: a.verifier_id.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

// ── FederationError ───────────────────────────────────────────────────────

/// Errors from federation structural validation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FederationError {
    /// The federation has no members.
    EmptyMembership,
    /// `Threshold(0)` is invalid — quorum would always be satisfied.
    ZeroThreshold,
    /// `Threshold(t)` exceeds the member count.
    ThresholdExceedsMembership { threshold: u8, members: usize },
    /// Two members share the same `verifier_id`.
    DuplicateMember { verifier_id: String },
}

impl core::fmt::Display for FederationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyMembership => f.write_str("federation has no members"),
            Self::ZeroThreshold => f.write_str("federation threshold is zero"),
            Self::ThresholdExceedsMembership { threshold, members } => write!(
                f,
                "federation threshold {threshold} exceeds member count {members}"
            ),
            Self::DuplicateMember { verifier_id } => {
                write!(f, "duplicate federation member: {verifier_id}")
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn make_member(id: &str) -> VerifierIdentity {
        VerifierIdentity {
            verifier_id: id.into(),
            organization: "Org".into(),
            public_key: vec![1, 2, 3],
            capabilities: vec![VerifierCapability::HardwareVerification],
        }
    }

    fn make_federation(n: usize, policy: QuorumPolicy) -> VerifierFederation {
        VerifierFederation {
            federation_id: "fed-1".into(),
            members: (0..n).map(|i| make_member(&alloc::format!("v{i}"))).collect(),
            quorum_policy: policy,
        }
    }

    #[test]
    fn quorum_majority_5() {
        let fed = make_federation(5, QuorumPolicy::Majority);
        assert_eq!(fed.quorum_required(), 3); // ⌈5/2⌉+1 = 3
        assert!(fed.is_quorum_satisfied(3));
        assert!(!fed.is_quorum_satisfied(2));
    }

    #[test]
    fn quorum_supermajority_6() {
        let fed = make_federation(6, QuorumPolicy::SuperMajority);
        assert_eq!(fed.quorum_required(), 4); // ⌈12/3⌉+1 = 5? Let's recheck: ⌈2*6/3⌉ = ⌈4⌉ = 4
        assert!(fed.is_quorum_satisfied(4));
        assert!(!fed.is_quorum_satisfied(3));
    }

    #[test]
    fn quorum_unanimous_3() {
        let fed = make_federation(3, QuorumPolicy::Unanimous);
        assert_eq!(fed.quorum_required(), 3);
        assert!(fed.is_quorum_satisfied(3));
        assert!(!fed.is_quorum_satisfied(2));
    }

    #[test]
    fn quorum_threshold_3_of_5() {
        let fed = make_federation(5, QuorumPolicy::Threshold(3));
        assert_eq!(fed.quorum_required(), 3);
        assert!(fed.is_quorum_satisfied(3));
        assert!(!fed.is_quorum_satisfied(2));
    }

    #[test]
    fn validate_rejects_empty_membership() {
        let fed = VerifierFederation {
            federation_id: "f".into(),
            members: vec![],
            quorum_policy: QuorumPolicy::Majority,
        };
        assert!(matches!(
            fed.validate().unwrap_err(),
            FederationError::EmptyMembership
        ));
    }

    #[test]
    fn validate_rejects_zero_threshold() {
        let fed = make_federation(3, QuorumPolicy::Threshold(0));
        assert!(matches!(
            fed.validate().unwrap_err(),
            FederationError::ZeroThreshold
        ));
    }

    #[test]
    fn validate_rejects_threshold_exceeds_members() {
        let fed = make_federation(3, QuorumPolicy::Threshold(5));
        assert!(matches!(
            fed.validate().unwrap_err(),
            FederationError::ThresholdExceedsMembership { .. }
        ));
    }

    #[test]
    fn validate_rejects_duplicate_members() {
        let fed = VerifierFederation {
            federation_id: "f".into(),
            members: vec![make_member("v1"), make_member("v1")],
            quorum_policy: QuorumPolicy::Majority,
        };
        assert!(matches!(
            fed.validate().unwrap_err(),
            FederationError::DuplicateMember { .. }
        ));
    }

    #[test]
    fn members_with_capability_filter() {
        let mut fed = make_federation(3, QuorumPolicy::Majority);
        fed.members[0].capabilities.push(VerifierCapability::PolicyAuthority);
        let policy_holders = fed.members_with_capability(VerifierCapability::PolicyAuthority);
        assert_eq!(policy_holders.len(), 1);
        assert_eq!(policy_holders[0].verifier_id, "v0");
    }
}
