/// OIDC builder-identity constraints for Fulcio certificate verification.
///
/// Condition 4 of the Provenance Enforcement Invariant: the signing certificate's
/// OIDC subject and issuer must satisfy the policy's identity constraints before
/// a [`VerifiedProvenance`] token can be issued.
///
/// [`VerifiedProvenance`]: super::VerifiedProvenance
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::error::PqRascvError;

/// Error returned when a builder identity fails a constraint check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// The OIDC issuer URI does not match the required issuer.
    IssuerMismatch,
    /// The OIDC subject URI is not in the allowed-workflows list.
    SubjectNotAllowed,
    /// The allowed-builders list is empty — all builders are denied.
    AllBuildersExcluded,
}

impl From<IdentityError> for PqRascvError {
    fn from(_: IdentityError) -> Self {
        PqRascvError::PolicyViolation
    }
}

/// The OIDC identity extracted from a Fulcio short-lived certificate.
///
/// Both fields are URIs from the certificate's extensions:
/// - `oidc_subject` from the Subject Alternative Name (SAN) URI entry
/// - `oidc_issuer` from the Fulcio-specific OID `1.3.6.1.4.1.57264.1.1`
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuilderIdentity {
    /// OIDC issuer URI (e.g. `"https://token.actions.githubusercontent.com"`).
    pub oidc_issuer: String,
    /// OIDC subject URI (e.g. a GitHub Actions workflow URL).
    pub oidc_subject: String,
}

/// A policy constraint that a [`BuilderIdentity`] must satisfy.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub enum IdentityConstraint {
    /// The OIDC issuer must exactly match this string.
    RequireIssuer(String),
    /// The OIDC subject must be one of these workflow URLs.
    ///
    /// An empty list denies all subjects — use [`AllowedWorkflows`] only
    /// after confirming the list is non-empty.
    ///
    /// [`AllowedWorkflows`]: Self::AllowedWorkflows
    AllowedWorkflows(Vec<String>),
    /// The OIDC subject must start with this prefix (for org-level allowlists).
    SubjectPrefix(String),
}

#[cfg(feature = "alloc")]
impl IdentityConstraint {
    /// Check the constraint against a builder identity.
    ///
    /// Returns `Ok(())` if the constraint is satisfied, `Err` otherwise.
    pub fn check(&self, identity: &BuilderIdentity) -> Result<(), IdentityError> {
        match self {
            Self::RequireIssuer(required) => {
                if identity.oidc_issuer != *required {
                    return Err(IdentityError::IssuerMismatch);
                }
            }
            Self::AllowedWorkflows(allowed) => {
                if allowed.is_empty() {
                    return Err(IdentityError::AllBuildersExcluded);
                }
                if !allowed.contains(&identity.oidc_subject) {
                    return Err(IdentityError::SubjectNotAllowed);
                }
            }
            Self::SubjectPrefix(prefix) => {
                if !identity.oidc_subject.starts_with(prefix.as_str()) {
                    return Err(IdentityError::SubjectNotAllowed);
                }
            }
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
    const ALLOWED_WORKFLOW: &str =
        "https://github.com/acme/firmware/.github/workflows/release.yml@refs/heads/main";

    fn allowed_identity() -> BuilderIdentity {
        BuilderIdentity {
            oidc_issuer: GITHUB_ISSUER.to_string(),
            oidc_subject: ALLOWED_WORKFLOW.to_string(),
        }
    }

    #[test]
    fn require_issuer_accepts_matching() {
        let constraint = IdentityConstraint::RequireIssuer(GITHUB_ISSUER.to_string());
        constraint.check(&allowed_identity()).unwrap();
    }

    #[test]
    fn require_issuer_rejects_wrong_issuer() {
        let identity = BuilderIdentity {
            oidc_issuer: "https://evil.example.com".to_string(),
            oidc_subject: ALLOWED_WORKFLOW.to_string(),
        };
        let err = IdentityConstraint::RequireIssuer(GITHUB_ISSUER.to_string())
            .check(&identity)
            .unwrap_err();
        assert_eq!(err, IdentityError::IssuerMismatch);
    }

    #[test]
    fn allowed_workflows_accepts_listed_subject() {
        let constraint =
            IdentityConstraint::AllowedWorkflows(alloc::vec![ALLOWED_WORKFLOW.to_string()]);
        constraint.check(&allowed_identity()).unwrap();
    }

    #[test]
    fn allowed_workflows_rejects_unlisted_subject() {
        let identity = BuilderIdentity {
            oidc_issuer: GITHUB_ISSUER.to_string(),
            oidc_subject: "https://github.com/evil/repo/.github/workflows/attack.yml".to_string(),
        };
        let err =
            IdentityConstraint::AllowedWorkflows(alloc::vec![ALLOWED_WORKFLOW.to_string()])
                .check(&identity)
                .unwrap_err();
        assert_eq!(err, IdentityError::SubjectNotAllowed);
    }

    #[test]
    fn allowed_workflows_empty_list_denies_all() {
        let err = IdentityConstraint::AllowedWorkflows(alloc::vec![])
            .check(&allowed_identity())
            .unwrap_err();
        assert_eq!(err, IdentityError::AllBuildersExcluded);
    }

    #[test]
    fn subject_prefix_accepts_matching() {
        let constraint = IdentityConstraint::SubjectPrefix(
            "https://github.com/acme/".to_string(),
        );
        constraint.check(&allowed_identity()).unwrap();
    }

    #[test]
    fn subject_prefix_rejects_non_matching() {
        let identity = BuilderIdentity {
            oidc_issuer: GITHUB_ISSUER.to_string(),
            oidc_subject: "https://github.com/evil/".to_string(),
        };
        let err = IdentityConstraint::SubjectPrefix("https://github.com/acme/".to_string())
            .check(&identity)
            .unwrap_err();
        assert_eq!(err, IdentityError::SubjectNotAllowed);
    }
}
