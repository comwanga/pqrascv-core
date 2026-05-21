//! Policy engine v2 — typed, composable attestation policy rules.
//!
//! # Design
//!
//! [`PolicyEngineV2`] replaces the flat [`PolicyConfig`](crate::config::PolicyConfig)
//! from v1 with a composable rule set. Rules are evaluated in order; the first
//! failure short-circuits with a descriptive error.
//!
//! Rules are serializable so policies can be distributed, audited, and version-
//! controlled alongside infrastructure code.
//!
//! # Audit Findings Addressed
//!
//! - **Finding #1**: `RequireHardwareBackend` rejects `SoftwareRoT` in production.
//! - **Finding #2**: `RequireExternalProvenance` rejects self-asserted SLSA claims.
//! - **Finding #4**: `RequireCertificateChain` enforces PKI validation.
//! - **Finding #10**: `EnforceProtocolVersion` rejects downgrade attempts.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "alloc")]
use crate::{error::PqRascvError, nonce::ClockEvidence};

// ── HardwareBackendKind ───────────────────────────────────────────────────

/// Identifies the hardware backend that produced a set of measurements.
///
/// Embedded in [`Measurements`](crate::measurement::Measurements) so the
/// policy engine can enforce hardware requirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HardwareBackendKind {
    /// TPM 2.0 hardware.
    Tpm2,
    /// DICE CDI derivation.
    Dice,
    /// Intel Trust Domain Extensions.
    IntelTdx,
    /// AMD Secure Encrypted Virtualization — Secure Nested Paging.
    AmdSevSnp,
    /// Software `RoT` — TEST ONLY. Rejected by default policy.
    SoftwareUnsafe,
}

impl HardwareBackendKind {
    /// Returns `true` if this backend provides a real hardware security boundary.
    #[must_use]
    pub fn is_hardware_rooted(self) -> bool {
        !matches!(self, Self::SoftwareUnsafe)
    }
}

// ── PolicyRule ────────────────────────────────────────────────────────────

/// A single attestation policy rule.
///
/// Rules are evaluated in the order they appear in [`PolicyEngineV2::rules`].
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum PolicyRule {
    /// Reject quotes with SLSA level below this threshold.
    MinSlsaLevel(u8),

    /// Reject quotes with an all-zero firmware hash.
    RequireFirmwareHash,

    /// Reject quotes from builders not in this allowlist.
    ///
    /// Builder IDs are URIs (e.g. `"https://github.com/actions/runner"`).
    AllowedBuilders(Vec<String>),

    /// Reject quotes whose firmware hash is not in this allowlist.
    ///
    /// An empty list means "any firmware hash is permitted" — use with caution.
    AllowedFirmwareHashes(Vec<[u8; 32]>),

    /// Reject quotes from backends that are not hardware-rooted.
    ///
    /// This rule rejects `SoftwareRoT` in production. Always include this
    /// rule in production policies.
    RequireHardwareBackend,

    /// Reject quotes that are not backed by a validated certificate chain.
    ///
    /// Fixes audit finding #4 (missing PKI).
    RequireCertificateChain,

    /// Reject quotes that carry self-asserted provenance.
    ///
    /// Requires an [`ExternalProvenanceBundle`](crate::provenance_v2::ExternalProvenanceBundle)
    /// signed by a CI provider. Fixes audit finding #2.
    RequireExternalProvenance,

    /// Reject quotes older than this many seconds (only for `TrustedRtc` quotes).
    MaxQuoteAgeSecs(u64),

    /// Reject quotes from devices without a real-time clock.
    ///
    /// When absent, `NoRtc` quotes are accepted (freshness via nonce only).
    RequireRtc,

    /// Require a Bitcoin anchor inclusion proof with at least this many confirmations.
    RequireBitcoinAnchor {
        /// Minimum number of Bitcoin block confirmations required.
        min_confirmations: u32,
    },

    /// Reject quotes with a protocol version other than the current one.
    ///
    /// Always include this rule. Fixes audit finding #10.
    EnforceProtocolVersion {
        /// The only accepted protocol version.
        expected: u16,
    },
}

// ── PolicyContext ─────────────────────────────────────────────────────────

/// All data available to the policy engine during evaluation.
///
/// Populated by the verifier from the parsed quote and verification results.
#[cfg(feature = "alloc")]
pub struct PolicyContext<'a> {
    pub protocol_version: u16,
    pub clock: ClockEvidence,
    pub now_secs: u64,
    pub firmware_hash: &'a [u8; 32],
    pub slsa_level: u8,
    pub builder_id: Option<&'a str>,
    pub hardware_backend: HardwareBackendKind,
    pub has_cert_chain: bool,
    pub has_external_provenance: bool,
    pub bitcoin_confirmations: Option<u32>,
}

// ── PolicyEngineV2 ────────────────────────────────────────────────────────

/// Composable attestation policy engine.
///
/// # Example
///
/// ```rust,ignore
/// use pqrascv_core::policy::{PolicyEngineV2, PolicyRule};
///
/// let engine = PolicyEngineV2::production();
/// engine.evaluate(&ctx)?;
/// ```
#[cfg(feature = "alloc")]
pub struct PolicyEngineV2 {
    pub rules: Vec<PolicyRule>,
}

#[cfg(feature = "alloc")]
impl PolicyEngineV2 {
    /// Creates a policy engine with the given rules.
    #[must_use]
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }

    /// Returns a production-grade default policy.
    ///
    /// Enforces:
    /// - Protocol version 2
    /// - Hardware-rooted backend (no `SoftwareRoT`)
    /// - Certificate chain required
    /// - External provenance required
    /// - SLSA level ≥ 2
    /// - Firmware hash required
    /// - Max quote age 300 seconds
    #[must_use]
    pub fn production() -> Self {
        Self::new(alloc::vec![
            PolicyRule::EnforceProtocolVersion { expected: 2 },
            PolicyRule::RequireHardwareBackend,
            PolicyRule::RequireCertificateChain,
            PolicyRule::RequireExternalProvenance,
            PolicyRule::MinSlsaLevel(2),
            PolicyRule::RequireFirmwareHash,
            PolicyRule::MaxQuoteAgeSecs(300),
        ])
    }

    /// Evaluates all rules against the provided context.
    ///
    /// Returns `Ok(())` if all rules pass, or the first [`PqRascvError`] encountered.
    pub fn evaluate(&self, ctx: &PolicyContext<'_>) -> Result<(), PqRascvError> {
        for rule in &self.rules {
            Self::evaluate_rule(rule, ctx)?;
        }
        Ok(())
    }

    fn evaluate_rule(rule: &PolicyRule, ctx: &PolicyContext<'_>) -> Result<(), PqRascvError> {
        match rule {
            PolicyRule::EnforceProtocolVersion { expected } => {
                if ctx.protocol_version != *expected {
                    return Err(PqRascvError::UnsupportedVersion);
                }
            }
            PolicyRule::RequireHardwareBackend => {
                if !ctx.hardware_backend.is_hardware_rooted() {
                    return Err(PqRascvError::PolicyViolation);
                }
            }
            PolicyRule::RequireCertificateChain => {
                if !ctx.has_cert_chain {
                    return Err(PqRascvError::PolicyViolation);
                }
            }
            PolicyRule::RequireExternalProvenance => {
                if !ctx.has_external_provenance {
                    return Err(PqRascvError::PolicyViolation);
                }
            }
            PolicyRule::MinSlsaLevel(min) => {
                if ctx.slsa_level < *min {
                    return Err(PqRascvError::PolicyViolation);
                }
            }
            PolicyRule::RequireFirmwareHash => {
                if ctx.firmware_hash == &[0u8; 32] {
                    return Err(PqRascvError::PolicyViolation);
                }
            }
            PolicyRule::AllowedBuilders(builders) => {
                let builder = ctx.builder_id.unwrap_or("");
                if !builders.iter().any(|b| b == builder) {
                    return Err(PqRascvError::PolicyViolation);
                }
            }
            PolicyRule::AllowedFirmwareHashes(hashes) => {
                if !hashes.is_empty() && !hashes.contains(ctx.firmware_hash) {
                    return Err(PqRascvError::PolicyViolation);
                }
            }
            PolicyRule::MaxQuoteAgeSecs(max_age) => {
                if let ClockEvidence::TrustedRtc(ts) = ctx.clock {
                    let age = ctx.now_secs.saturating_sub(ts);
                    if age > *max_age {
                        return Err(PqRascvError::PolicyViolation);
                    }
                }
            }
            PolicyRule::RequireRtc => {
                if ctx.clock == ClockEvidence::NoRtc {
                    return Err(PqRascvError::RtcRequired);
                }
            }
            PolicyRule::RequireBitcoinAnchor { min_confirmations } => {
                match ctx.bitcoin_confirmations {
                    Some(c) if c >= *min_confirmations => {}
                    _ => return Err(PqRascvError::PolicyViolation),
                }
            }
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    fn base_ctx() -> PolicyContext<'static> {
        PolicyContext {
            protocol_version: 2,
            clock: ClockEvidence::TrustedRtc(1_000),
            now_secs: 1_100,
            firmware_hash: &[0xabu8; 32],
            slsa_level: 2,
            builder_id: Some("https://github.com/actions/runner"),
            hardware_backend: HardwareBackendKind::Tpm2,
            has_cert_chain: true,
            has_external_provenance: true,
            bitcoin_confirmations: None,
        }
    }

    #[test]
    fn production_policy_accepts_valid_context() {
        let engine = PolicyEngineV2::production();
        assert!(engine.evaluate(&base_ctx()).is_ok());
    }

    #[test]
    fn rejects_software_rot() {
        let engine = PolicyEngineV2::production();
        let mut ctx = base_ctx();
        ctx.hardware_backend = HardwareBackendKind::SoftwareUnsafe;
        assert_eq!(engine.evaluate(&ctx), Err(PqRascvError::PolicyViolation));
    }

    #[test]
    fn rejects_missing_cert_chain() {
        let engine = PolicyEngineV2::production();
        let mut ctx = base_ctx();
        ctx.has_cert_chain = false;
        assert_eq!(engine.evaluate(&ctx), Err(PqRascvError::PolicyViolation));
    }

    #[test]
    fn rejects_self_asserted_provenance() {
        let engine = PolicyEngineV2::production();
        let mut ctx = base_ctx();
        ctx.has_external_provenance = false;
        assert_eq!(engine.evaluate(&ctx), Err(PqRascvError::PolicyViolation));
    }

    #[test]
    fn rejects_downgrade() {
        let engine = PolicyEngineV2::production();
        let mut ctx = base_ctx();
        ctx.protocol_version = 1;
        assert_eq!(engine.evaluate(&ctx), Err(PqRascvError::UnsupportedVersion));
    }

    #[test]
    fn rejects_stale_quote() {
        let engine = PolicyEngineV2::production();
        let mut ctx = base_ctx();
        ctx.clock = ClockEvidence::TrustedRtc(1_000);
        ctx.now_secs = 1_000 + 301;
        assert_eq!(engine.evaluate(&ctx), Err(PqRascvError::PolicyViolation));
    }

    #[test]
    fn bitcoin_anchor_rule_enforced() {
        let engine = PolicyEngineV2::new(alloc::vec![PolicyRule::RequireBitcoinAnchor {
            min_confirmations: 6,
        }]);
        let mut ctx = base_ctx();
        ctx.bitcoin_confirmations = Some(3);
        assert_eq!(engine.evaluate(&ctx), Err(PqRascvError::PolicyViolation));
        ctx.bitcoin_confirmations = Some(6);
        assert!(engine.evaluate(&ctx).is_ok());
    }
}
