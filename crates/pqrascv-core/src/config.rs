//! Policy configuration for the PQ-RASCV attestation engine.
//!
//! [`PolicyConfig`] drives the verifier's acceptance criteria and can be
//! constructed as a `const` value, making it suitable for `no_std` environments
//! where runtime configuration is not available.

use crate::quote::QuoteTimestamp;

/// Minimum SLSA level required for a quote to pass policy.
pub const DEFAULT_MIN_SLSA_LEVEL: u8 = 1;

/// Maximum age of a quote (in seconds) before it is considered stale.
/// Zero means no age check is performed.
pub const DEFAULT_MAX_QUOTE_AGE_SECS: u64 = 300; // 5 minutes

/// Policy configuration applied during quote verification.
///
/// This struct is intentionally kept `Copy` and allocation-free so it can be
/// embedded as a compile-time constant on embedded targets.
///
/// # Example
///
/// ```
/// use pqrascv_core::config::PolicyConfig;
///
/// const MY_POLICY: PolicyConfig = PolicyConfig {
///     min_slsa_level: 2,
///     max_quote_age_secs: 120,
///     require_firmware_hash: true,
///     require_event_counter: false,
///     allow_rtcless_devices: false,
/// };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyConfig {
    /// Minimum acceptable SLSA build level (1–4).
    pub min_slsa_level: u8,

    /// Maximum acceptable quote age in seconds (0 = no check).
    ///
    /// Only applied when the quote carries a [`QuoteTimestamp::Rtc`] value.
    pub max_quote_age_secs: u64,

    /// When `true`, reject quotes with an all-zero firmware hash.
    pub require_firmware_hash: bool,

    /// When `true`, reject quotes where `event_counter == 0`.
    pub require_event_counter: bool,

    /// When `true`, accept quotes from devices that have no real-time clock
    /// ([`QuoteTimestamp::NoRtc`]). When `false` (the default), such quotes
    /// are rejected with [`PqRascvError::RtcRequired`].
    ///
    /// There is no silent bypass: a `NoRtc` quote is always rejected unless
    /// this flag is explicitly set.
    pub allow_rtcless_devices: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            min_slsa_level: DEFAULT_MIN_SLSA_LEVEL,
            max_quote_age_secs: DEFAULT_MAX_QUOTE_AGE_SECS,
            require_firmware_hash: true,
            require_event_counter: false,
            allow_rtcless_devices: false,
        }
    }
}

impl PolicyConfig {
    /// Evaluates a quote's provenance and measurements against this policy.
    ///
    /// Returns `Ok(())` if all checks pass, or the first
    /// [`crate::error::PqRascvError`] encountered.
    pub fn evaluate(
        &self,
        slsa_level: u8,
        firmware_hash: &[u8; 32],
        event_counter: u64,
        timestamp: QuoteTimestamp,
        now_secs: u64,
    ) -> Result<(), crate::error::PqRascvError> {
        use crate::error::PqRascvError;

        if slsa_level < self.min_slsa_level {
            return Err(PqRascvError::PolicyViolation("MinSlsaLevel"));
        }
        if self.require_firmware_hash && firmware_hash == &[0u8; 32] {
            return Err(PqRascvError::PolicyViolation("RequireFirmwareHash"));
        }
        if self.require_event_counter && event_counter == 0 {
            return Err(PqRascvError::PolicyViolation("RequireEventCounter"));
        }

        match timestamp {
            QuoteTimestamp::NoRtc => {
                if !self.allow_rtcless_devices {
                    return Err(PqRascvError::RtcRequired);
                }
                // age check skipped — no clock available
            }
            QuoteTimestamp::Rtc(ts) => {
                if self.max_quote_age_secs > 0 {
                    let age = now_secs.saturating_sub(ts);
                    if age > self.max_quote_age_secs {
                        return Err(PqRascvError::PolicyViolation("MaxQuoteAgeSecs"));
                    }
                }
            }
        }

        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quote::QuoteTimestamp;

    #[test]
    fn default_policy_accepts_valid_quote() {
        let policy = PolicyConfig {
            allow_rtcless_devices: false,
            ..Default::default()
        };
        let result = policy.evaluate(1, &[0xabu8; 32], 0, QuoteTimestamp::Rtc(1_000), 1_100);
        assert!(result.is_ok());
    }

    #[test]
    fn policy_rejects_low_slsa_level() {
        let policy = PolicyConfig {
            min_slsa_level: 3,
            ..Default::default()
        };
        assert!(policy
            .evaluate(2, &[0xabu8; 32], 0, QuoteTimestamp::Rtc(1_000), 1_100)
            .is_err());
    }

    #[test]
    fn policy_rejects_zero_firmware_hash() {
        let policy = PolicyConfig {
            require_firmware_hash: true,
            ..Default::default()
        };
        assert!(policy
            .evaluate(1, &[0u8; 32], 0, QuoteTimestamp::Rtc(1_000), 1_100)
            .is_err());
    }

    #[test]
    fn policy_rejects_stale_quote() {
        let policy = PolicyConfig {
            max_quote_age_secs: 60,
            ..Default::default()
        };
        assert!(policy
            .evaluate(1, &[0xabu8; 32], 0, QuoteTimestamp::Rtc(1_000), 1_120)
            .is_err());
    }

    #[test]
    fn policy_accepts_zero_age_check() {
        let policy = PolicyConfig {
            max_quote_age_secs: 0,
            ..Default::default()
        };
        assert!(policy
            .evaluate(1, &[0xabu8; 32], 0, QuoteTimestamp::Rtc(1_000), 11_000)
            .is_ok());
    }

    #[test]
    fn policy_rejects_rtcless_by_default() {
        // Default policy has allow_rtcless_devices: false.
        let policy = PolicyConfig::default();
        assert_eq!(
            policy.evaluate(1, &[0xabu8; 32], 0, QuoteTimestamp::NoRtc, 999_999),
            Err(crate::error::PqRascvError::RtcRequired)
        );
    }

    #[test]
    fn policy_accepts_rtcless_when_explicitly_allowed() {
        let policy = PolicyConfig {
            allow_rtcless_devices: true,
            ..Default::default()
        };
        assert!(policy
            .evaluate(1, &[0xabu8; 32], 0, QuoteTimestamp::NoRtc, 999_999)
            .is_ok());
    }
}
