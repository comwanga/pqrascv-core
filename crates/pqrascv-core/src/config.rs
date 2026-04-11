//! Policy configuration for the PQ-RASCV attestation engine.
//!
//! [`PolicyConfig`] drives the verifier's acceptance criteria and can be
//! constructed as a `const` value, making it suitable for `no_std` environments
//! where runtime configuration is not available.

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
/// };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyConfig {
    /// Minimum acceptable SLSA build level (1–4).
    pub min_slsa_level: u8,

    /// Maximum acceptable quote age in seconds (0 = no check).
    ///
    /// If the prover has no real-time clock it passes `timestamp = 0` to
    /// [`generate_quote`](crate::quote::generate_quote). A zero timestamp is
    /// treated as "no clock available" and the age check is skipped regardless
    /// of this setting, so RTC-less devices are never silently rejected.
    pub max_quote_age_secs: u64,

    /// When `true`, reject quotes with an all-zero firmware hash.
    pub require_firmware_hash: bool,

    /// When `true`, reject quotes where `event_counter == 0`.
    pub require_event_counter: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            min_slsa_level: DEFAULT_MIN_SLSA_LEVEL,
            max_quote_age_secs: DEFAULT_MAX_QUOTE_AGE_SECS,
            require_firmware_hash: true,
            require_event_counter: false,
        }
    }
}

impl PolicyConfig {
    /// Evaluates a quote's provenance and measurements against this policy.
    ///
    /// Returns `Ok(())` if all checks pass, or the first
    /// [`crate::error::PqRascvError::PolicyViolation`] encountered.
    pub fn evaluate(
        &self,
        slsa_level: u8,
        firmware_hash: &[u8; 32],
        event_counter: u64,
        quote_timestamp: u64,
        now_secs: u64,
    ) -> Result<(), crate::error::PqRascvError> {
        use crate::error::PqRascvError;

        if slsa_level < self.min_slsa_level {
            return Err(PqRascvError::PolicyViolation);
        }
        if self.require_firmware_hash && firmware_hash == &[0u8; 32] {
            return Err(PqRascvError::PolicyViolation);
        }
        if self.require_event_counter && event_counter == 0 {
            return Err(PqRascvError::PolicyViolation);
        }
        // timestamp == 0 means the prover has no real-time clock; skip the age
        // check rather than silently rejecting every quote from RTC-less devices.
        if self.max_quote_age_secs > 0 && quote_timestamp > 0 {
            let age = now_secs.saturating_sub(quote_timestamp);
            if age > self.max_quote_age_secs {
                return Err(PqRascvError::PolicyViolation);
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

    #[test]
    fn default_policy_accepts_valid_quote() {
        let policy = PolicyConfig::default();
        let result = policy.evaluate(1, &[0xabu8; 32], 0, 1_000, 1_100);
        assert!(result.is_ok());
    }

    #[test]
    fn policy_rejects_low_slsa_level() {
        let policy = PolicyConfig {
            min_slsa_level: 3,
            ..Default::default()
        };
        assert!(policy.evaluate(2, &[0xabu8; 32], 0, 1_000, 1_100).is_err());
    }

    #[test]
    fn policy_rejects_zero_firmware_hash() {
        let policy = PolicyConfig {
            require_firmware_hash: true,
            ..Default::default()
        };
        assert!(policy.evaluate(1, &[0u8; 32], 0, 1_000, 1_100).is_err());
    }

    #[test]
    fn policy_rejects_stale_quote() {
        let policy = PolicyConfig {
            max_quote_age_secs: 60,
            ..Default::default()
        };
        // Quote is 120 seconds old.
        assert!(policy.evaluate(1, &[0xabu8; 32], 0, 1_000, 1_120).is_err());
    }

    #[test]
    fn policy_accepts_zero_age_check() {
        let policy = PolicyConfig {
            max_quote_age_secs: 0,
            ..Default::default()
        };
        // Quote appears 10 000 seconds old — no age check, should pass.
        assert!(policy.evaluate(1, &[0xabu8; 32], 0, 1_000, 11_000).is_ok());
    }

    #[test]
    fn policy_accepts_rtc_less_device_with_age_check_enabled() {
        // Devices without a real-time clock pass timestamp=0. The age check
        // must be skipped for them even when max_quote_age_secs is set, to
        // avoid silently rejecting every quote they produce.
        let policy = PolicyConfig {
            max_quote_age_secs: 60,
            ..Default::default()
        };
        assert!(policy.evaluate(1, &[0xabu8; 32], 0, 0, 999_999).is_ok());
    }
}
