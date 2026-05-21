//! Hardware monotonic counter evidence.
//!
//! # Problem
//!
//! In v1, `event_counter: u64` was caller-controlled and non-monotonic.
//! A replay attacker could reuse a captured quote because the counter
//! provided no real freshness guarantee.
//!
//! # Solution
//!
//! [`CounterEvidence`] is an explicit enum with three variants:
//!
//! - `HardwareMonotonic` — a counter backed by TPM NV or equivalent hardware.
//!   The verifier can require this variant via policy.
//! - `SoftwareObserved` — a counter from a software source (OS clock, sequence
//!   number). Weaker than hardware, but better than nothing.
//! - `Unsupported` — the backend has no counter. The verifier must rely
//!   entirely on the nonce for freshness.
//!
//! The policy engine's `RequireHardwareCounter` rule rejects anything that
//! is not `HardwareMonotonic`.

// ── CounterEvidence ───────────────────────────────────────────────────────

/// Monotonic counter evidence from a hardware or software source.
///
/// The verifier uses this to bound the age of an attestation quote when
/// no real-time clock is available, or as an additional freshness signal
/// alongside the nonce.
///
/// # Ordering
///
/// `HardwareMonotonic` > `SoftwareObserved` > `Unsupported` in terms of
/// trust strength. Policy rules can require a minimum trust level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CounterEvidence {
    /// A counter backed by hardware (e.g. TPM NV monotonic counter,
    /// TPM audit counter, or equivalent).
    ///
    /// The value is guaranteed to be non-decreasing across power cycles
    /// (within the hardware's lifetime). The verifier can store the last
    /// seen value and reject quotes with a lower counter.
    HardwareMonotonic(u64),

    /// A counter from a software source (e.g. OS uptime, sequence number).
    ///
    /// Weaker than `HardwareMonotonic` — an attacker with OS access could
    /// manipulate it. Acceptable for low-security deployments or when
    /// hardware counters are unavailable.
    SoftwareObserved(u64),

    /// The backend does not support any counter.
    ///
    /// Freshness relies entirely on the nonce. The verifier policy must
    /// explicitly permit this via `allow_no_counter`.
    Unsupported,
}

impl CounterEvidence {
    /// Returns the counter value if available (either variant with a value).
    #[must_use]
    pub fn value(self) -> Option<u64> {
        match self {
            Self::HardwareMonotonic(v) | Self::SoftwareObserved(v) => Some(v),
            Self::Unsupported => None,
        }
    }

    /// Returns `true` if this counter is hardware-backed.
    #[must_use]
    pub fn is_hardware_backed(self) -> bool {
        matches!(self, Self::HardwareMonotonic(_))
    }

    /// Returns `true` if any counter value is available.
    #[must_use]
    pub fn is_available(self) -> bool {
        !matches!(self, Self::Unsupported)
    }

    /// Returns the trust level as an ordinal (higher = more trusted).
    ///
    /// Used by policy rules that require a minimum trust level.
    #[must_use]
    pub fn trust_level(self) -> u8 {
        match self {
            Self::HardwareMonotonic(_) => 2,
            Self::SoftwareObserved(_) => 1,
            Self::Unsupported => 0,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_monotonic_is_hardware_backed() {
        assert!(CounterEvidence::HardwareMonotonic(42).is_hardware_backed());
        assert!(!CounterEvidence::SoftwareObserved(42).is_hardware_backed());
        assert!(!CounterEvidence::Unsupported.is_hardware_backed());
    }

    #[test]
    fn value_extraction() {
        assert_eq!(CounterEvidence::HardwareMonotonic(99).value(), Some(99));
        assert_eq!(CounterEvidence::SoftwareObserved(7).value(), Some(7));
        assert_eq!(CounterEvidence::Unsupported.value(), None);
    }

    #[test]
    fn trust_level_ordering() {
        assert!(
            CounterEvidence::HardwareMonotonic(0).trust_level()
                > CounterEvidence::SoftwareObserved(0).trust_level()
        );
        assert!(
            CounterEvidence::SoftwareObserved(0).trust_level()
                > CounterEvidence::Unsupported.trust_level()
        );
    }

    #[test]
    fn is_available() {
        assert!(CounterEvidence::HardwareMonotonic(1).is_available());
        assert!(CounterEvidence::SoftwareObserved(1).is_available());
        assert!(!CounterEvidence::Unsupported.is_available());
    }
}
