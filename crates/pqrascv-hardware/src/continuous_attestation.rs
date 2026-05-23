//! Continuous Attestation Sessions
//!
//! Provides structures to track long-lived verification sessions and enforce
//! freshness, monotonicity, and sequence continuity.

use alloc::string::String;

/// A stateful continuous attestation session tracked on the verifier side.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttestationSession {
    /// Unique identifier for this attestation session.
    pub session_id: String,
    /// Unique identifier of the device/prover.
    pub device_id: String,
    /// Unix timestamp when the session was created.
    pub started_at: u64,
    /// Unix timestamp when the last valid evidence was received.
    pub last_seen: u64,
    /// The last verified sequence number.
    pub sequence_number: u64,
    /// Indicates whether the session is currently active.
    pub active: bool,
}

/// Errors occurring during session validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// The session has been deactivated.
    SessionInactive,
    /// The session lease has expired.
    SessionExpired,
    /// The sequence number is non-contiguous or non-monotonic.
    NonMonotonicSequence {
        /// Expected sequence number.
        expected: u64,
        /// Received sequence number.
        got: u64,
    },
    /// A duplicate or smaller sequence number was received, indicating a replay.
    ReplayDetected,
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SessionInactive => f.write_str("attestation session is inactive"),
            Self::SessionExpired => f.write_str("attestation session lease has expired"),
            Self::NonMonotonicSequence { expected, got } => {
                write!(
                    f,
                    "non-monotonic sequence number: expected {expected}, got {got}"
                )
            }
            Self::ReplayDetected => {
                f.write_str("replay detected: duplicate or stale sequence number")
            }
        }
    }
}

impl AttestationSession {
    /// Asserts sequence monotonicity and freshness constraints.
    ///
    /// # Errors
    ///
    /// Returns `SessionError` if the session is inactive, expired, or if the
    /// sequence number does not match sequence continuity rules.
    pub fn verify_next_sequence(
        &mut self,
        next_sequence: u64,
        now: u64,
        expiration_window: u64,
    ) -> Result<(), SessionError> {
        if !self.active {
            return Err(SessionError::SessionInactive);
        }

        // Verify expiration
        if now < self.last_seen || now - self.last_seen > expiration_window {
            return Err(SessionError::SessionExpired);
        }

        // Replay and gap checks
        if next_sequence <= self.sequence_number {
            return Err(SessionError::ReplayDetected);
        }

        if next_sequence != self.sequence_number + 1 {
            return Err(SessionError::NonMonotonicSequence {
                expected: self.sequence_number + 1,
                got: next_sequence,
            });
        }

        self.sequence_number = next_sequence;
        self.last_seen = now;
        Ok(())
    }
}
