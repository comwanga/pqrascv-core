//! Verifier Timeline state tracking
//!
//! Stores chronological history of attestation outcomes to ensure sequence
//! safety, detect replays, and support auditability.

use alloc::string::String;
use alloc::vec::Vec;

/// Events recorded in a device's attestation lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AttestationEvent {
    /// Initial boot measurement verification completed successfully.
    BootVerified {
        timestamp: u64,
        sequence_number: u64,
        event_hash: crate::digest::TypedDigest,
    },
    /// A new runtime attestation measurement block was received.
    RuntimeMeasurementReceived {
        timestamp: u64,
        sequence_number: u64,
        event_hash: crate::digest::TypedDigest,
    },
    /// System runtime drift was detected.
    RuntimeDriftDetected {
        timestamp: u64,
        sequence_number: u64,
        event_hash: crate::digest::TypedDigest,
        severity: crate::drift::DriftSeverity,
    },
    /// The active policy epoch changed.
    PolicyEpochChanged {
        timestamp: u64,
        sequence_number: u64,
        event_hash: crate::digest::TypedDigest,
        new_epoch: u64,
    },
    /// Attestation lease expired before new evidence was received.
    AttestationExpired {
        timestamp: u64,
        sequence_number: u64,
        event_hash: crate::digest::TypedDigest,
    },
}

impl AttestationEvent {
    /// Returns the timestamp associated with the event.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        match *self {
            Self::BootVerified { timestamp, .. }
            | Self::RuntimeMeasurementReceived { timestamp, .. }
            | Self::RuntimeDriftDetected { timestamp, .. }
            | Self::PolicyEpochChanged { timestamp, .. }
            | Self::AttestationExpired { timestamp, .. } => timestamp,
        }
    }

    /// Returns the sequence number associated with the event.
    #[must_use]
    pub fn sequence_number(&self) -> u64 {
        match *self {
            Self::BootVerified { sequence_number, .. }
            | Self::RuntimeMeasurementReceived { sequence_number, .. }
            | Self::RuntimeDriftDetected { sequence_number, .. }
            | Self::PolicyEpochChanged { sequence_number, .. }
            | Self::AttestationExpired { sequence_number, .. } => sequence_number,
        }
    }

    /// Returns the event hash digest associated with the event.
    #[must_use]
    pub fn event_hash(&self) -> &crate::digest::TypedDigest {
        match self {
            Self::BootVerified { event_hash, .. }
            | Self::RuntimeMeasurementReceived { event_hash, .. }
            | Self::RuntimeDriftDetected { event_hash, .. }
            | Self::PolicyEpochChanged { event_hash, .. }
            | Self::AttestationExpired { event_hash, .. } => event_hash,
        }
    }
}

/// Chronological sequence of attestation events for a specific device.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttestationTimeline {
    /// Identification of the device.
    pub device_id: String,
    /// Chronological list of events.
    pub events: Vec<AttestationEvent>,
}

/// Errors from validating timeline consistency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelineValidationError {
    /// Timestamps in the timeline are out of order.
    TemporalOrderingViolation,
    /// An event sequence anomaly (e.g. sequence number rollback).
    SequenceNumberRollback { expected: u64, got: u64 },
}

impl core::fmt::Display for TimelineValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TemporalOrderingViolation => {
                f.write_str("timeline events are out of chronological order")
            }
            Self::SequenceNumberRollback { expected, got } => {
                write!(
                    f,
                    "sequence number rollback detected: expected >= {expected}, got {got}"
                )
            }
        }
    }
}

impl AttestationTimeline {
    /// Creates an empty timeline for a device.
    #[must_use]
    pub fn new(device_id: String) -> Self {
        Self {
            device_id,
            events: Vec::new(),
        }
    }

    /// Returns a slice of events in the timeline.
    #[must_use]
    pub fn events(&self) -> &[AttestationEvent] {
        &self.events
    }

    /// Appends an event to the timeline.
    pub fn push(&mut self, event: AttestationEvent) {
        self.events.push(event);
    }

    /// Validates temporal ordering and sequence consistency of the timeline.
    ///
    /// # Errors
    ///
    /// Returns `TimelineValidationError` if the events violate chronological ordering
    /// or contain sequence rollback anomalies.
    pub fn verify_consistency(&self) -> Result<(), TimelineValidationError> {
        let mut last_timestamp = 0;
        let mut last_sequence = None;

        for event in &self.events {
            let ts = event.timestamp();
            if ts < last_timestamp {
                return Err(TimelineValidationError::TemporalOrderingViolation);
            }
            last_timestamp = ts;

            if let AttestationEvent::RuntimeMeasurementReceived {
                sequence_number, ..
            } = *event
            {
                if let Some(prev) = last_sequence {
                    if sequence_number <= prev {
                        return Err(TimelineValidationError::SequenceNumberRollback {
                            expected: prev + 1,
                            got: sequence_number,
                        });
                    }
                }
                last_sequence = Some(sequence_number);
            }
        }

        Ok(())
    }
}
