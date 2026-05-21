# Verifier Timeline State Tracking

To detect replays and evaluate the temporal sequence of a device's attestation, the verifier maintains a chronological event log for each registered device. This is represented by the `AttestationTimeline` structure.

## Timeline Structures

A timeline consists of a chronological series of events:

```rust
pub enum AttestationEvent {
    /// Initial boot measurement verification completed successfully.
    BootVerified { timestamp: u64 },
    /// A new runtime attestation measurement block was received.
    RuntimeMeasurementReceived { timestamp: u64, sequence_number: u64 },
    /// System runtime drift was detected.
    RuntimeDriftDetected { timestamp: u64, severity: DriftSeverity },
    /// The active policy epoch changed.
    PolicyEpochChanged { timestamp: u64, new_epoch: u64 },
    /// Attestation lease expired before new evidence was received.
    AttestationExpired { timestamp: u64 },
}

pub struct AttestationTimeline {
    /// Identification of the device.
    pub device_id: String,
    /// Chronological list of events.
    pub events: Vec<AttestationEvent>,
}
```

## Consistency Verification

The verifier asserts timeline consistency by evaluating two rules:

1. **Temporal Ordering**: Every event's timestamp must be greater than or equal to the previous event's timestamp. A violation indicates clock drift or timestamp manipulation (`TimelineValidationError::TemporalOrderingViolation`).
2. **Sequence Monotonicity**: For all `RuntimeMeasurementReceived` events, the sequence number must be strictly monotonic (greater than the last seen sequence number). Any decrease or repetition indicates a sequence rollback or replay attempt (`TimelineValidationError::SequenceNumberRollback`).

### Timeline Verification Implementation

```rust
impl AttestationTimeline {
    pub fn verify_consistency(&self) -> Result<(), TimelineValidationError> {
        let mut last_timestamp = 0;
        let mut last_sequence = None;

        for event in &self.events {
            let ts = event.timestamp();
            if ts < last_timestamp {
                return Err(TimelineValidationError::TemporalOrderingViolation);
            }
            last_timestamp = ts;

            if let AttestationEvent::RuntimeMeasurementReceived { sequence_number, .. } = *event {
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
```
