# Continuous Attestation Framework

Continuous attestation extends PQ-RASCV v2 from a one-time boot validation check to a stateful, continuous monitoring model. Instead of verifying the platform only at boot, the verifier establishes long-lived attestation sessions and periodically evaluates fresh evidence.

## Stateful Sessions

At the core of the continuous attestation framework is the `AttestationSession` struct. This structure tracks session state on the verifier side:

```rust
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
```

## Security Guarantees

The continuous attestation session model provides three critical security properties:

1. **Monotonicity**: The sequence number of incoming evidence must be strictly incremented by exactly 1 (`sequence_number + 1`). This prevents gaps in the verification history.
2. **Replay Prevention**: Evidence containing duplicate or smaller sequence numbers is rejected immediately.
3. **Lease Expiration**: Every session has a configurable validation window (lease). If the verifier does not receive new evidence within this window, the session expires, indicating a potential offline attack or network disruption.

## Session Transition Logic

The verifier transition logic is implemented in the `verify_next_sequence` method:

```rust
impl AttestationSession {
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

        // Update state
        self.sequence_number = next_sequence;
        self.last_seen = now;
        Ok(())
    }
}
```

## Policy Configuration

The policy engine enforces continuous attestation using two rules:
- `HardwarePolicyRule::RequireContinuousAttestation`: Validates that a session exists and is active/unexpired.
- `HardwarePolicyRule::RequireSequenceMonotonicity`: Validates that the evidence sequence matches the expected session sequence.

## Session Error Handling

If a session fails validation, one of the following `SessionError` variants is returned:
- `SessionInactive`: The session was deactivated manually or due to a security violation.
- `SessionExpired`: The platform failed to attest within the allowed time window.
- `NonMonotonicSequence`: A sequence number skipped a slot, suggesting missed evidence.
- `ReplayDetected`: A replayed or out-of-order sequence number was detected.
