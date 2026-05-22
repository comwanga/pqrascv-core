//! Incremental Runtime Integrity Streaming
//!
//! Provides the core semantics for transitioning away from snapshot-oriented
//! attestations toward continuous, streaming runtime integrity events.
//! Ensures sequence monotonicity, prevents gaps, and manages rolling
//! stream checkpoints.

use crate::digest::TypedDigest;
use crate::runtime_attestation::RuntimeMeasurement;
use alloc::string::String;
use alloc::vec::Vec;

/// A single incremental runtime integrity event in a continuous stream.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeStreamEvent {
    /// Monotonically increasing sequence number for this stream.
    pub sequence: u64,
    /// Unix timestamp of the event.
    pub timestamp: u64,
    /// The incremental measurements acquired during this window.
    pub measurements: Vec<RuntimeMeasurement>,
    /// The delta hash representing the incremental change state.
    pub delta_hash: TypedDigest,
}

/// Represents the state of an active, verifiable runtime integrity stream.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeIntegrityStream {
    /// Unique identifier for this stream session.
    pub stream_id: String,
    /// The hardware identity generating this stream.
    pub device_id: String,
    /// The highest sequence number successfully ingested.
    pub current_sequence: u64,
    /// The sequence number of the last compacted checkpoint.
    pub last_checkpoint: u64,
    /// Whether the stream is currently accepting new events.
    pub active: bool,
}

impl RuntimeIntegrityStream {
    /// Initializes a new stream for a given device.
    #[must_use]
    pub fn new(stream_id: String, device_id: String) -> Self {
        Self {
            stream_id,
            device_id,
            current_sequence: 0,
            last_checkpoint: 0,
            active: true,
        }
    }

    /// Ingests the next event in the stream, strictly enforcing monotonicity.
    ///
    /// Fails closed on sequence replays, gaps, or if the stream is inactive.
    pub fn ingest_event(&mut self, event: &RuntimeStreamEvent) -> Result<(), &'static str> {
        if !self.active {
            return Err("stream is inactive and cannot accept new events");
        }

        // Must be exactly the next sequence
        let expected = self.current_sequence + 1;
        if event.sequence < expected {
            return Err("sequence replay detected");
        } else if event.sequence > expected {
            return Err("sequence gap detected");
        }

        // Enforce basic timeline sanity
        if event.timestamp == 0 {
            return Err("event timestamp must be non-zero");
        }

        self.current_sequence = event.sequence;
        Ok(())
    }

    /// Rotates the stream's checkpoint marker to the current sequence.
    pub fn rotate_checkpoint(&mut self) -> Result<(), &'static str> {
        if self.current_sequence == self.last_checkpoint {
            return Err("no new events to checkpoint");
        }
        self.last_checkpoint = self.current_sequence;
        Ok(())
    }

    /// Terminates the stream, preventing further ingestions.
    pub fn terminate(&mut self) {
        self.active = false;
    }
}
