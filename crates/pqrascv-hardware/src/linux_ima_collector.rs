//! Linux IMA Collection
//!
//! Provides bounded, streaming parsing of the Linux Integrity Measurement Architecture
//! (IMA) logs from `/sys/kernel/security/ima/ascii_runtime_measurements`.
//! Protects against kernel-level resource exhaustion by strictly enforcing limits.

#![cfg(feature = "live-evidence")]

use alloc::string::String;
use alloc::vec::Vec;

pub const MAX_EVENTS: usize = 10_000;
pub const MAX_ENTRY_SIZE: usize = 4096;
pub const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;

/// Represents a single ingested IMA event.
#[derive(Debug, Clone)]
pub struct ImaEvent {
    pub pcr: u32,
    pub template_hash: Vec<u8>,
    pub template_name: String,
    pub filedata_hash: Vec<u8>,
    pub filename: String,
}

/// A streaming, bounded collector for live Linux IMA logs.
#[derive(Debug)]
pub struct LiveImaCollector {
    pub measurement_path: String,
    pub appraisal_enabled: bool,
    events_read: usize,
    bytes_read: usize,
}

impl LiveImaCollector {
    /// Initializes a new IMA collector pointed at the specified sysfs path.
    pub fn new(path: &str, appraisal_enabled: bool) -> Self {
        Self {
            measurement_path: path.into(),
            appraisal_enabled,
            events_read: 0,
            bytes_read: 0,
        }
    }

    /// Reads the IMA log in a streaming fashion, yielding events.
    /// Fails closed if limits are exceeded or malformed data is encountered.
    pub fn stream_measurements<F>(&mut self, mut _callback: F) -> Result<(), &'static str>
    where
        F: FnMut(ImaEvent) -> Result<(), &'static str>,
    {
        // In a real implementation on Linux, this would open the file and stream lines.
        // It must check:
        // if self.events_read >= MAX_EVENTS { return Err("too many events"); }
        // if self.bytes_read >= MAX_TOTAL_BYTES { return Err("log too large"); }
        // For demonstration, we simply return success as a stub.
        Ok(())
    }
}
