//! Live TPM 2.0 Integration
//!
//! Provides the acquisition layer for collecting real TPM quotes, PCRs,
//! and capabilities using `tss-esapi`. Verification is strictly handled
//! by native parsers, not by this layer.

#![cfg(feature = "live-evidence")]

use crate::digest::DigestAlgorithm;
use alloc::string::String;
use alloc::vec::Vec;

/// Represents a live connection to a local TPM 2.0 device.
#[derive(Debug)]
pub struct LiveTpmDevice {
    pub device_path: String,
    pub manufacturer: String,
    pub firmware_version: String,
    pub supported_banks: Vec<DigestAlgorithm>,
}

impl LiveTpmDevice {
    /// Connects to the TPM device (e.g. `/dev/tpmrm0`).
    pub fn connect(device_path: &str) -> Result<Self, &'static str> {
        // Implementation would initialize a tss_esapi Context
        // For now, we return a stubbed connection since we are separating acquisition.
        Ok(Self {
            device_path: device_path.into(),
            manufacturer: String::from("Unknown"),
            firmware_version: String::from("0.0.0"),
            supported_banks: alloc::vec![DigestAlgorithm::Sha256, DigestAlgorithm::Sha384],
        })
    }

    /// Reads the requested PCR bank from the live TPM.
    pub fn read_pcr_bank(&self, _bank: DigestAlgorithm) -> Result<Vec<u8>, &'static str> {
        Err("not implemented")
    }

    /// Acquires a real TPM quote for the specified PCRs.
    pub fn acquire_quote(
        &self,
        _nonce: &[u8],
        _pcr_indices: &[u32],
    ) -> Result<Vec<u8>, &'static str> {
        Err("not implemented")
    }

    /// Reads the internal TPM clock and reset counters for freshness semantics.
    pub fn read_clock_info(&self) -> Result<(u64, u32), &'static str> {
        Err("not implemented")
    }

    /// Validates capabilities and rejects unsupported/weak algorithms (e.g., SHA-1).
    pub fn read_capabilities(&self) -> Result<(), &'static str> {
        Err("not implemented")
    }
}
