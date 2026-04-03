//! TPM 2.0 Root-of-Trust backend.
//!
//! This module provides a [`TpmRoT`] that reads PCR values from a TPM 2.0
//! device using the host OS TPM driver.
//!
//! # Status
//!
//! **Stub** — full TSS2/tpm2-tss integration is a near-term milestone.
//! The trait signature is stable; only the driver calls need filling in.
//!
//! Enabled by the `hardware-tpm` feature flag.

use crate::{
    error::PqRascvError,
    measurement::{Measurements, RoT},
};

/// TPM 2.0 Root-of-Trust.
///
/// Reads PCR bank 0 (SHA-256 bank) from the system TPM and returns the
/// values as a [`Measurements`] snapshot.
///
/// # Availability
///
/// Requires the `hardware-tpm` feature and a kernel TPM driver
/// (e.g. `/dev/tpm0` on Linux, TBS on Windows).
pub struct TpmRoT {
    /// TPM PCR selection mask (bit N = read PCR N).  Default: all 8.
    pcr_mask: u8,
    /// Event counter to embed (caller-supplied; TPM NV index reads are
    /// deferred to the full implementation).
    event_counter: u64,
}

impl TpmRoT {
    /// Creates a new [`TpmRoT`] that reads PCRs matching `pcr_mask`.
    #[must_use]
    pub fn new(pcr_mask: u8, event_counter: u64) -> Self {
        Self { pcr_mask, event_counter }
    }
}

impl RoT for TpmRoT {
    fn measure(&self) -> Result<Measurements, PqRascvError> {
        // TODO: integrate with tpm2-tss or tss-esapi crate.
        //
        // Planned steps:
        //   1. Open /dev/tpm0 (Linux) or TBS context (Windows).
        //   2. Invoke TPM2_PCR_Read for selected PCR indices.
        //   3. Map SHA-256 PCR values into pcrs.0[i].
        //   4. Read TPM NV counter for event_counter.
        //   5. Hash firmware via TPM2_Hash if available.
        //
        // For now return BackendUnavailable so callers can detect the stub.
        Err(PqRascvError::BackendUnavailable)
    }
}
