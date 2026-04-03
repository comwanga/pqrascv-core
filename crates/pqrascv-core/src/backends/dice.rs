//! DICE (Device Identifier Composition Engine) Root-of-Trust backend.
//!
//! DICE is specified by the TCG DICE Architecture and is widely used in
//! microcontroller firmware (Zephyr, Tock, OpenTitan, Arm CCA).
//!
//! # Status
//!
//! **Stub** — full integration with a DICE layer (e.g. CDI extension) is a
//! near-term milestone.  The trait signature is stable.
//!
//! Enabled by the `dice` feature flag.

use crate::{
    error::PqRascvError,
    measurement::{Measurements, RoT},
};

/// DICE Root-of-Trust.
///
/// Derives measurements from the DICE Compound Device Identifier (CDI)
/// and the firmware image hash recorded in the DICE certificate chain.
///
/// # Availability
///
/// Requires the `dice` feature.  Typically available on bare-metal targets
/// running Zephyr, Tock, or OpenTitan firmware with DICE enabled.
pub struct DiceRoT {
    /// CDI (Compound Device Identifier) bytes from the previous DICE layer.
    /// On real hardware this is derived from a hardware secret; for testing
    /// callers can pass any 32-byte array.
    cdi: [u8; 32],
    /// Firmware image bytes to measure.
    firmware: &'static [u8],
}

impl DiceRoT {
    /// Creates a new [`DiceRoT`] from a CDI value and firmware image.
    #[must_use]
    pub fn new(cdi: [u8; 32], firmware: &'static [u8]) -> Self {
        Self { cdi, firmware }
    }
}

impl RoT for DiceRoT {
    fn measure(&self) -> Result<Measurements, PqRascvError> {
        // TODO: integrate with the DICE layer.
        //
        // Planned steps:
        //   1. Hash firmware image with SHA3-256 → firmware_hash.
        //   2. Derive CDI_Sealing = HMAC-SHA3(CDI, "DICE-seal" || firmware_hash).
        //   3. Derive CDI_Attestation = HMAC-SHA3(CDI, "DICE-attest" || firmware_hash).
        //   4. Populate pcrs.0[0] with CDI_Attestation (DICE PCR equivalent).
        //   5. Read monotonic counter from DICE NV if available.
        //
        // For now return BackendUnavailable so callers can detect the stub.
        let _ = (self.cdi, self.firmware); // suppress unused-field warnings
        Err(PqRascvError::BackendUnavailable)
    }
}
