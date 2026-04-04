//! Measurement layer — hardware-agnostic Root-of-Trust abstraction.
//!
//! # Design
//!
//! [`RoT`] (Root of Trust) is a trait whose only obligation is to produce a
//! [`Measurements`] snapshot.  The measurement data flows directly into
//! [`AttestationQuote`](crate::quote::AttestationQuote), which is then signed.
//!
//! Concrete backends live in [`crate::backends`]:
//!
//! | Backend | Feature flag | Platform |
//! |---------|-------------|---------|
//! | [`SoftwareRoT`] | *(default)* | any (SHA3-256 over supplied regions) |
//! | `TpmRoT` | `hardware-tpm` | TPM 2.0 devices |
//! | `DiceRoT` | `dice` | DICE-compliant firmware |

use crate::error::PqRascvError;

// ────────────────────────────────────────────────────────────────────────────
// PCR bank
// ────────────────────────────────────────────────────────────────────────────

/// Number of Platform Configuration Registers supported.
pub const PCR_COUNT: usize = 8;
/// Size of each PCR value in bytes (SHA3-256).
pub const PCR_SIZE: usize = 32;

/// An array of PCR (Platform Configuration Register) values.
///
/// Each register is a 32-byte SHA3-256 hash of the corresponding measurement.
/// Index semantics follow the caller's convention; the core crate does not
/// assign meaning to individual PCR indices.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PcrBank(pub [[u8; PCR_SIZE]; PCR_COUNT]);

impl Default for PcrBank {
    fn default() -> Self {
        Self([[0u8; PCR_SIZE]; PCR_COUNT])
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Measurements struct
// ────────────────────────────────────────────────────────────────────────────

/// All measurements produced by a Root-of-Trust during attestation.
///
/// This struct is embedded verbatim in [`AttestationQuote`](crate::quote::AttestationQuote)
/// and therefore serialised as CBOR on the wire.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Measurements {
    /// PCR-style hash bank (SHA3-256 digests of measured regions).
    pub pcrs: PcrBank,

    /// SHA3-256 digest of the firmware / binary image being attested.
    pub firmware_hash: [u8; 32],

    /// Optional SHA3-256 digest of an AI model loaded on the device.
    /// `[0u8; 32]` means "not present".
    pub ai_model_hash: [u8; 32],

    /// Monotonic event counter from the `RoT` hardware (replay protection).
    /// Zero if the backend does not support hardware counters.
    pub event_counter: u64,
}

impl Measurements {
    /// Create a zeroed `Measurements` struct.  Useful as a default in tests.
    #[must_use]
    pub fn zeroed() -> Self {
        Self {
            pcrs: PcrBank::default(),
            firmware_hash: [0u8; 32],
            ai_model_hash: [0u8; 32],
            event_counter: 0,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RoT trait
// ────────────────────────────────────────────────────────────────────────────

/// Root-of-Trust abstraction.
///
/// Implementors collect platform measurements and return them as a
/// [`Measurements`] snapshot.  The implementation must be deterministic
/// for the same platform state — repeated calls on the same state must
/// return the same PCR values.
pub trait RoT {
    /// Collect all measurements from the platform.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::MeasurementFailed`] if any measurement
    /// register cannot be read (e.g. hardware fault, permission denied).
    fn measure(&self) -> Result<Measurements, PqRascvError>;
}

// ────────────────────────────────────────────────────────────────────────────
// SoftwareRoT — default backend
// ────────────────────────────────────────────────────────────────────────────

/// Software-based [`RoT`] that hashes supplied byte regions with SHA3-256.
///
/// This backend is the default for platforms without hardware security
/// modules.  It is suitable for development, testing, and environments
/// where a pure-software measurement chain is acceptable.
///
/// # Usage
///
/// ```
/// use pqrascv_core::measurement::{SoftwareRoT, RoT};
///
/// let rot = SoftwareRoT::new(b"my-firmware-image", None, 0);
/// let measurements = rot.measure().unwrap();
/// assert_ne!(measurements.firmware_hash, [0u8; 32]);
/// ```
pub struct SoftwareRoT<'a> {
    /// Raw bytes of the firmware / binary image to measure.
    firmware: &'a [u8],
    /// Optional AI model bytes to measure.  `None` produces a zero hash.
    ai_model: Option<&'a [u8]>,
    /// Monotonic counter value to embed.
    event_counter: u64,
    /// Optional extra regions to fold into individual PCRs (up to `PCR_COUNT`).
    pcr_regions: &'a [&'a [u8]],
}

impl<'a> SoftwareRoT<'a> {
    /// Constructs a new [`SoftwareRoT`].
    ///
    /// - `firmware`: bytes of the code image being attested.
    /// - `ai_model`: optional AI model bytes; `None` leaves `ai_model_hash` zeroed.
    /// - `event_counter`: caller-supplied monotonic counter.
    #[must_use]
    pub fn new(firmware: &'a [u8], ai_model: Option<&'a [u8]>, event_counter: u64) -> Self {
        Self {
            firmware,
            ai_model,
            event_counter,
            pcr_regions: &[],
        }
    }

    /// Attaches additional memory regions for PCR measurements.
    ///
    /// Each region is hashed into the corresponding PCR slot.  If more than
    /// [`PCR_COUNT`] regions are supplied the extras are silently ignored.
    #[must_use]
    pub fn with_pcr_regions(mut self, regions: &'a [&'a [u8]]) -> Self {
        self.pcr_regions = regions;
        self
    }
}

impl RoT for SoftwareRoT<'_> {
    fn measure(&self) -> Result<Measurements, PqRascvError> {
        use sha3::{Digest, Sha3_256};

        let firmware_hash: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(self.firmware);
            h.finalize().into()
        };

        let ai_model_hash: [u8; 32] = match self.ai_model {
            Some(model) => {
                let mut h = Sha3_256::new();
                h.update(model);
                h.finalize().into()
            }
            None => [0u8; 32],
        };

        let mut pcrs = PcrBank::default();
        for (i, region) in self.pcr_regions.iter().enumerate().take(PCR_COUNT) {
            let mut h = Sha3_256::new();
            h.update(region);
            pcrs.0[i] = h.finalize().into();
        }

        Ok(Measurements {
            pcrs,
            firmware_hash,
            ai_model_hash,
            event_counter: self.event_counter,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_hash_changes_with_content() {
        let rot_a = SoftwareRoT::new(b"firmware_a", None, 0);
        let rot_b = SoftwareRoT::new(b"firmware_b", None, 0);
        let m_a = rot_a.measure().unwrap();
        let m_b = rot_b.measure().unwrap();
        assert_ne!(m_a.firmware_hash, m_b.firmware_hash);
    }

    #[test]
    fn firmware_hash_is_deterministic() {
        let rot = SoftwareRoT::new(b"stable-firmware", None, 42);
        assert_eq!(rot.measure().unwrap(), rot.measure().unwrap());
    }

    #[test]
    fn ai_model_hash_zero_when_absent() {
        let rot = SoftwareRoT::new(b"fw", None, 0);
        assert_eq!(rot.measure().unwrap().ai_model_hash, [0u8; 32]);
    }

    #[test]
    fn pcr_regions_are_hashed() {
        let regions: &[&[u8]] = &[b"pcr0", b"pcr1"];
        let rot = SoftwareRoT::new(b"fw", None, 0).with_pcr_regions(regions);
        let m = rot.measure().unwrap();
        // PCR 0 and 1 should not be zero.
        assert_ne!(m.pcrs.0[0], [0u8; 32]);
        assert_ne!(m.pcrs.0[1], [0u8; 32]);
        // PCR 2+ untouched → zero.
        assert_eq!(m.pcrs.0[2], [0u8; 32]);
    }
}
