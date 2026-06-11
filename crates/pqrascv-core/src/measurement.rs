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
//! | [`SoftwareRoT`] | `software-rot-unsafe` | **testing only** — not a real security boundary |
//! | `TpmRoT` | `hardware-tpm` | TPM 2.0 devices |
//! | `DiceRoT` | `dice` | DICE-compliant firmware |

use crate::error::PqRascvError;

/// Number of Platform Configuration Registers supported.
pub const PCR_COUNT: usize = 8;
/// Size of each PCR value in bytes (SHA3-256).
pub const PCR_SIZE: usize = 32;

// PCR slot semantic constants.
// All backends must use these indices consistently so policy rules are portable.
/// PCR slot 0: firmware / boot image measurement.
pub const PCR_FIRMWARE: usize = 0;
/// PCR slot 1: configuration / device tree measurement.
pub const PCR_CONFIG: usize = 1;
/// PCR slot 2: bootloader measurement.
pub const PCR_BOOTLOADER: usize = 2;
/// PCR slot 3: secure-world / `TrustZone` image measurement.
pub const PCR_SECURE_WORLD: usize = 3;
/// PCR slots 4–7: reserved for application-defined use.
pub const PCR_APP_BASE: usize = 4;

/// Hash algorithm used to produce PCR digests.
///
/// All backends normalize to SHA3-256 before storing values in [`PcrBank`].
/// The TPM backend reads SHA-256 PCRs from hardware and then wraps each
/// raw digest through `SHA3-256(raw_pcr_value)` so that policy rules can
/// compare values across backends without algorithm confusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PcrAlgorithm {
    /// SHA3-256 (FIPS 202) — the canonical algorithm for all backends.
    Sha3_256,
}

/// An array of PCR (Platform Configuration Register) values.
///
/// All digests are normalized to SHA3-256 regardless of the underlying
/// hardware algorithm. See [`PcrAlgorithm`] for details.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PcrBank {
    /// The 8 PCR digest values, each 32 bytes.
    pub digests: [[u8; PCR_SIZE]; PCR_COUNT],
    /// Hash algorithm used for all entries (always `Sha3_256` after normalization).
    pub algorithm: PcrAlgorithm,
}

impl Default for PcrBank {
    fn default() -> Self {
        Self {
            digests: [[0u8; PCR_SIZE]; PCR_COUNT],
            algorithm: PcrAlgorithm::Sha3_256,
        }
    }
}

/// All measurements produced by a Root-of-Trust during attestation.
///
/// This struct is embedded verbatim in [`AttestationQuote`](crate::quote::AttestationQuote)
/// and serialized as CBOR on the wire.
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
    /// Returns a zeroed `Measurements`. Handy for tests and default initializations.
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

/// Root-of-Trust abstraction.
///
/// Your implementation should collect whatever platform measurements are
/// available and pack them into a [`Measurements`] snapshot.
///
/// Important: two calls on the same, unchanged platform must return
/// identical PCR values — the verifier depends on this.
pub trait RoT {
    /// Collect all measurements from the platform.
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::MeasurementFailed`] if any measurement
    /// register cannot be read (e.g. hardware fault, permission denied).
    fn measure(&self) -> Result<Measurements, PqRascvError>;
}

/// Software-based [`RoT`] that hashes supplied byte regions with SHA3-256.
///
/// # ⚠ SECURITY WARNING — NOT FOR PRODUCTION USE
///
/// `SoftwareRoT` is gated behind the `software-rot-unsafe` feature flag
/// because it provides **no real attestation security**. The caller supplies
/// the bytes to be measured, so compromised firmware can trivially pass its
/// own expected-clean bytes and produce a cryptographically valid quote for
/// code that is not actually running.
///
/// Use this backend only for:
/// - Unit and integration tests
/// - CI pipelines without hardware
/// - Local development
///
/// For production, use [`TpmRoT`](crate::backends::tpm::TpmRoT) or
/// [`DiceRoT`](crate::backends::dice::DiceRoT), which root measurements in
/// hardware that executes before and outside the attested code.
#[cfg(feature = "software-rot-unsafe")]
pub struct SoftwareRoT<'a> {
    /// Raw bytes of the firmware / binary image to measure.
    firmware: &'a [u8],
    /// Optional AI model bytes to measure.  `None` produces a zero hash.
    ai_model: Option<&'a [u8]>,
    /// Monotonic counter value to embed.
    event_counter: u64,
    /// Extra memory regions to hash into PCR slots, one region per slot.
    pcr_regions: &'a [&'a [u8]],
}

#[cfg(feature = "software-rot-unsafe")]
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
    /// Each region gets hashed into its matching PCR slot, in order.
    /// Extras beyond [`PCR_COUNT`] are quietly ignored.
    #[must_use]
    pub fn with_pcr_regions(mut self, regions: &'a [&'a [u8]]) -> Self {
        self.pcr_regions = regions;
        self
    }
}

#[cfg(feature = "software-rot-unsafe")]
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
            pcrs.digests[i] = h.finalize().into();
        }

        Ok(Measurements {
            pcrs,
            firmware_hash,
            ai_model_hash,
            event_counter: self.event_counter,
        })
    }
}

#[cfg(all(test, feature = "software-rot-unsafe"))]
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
        assert_ne!(m.pcrs.digests[0], [0u8; 32]);
        assert_ne!(m.pcrs.digests[1], [0u8; 32]);
        assert_eq!(m.pcrs.digests[2], [0u8; 32]);
        assert_eq!(m.pcrs.algorithm, PcrAlgorithm::Sha3_256);
    }
}
