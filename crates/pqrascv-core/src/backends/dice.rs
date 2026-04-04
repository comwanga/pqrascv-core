//! DICE (Device Identifier Composition Engine) Root-of-Trust backend.
//!
//! Implements the TCG DICE Architecture §6 CDI derivation in pure Rust,
//! using only SHA3-256 and no heap allocation.
//!
//! # DICE primer
//!
//! DICE is a TCG standard for hardware-rooted device identity.  Each firmware
//! layer receives a Compound Device Identifier (CDI) from the layer below.
//! The CDI is derived by hashing the previous-layer CDI together with the
//! current firmware measurement (FWID), providing a layered trust chain.
//!
//! ```text
//! UDS (hardware secret)
//!   └─► CDI_0 = SHA3-256(UDS   ║ "DICE-attest" ║ FWID_0)
//!         └─► CDI_1 = SHA3-256(CDI_0 ║ "DICE-attest" ║ FWID_1)
//!               └─► …
//! ```
//!
//! [`DiceRoT`] takes the CDI passed from the previous layer and the current
//! firmware image, and derives the attestation CDI stored in PCR 0.
//!
//! # Enabled by
//!
//! The `dice` Cargo feature.  No additional system libraries are required.

use crate::{
    error::PqRascvError,
    measurement::{Measurements, PcrBank, RoT},
};
use sha3::{Digest, Sha3_256};

/// Domain-separation label for attestation CDI derivation (TCG DICE §6.2).
const DICE_ATTEST_LABEL: &[u8] = b"DICE-attest";

/// DICE Root-of-Trust.
///
/// Derives measurements from the Compound Device Identifier (CDI) supplied
/// by the previous DICE layer and the firmware image.
///
/// # Security
///
/// - `cdi` must be kept secret; it is the hardware root credential.
/// - The derived `cdi_attestation` in PCR 0 is safe to include in an
///   attestation quote because it is one-way (SHA3-256 hash).
/// - Different firmware images produce different `cdi_attestation` values,
///   so a verifier can detect unexpected firmware changes.
///
/// # Example
///
/// ```
/// use pqrascv_core::backends::dice::DiceRoT;
/// use pqrascv_core::measurement::RoT;
///
/// static FIRMWARE: &[u8] = b"my-firmware-image";
/// let cdi = [0xabu8; 32]; // In production: obtained from hardware
///
/// let rot = DiceRoT::new(cdi, FIRMWARE, None, 0);
/// let m = rot.measure().unwrap();
/// assert_ne!(m.pcrs.0[0], [0u8; 32], "PCR 0 must contain CDI attestation");
/// assert_ne!(m.firmware_hash, [0u8; 32]);
/// ```
pub struct DiceRoT<'a> {
    /// Compound Device Identifier from the previous DICE layer.
    cdi: [u8; 32],
    /// Firmware image bytes — measured by SHA3-256.
    firmware: &'a [u8],
    /// Optional AI model bytes. `None` → `ai_model_hash` is all-zeros.
    ai_model: Option<&'a [u8]>,
    /// Caller-supplied baseline event counter.
    event_counter: u64,
}

impl<'a> DiceRoT<'a> {
    /// Creates a new [`DiceRoT`].
    ///
    /// - `cdi`: 32-byte CDI from the previous DICE layer (or hardware UDS).
    /// - `firmware`: bytes of the firmware image to measure.
    /// - `ai_model`: optional AI model bytes to measure.
    /// - `event_counter`: caller-supplied monotonic counter baseline.
    #[must_use]
    pub fn new(
        cdi: [u8; 32],
        firmware: &'a [u8],
        ai_model: Option<&'a [u8]>,
        event_counter: u64,
    ) -> Self {
        Self { cdi, firmware, ai_model, event_counter }
    }
}

impl<'a> RoT for DiceRoT<'a> {
    fn measure(&self) -> Result<Measurements, PqRascvError> {
        // ── 1. FWID = SHA3-256(firmware) ─────────────────────────────────────
        let firmware_hash: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(self.firmware);
            h.finalize().into()
        };

        // ── 2. AI model hash ─────────────────────────────────────────────────
        let ai_model_hash: [u8; 32] = match self.ai_model {
            Some(model) => {
                let mut h = Sha3_256::new();
                h.update(model);
                h.finalize().into()
            }
            None => [0u8; 32],
        };

        // ── 3. Attestation CDI = SHA3-256(CDI ‖ "DICE-attest" ‖ FWID) ───────
        //
        // Follows TCG DICE Architecture §6.2.  Domain-separation via the fixed
        // label prevents length-extension and cross-purpose CDI reuse.
        let cdi_attestation: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(self.cdi);
            h.update(DICE_ATTEST_LABEL);
            h.update(firmware_hash);
            h.finalize().into()
        };

        // ── 4. Populate PCR bank ─────────────────────────────────────────────
        //
        // PCR 0 = attestation CDI (one-way function of CDI + FWID).
        // All other PCRs are left at zero — hardware DICE layers can populate
        // additional PCRs by calling `measure()` on nested `DiceRoT` instances.
        let mut pcrs = PcrBank::default();
        pcrs.0[0] = cdi_attestation;

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

    static FW_A: &[u8] = b"firmware-v1.0.0";
    static FW_B: &[u8] = b"firmware-v1.0.1";
    const CDI: [u8; 32] = [0x42u8; 32];

    #[test]
    fn measure_is_deterministic() {
        let rot = DiceRoT::new(CDI, FW_A, None, 0);
        assert_eq!(rot.measure().unwrap(), rot.measure().unwrap());
    }

    #[test]
    fn firmware_change_changes_hash_and_pcr0() {
        let m_a = DiceRoT::new(CDI, FW_A, None, 0).measure().unwrap();
        let m_b = DiceRoT::new(CDI, FW_B, None, 0).measure().unwrap();

        assert_ne!(m_a.firmware_hash, m_b.firmware_hash,
            "different firmware must produce different firmware_hash");
        assert_ne!(m_a.pcrs.0[0], m_b.pcrs.0[0],
            "different firmware must produce different CDI attestation in PCR 0");
    }

    #[test]
    fn cdi_change_changes_pcr0_but_not_firmware_hash() {
        let cdi_alt = [0xffu8; 32];
        let m_a = DiceRoT::new(CDI, FW_A, None, 0).measure().unwrap();
        let m_b = DiceRoT::new(cdi_alt, FW_A, None, 0).measure().unwrap();

        assert_eq!(m_a.firmware_hash, m_b.firmware_hash,
            "same firmware must produce the same firmware_hash regardless of CDI");
        assert_ne!(m_a.pcrs.0[0], m_b.pcrs.0[0],
            "different CDI must produce different CDI attestation in PCR 0");
    }

    #[test]
    fn pcr0_is_not_zero() {
        let m = DiceRoT::new(CDI, FW_A, None, 0).measure().unwrap();
        assert_ne!(m.pcrs.0[0], [0u8; 32]);
    }

    #[test]
    fn pcr1_through_7_are_zero() {
        let m = DiceRoT::new(CDI, FW_A, None, 0).measure().unwrap();
        for i in 1..8 {
            assert_eq!(m.pcrs.0[i], [0u8; 32], "PCR {i} should be zero for single-layer DICE");
        }
    }

    #[test]
    fn ai_model_hash_zero_when_absent() {
        let m = DiceRoT::new(CDI, FW_A, None, 0).measure().unwrap();
        assert_eq!(m.ai_model_hash, [0u8; 32]);
    }

    #[test]
    fn ai_model_hash_set_when_present() {
        let m = DiceRoT::new(CDI, FW_A, Some(b"model-weights"), 0).measure().unwrap();
        assert_ne!(m.ai_model_hash, [0u8; 32]);
    }

    #[test]
    fn event_counter_propagated() {
        let m = DiceRoT::new(CDI, FW_A, None, 99).measure().unwrap();
        assert_eq!(m.event_counter, 99);
    }
}
