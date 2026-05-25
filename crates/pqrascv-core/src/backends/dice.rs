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
/// assert_ne!(m.pcrs.digests[0], [0u8; 32], "PCR 0 must contain CDI attestation");
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
        Self {
            cdi,
            firmware,
            ai_model,
            event_counter,
        }
    }
}

impl RoT for DiceRoT<'_> {
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
        // Mixing in the fixed "DICE-attest" label keeps this CDI purpose-specific
        // and prevents length-extension attacks across different CDI uses.
        let cdi_attestation: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(self.cdi);
            h.update(DICE_ATTEST_LABEL);
            h.update(firmware_hash);
            h.finalize().into()
        };

        // ── 4. Populate PCR bank ─────────────────────────────────────────────
        //
        // PCR 0 holds the attestation CDI. The rest stay zero for now —
        let mut pcrs = PcrBank::default();
        pcrs.digests[0] = cdi_attestation;

        Ok(Measurements {
            pcrs,
            firmware_hash,
            ai_model_hash,
            event_counter: self.event_counter,
        })
    }
}

/// A single firmware layer in a DICE CDI chain.
pub struct DiceLayer<'a> {
    /// Bytes of the firmware image at this layer.
    pub firmware: &'a [u8],
}

/// Multi-layer DICE Root-of-Trust (TCG DICE Architecture §6.2, compound device).
///
/// Derives a chain of Compound Device Identifiers (CDIs) from a root secret (`uds`)
/// through ordered firmware layers. The final CDI is placed in PCR 0; the
/// previous `PCR_COUNT-1` intermediate CDIs in PCR 1..(PCR_COUNT-1).
///
/// Security property: changing any layer's firmware changes every CDI derived
/// after it, so a verifier can detect firmware substitution at any layer.
///
/// # Layer ordering
///
/// `layers[0]` is the lowest layer (boot ROM / UDS consumer).
/// `layers[last]` is the topmost layer (the firmware being attested).
/// `firmware_hash` in `Measurements` is `SHA3-256(layers[last].firmware)`.
pub struct CompoundDiceRoT<'a> {
    uds: [u8; 32],
    layers: &'a [DiceLayer<'a>],
    ai_model: Option<&'a [u8]>,
    event_counter: u64,
}

impl<'a> CompoundDiceRoT<'a> {
    #[must_use]
    pub fn new(
        uds: [u8; 32],
        layers: &'a [DiceLayer<'a>],
        ai_model: Option<&'a [u8]>,
        event_counter: u64,
    ) -> Self {
        Self {
            uds,
            layers,
            ai_model,
            event_counter,
        }
    }
}

impl RoT for CompoundDiceRoT<'_> {
    fn measure(&self) -> Result<Measurements, PqRascvError> {
        use crate::measurement::PCR_COUNT;

        if self.layers.is_empty() {
            return Err(PqRascvError::MeasurementFailed);
        }

        let n = self.layers.len();
        let mut prev_cdi = self.uds;
        let mut pcrs = PcrBank::default();

        for (i, layer) in self.layers.iter().enumerate() {
            let fwid: [u8; 32] = Sha3_256::digest(layer.firmware).into();
            let cdi: [u8; 32] = {
                let mut h = Sha3_256::new();
                h.update(prev_cdi);
                h.update(DICE_ATTEST_LABEL);
                h.update(fwid);
                h.finalize().into()
            };
            let pcr_slot = n - 1 - i;
            if pcr_slot < PCR_COUNT {
                pcrs.digests[pcr_slot] = cdi;
            }
            prev_cdi = cdi;
        }

        let firmware_hash: [u8; 32] = Sha3_256::digest(self.layers[n - 1].firmware).into();

        let ai_model_hash: [u8; 32] = match self.ai_model {
            Some(m) => Sha3_256::digest(m).into(),
            None => [0u8; 32],
        };

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

        assert_ne!(
            m_a.firmware_hash, m_b.firmware_hash,
            "different firmware must produce different firmware_hash"
        );
        assert_ne!(
            m_a.pcrs.digests[0], m_b.pcrs.digests[0],
            "different firmware must produce different CDI attestation in PCR 0"
        );
    }

    #[test]
    fn cdi_change_changes_pcr0_but_not_firmware_hash() {
        let cdi_alt = [0xffu8; 32];
        let m_a = DiceRoT::new(CDI, FW_A, None, 0).measure().unwrap();
        let m_b = DiceRoT::new(cdi_alt, FW_A, None, 0).measure().unwrap();

        assert_eq!(
            m_a.firmware_hash, m_b.firmware_hash,
            "same firmware must produce the same firmware_hash regardless of CDI"
        );
        assert_ne!(
            m_a.pcrs.digests[0], m_b.pcrs.digests[0],
            "different CDI must produce different CDI attestation in PCR 0"
        );
    }

    #[test]
    fn pcr0_is_not_zero() {
        let m = DiceRoT::new(CDI, FW_A, None, 0).measure().unwrap();
        assert_ne!(m.pcrs.digests[0], [0u8; 32]);
    }

    #[test]
    fn pcr1_through_7_are_zero() {
        let m = DiceRoT::new(CDI, FW_A, None, 0).measure().unwrap();
        for i in 1..8 {
            assert_eq!(
                m.pcrs.digests[i], [0u8; 32],
                "PCR {i} should be zero for single-layer DICE"
            );
        }
    }

    #[test]
    fn ai_model_hash_zero_when_absent() {
        let m = DiceRoT::new(CDI, FW_A, None, 0).measure().unwrap();
        assert_eq!(m.ai_model_hash, [0u8; 32]);
    }

    #[test]
    fn ai_model_hash_set_when_present() {
        let m = DiceRoT::new(CDI, FW_A, Some(b"model-weights"), 0)
            .measure()
            .unwrap();
        assert_ne!(m.ai_model_hash, [0u8; 32]);
    }

    #[test]
    fn event_counter_propagated() {
        let m = DiceRoT::new(CDI, FW_A, None, 99).measure().unwrap();
        assert_eq!(m.event_counter, 99);
    }

    #[test]
    fn pcr_algorithm_is_sha3_256() {
        use crate::measurement::PcrAlgorithm;
        let m = DiceRoT::new(CDI, FW_A, None, 0).measure().unwrap();
        assert_eq!(m.pcrs.algorithm, PcrAlgorithm::Sha3_256);
    }

    // ── CompoundDiceRoT tests ─────────────────────────────────────────────

    const UDS: [u8; 32] = [0x11u8; 32];
    static BL: &[u8] = b"bootloader-v1";
    static FW: &[u8] = b"firmware-v1.0.0";

    #[test]
    fn compound_empty_layers_returns_error() {
        let rot = CompoundDiceRoT::new(UDS, &[], None, 0);
        assert_eq!(rot.measure().unwrap_err(), PqRascvError::MeasurementFailed);
    }

    #[test]
    fn compound_single_layer_matches_dice_rot() {
        let single = [DiceLayer { firmware: FW }];
        let compound = CompoundDiceRoT::new(UDS, &single, None, 0);
        let original = DiceRoT::new(UDS, FW, None, 0);
        let mc = compound.measure().unwrap();
        let mo = original.measure().unwrap();
        assert_eq!(
            mc.pcrs.digests[0], mo.pcrs.digests[0],
            "PCR 0 must match DiceRoT"
        );
        assert_eq!(mc.firmware_hash, mo.firmware_hash);
    }

    #[test]
    fn compound_firmware_hash_is_topmost_layer() {
        let layers = [DiceLayer { firmware: BL }, DiceLayer { firmware: FW }];
        let m = CompoundDiceRoT::new(UDS, &layers, None, 0)
            .measure()
            .unwrap();
        let expected: [u8; 32] = Sha3_256::digest(FW).into();
        assert_eq!(
            m.firmware_hash, expected,
            "firmware_hash must be hash of topmost layer"
        );
    }

    #[test]
    fn compound_pcr0_is_topmost_cdi() {
        let layers = [DiceLayer { firmware: BL }, DiceLayer { firmware: FW }];
        let m = CompoundDiceRoT::new(UDS, &layers, None, 0)
            .measure()
            .unwrap();
        assert_ne!(m.pcrs.digests[0], [0u8; 32]);
        assert_ne!(m.pcrs.digests[1], [0u8; 32]);
        assert_eq!(
            m.pcrs.digests[2], [0u8; 32],
            "PCR 2 must be zero for 2-layer chain"
        );
    }

    #[test]
    fn compound_lower_layer_change_propagates_to_all_cdis() {
        let layers_a = [DiceLayer { firmware: BL }, DiceLayer { firmware: FW }];
        let layers_b = [
            DiceLayer {
                firmware: b"bootloader-v2",
            },
            DiceLayer { firmware: FW },
        ];
        let m_a = CompoundDiceRoT::new(UDS, &layers_a, None, 0)
            .measure()
            .unwrap();
        let m_b = CompoundDiceRoT::new(UDS, &layers_b, None, 0)
            .measure()
            .unwrap();
        assert_ne!(
            m_a.pcrs.digests[0], m_b.pcrs.digests[0],
            "changing a lower layer must change the topmost CDI"
        );
        assert_ne!(
            m_a.pcrs.digests[1], m_b.pcrs.digests[1],
            "changing layer 0 must change its own CDI (PCR 1)"
        );
    }

    #[test]
    fn compound_upper_layer_change_does_not_change_lower_cdis() {
        let layers_a = [DiceLayer { firmware: BL }, DiceLayer { firmware: FW }];
        let layers_b = [
            DiceLayer { firmware: BL },
            DiceLayer {
                firmware: b"firmware-v2.0.0",
            },
        ];
        let m_a = CompoundDiceRoT::new(UDS, &layers_a, None, 0)
            .measure()
            .unwrap();
        let m_b = CompoundDiceRoT::new(UDS, &layers_b, None, 0)
            .measure()
            .unwrap();
        assert_ne!(
            m_a.pcrs.digests[0], m_b.pcrs.digests[0],
            "changing the topmost layer must change PCR 0"
        );
        assert_eq!(
            m_a.pcrs.digests[1], m_b.pcrs.digests[1],
            "changing the topmost layer must NOT change PCR 1 (lower CDI)"
        );
    }

    #[test]
    fn compound_is_deterministic() {
        let layers = [DiceLayer { firmware: BL }, DiceLayer { firmware: FW }];
        let rot = CompoundDiceRoT::new(UDS, &layers, None, 0);
        assert_eq!(rot.measure().unwrap(), rot.measure().unwrap());
    }

    #[test]
    fn compound_more_than_pcr_count_layers_uses_topmost_n() {
        use crate::measurement::PCR_COUNT;
        let all_fw: &[&[u8]] = &[
            b"l0", b"l1", b"l2", b"l3", b"l4", b"l5", b"l6", b"l7", b"l8", b"l9",
        ];
        let layers: std::vec::Vec<DiceLayer<'_>> =
            all_fw.iter().map(|fw| DiceLayer { firmware: fw }).collect();
        let m = CompoundDiceRoT::new(UDS, &layers, None, 0)
            .measure()
            .unwrap();
        assert_ne!(m.pcrs.digests[0], [0u8; 32]);
        for slot in 0..PCR_COUNT {
            assert_ne!(
                m.pcrs.digests[slot], [0u8; 32],
                "PCR {slot} must be non-zero"
            );
        }
    }
}
