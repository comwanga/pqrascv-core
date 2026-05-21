//! PCR semantic specification — canonical slot meanings and typed measurements.
//!
//! # Problem
//!
//! In v1, PCR slots were raw indices with no enforced meaning. A policy rule
//! checking "PCR 0 must equal X" was fragile: different backends could put
//! different things in slot 0, and the verifier had no way to know what it
//! was actually checking.
//!
//! # Solution
//!
//! Every PCR measurement carries a [`PcrSemantic`] that declares what was
//! measured. The verifier's policy rules operate on semantics, not indices:
//!
//! ```text
//! PolicyRule::RequirePcrSemantic { semantic: PcrSemantic::Kernel, digest: expected }
//! ```
//!
//! This makes policy rules portable across backends and resistant to slot
//! reassignment attacks.
//!
//! # Canonical Slot Mapping
//!
//! The mapping from [`PcrSemantic`] to slot index is defined by
//! [`PcrSemantic::canonical_slot`]. All backends MUST use this mapping.
//! Deviations must be documented and justified.
//!
//! | Slot | Semantic              | What is measured                          |
//! |------|-----------------------|-------------------------------------------|
//! | 0    | `Firmware`            | Boot firmware / UEFI / ROM                |
//! | 1    | `Bootloader`          | First-stage bootloader (e.g. U-Boot)      |
//! | 2    | `Kernel`              | OS kernel image                           |
//! | 3    | `Initrd`              | Initial RAM disk / initramfs              |
//! | 4    | `Config`              | Boot configuration / device tree          |
//! | 5    | `SecureWorld`         | TrustZone / OP-TEE / secure enclave image |
//! | 6    | `Application`         | Application-layer measurement             |
//! | 7    | `Policy`              | Platform policy / security configuration  |

extern crate alloc;
use alloc::vec::Vec;

use crate::digest::TypedDigest;

// ── PcrSemantic ───────────────────────────────────────────────────────────

/// The semantic meaning of a PCR slot measurement.
///
/// Backends MUST use [`PcrSemantic::canonical_slot`] to determine which
/// slot index to write. Policy rules MUST use semantics, not raw indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PcrSemantic {
    /// Boot firmware / UEFI / ROM image. Measured before any mutable code runs.
    /// This is the hardware root of the measured boot chain.
    Firmware,
    /// First-stage bootloader (e.g. U-Boot, GRUB stage 1).
    Bootloader,
    /// OS kernel image.
    Kernel,
    /// Initial RAM disk / initramfs.
    Initrd,
    /// Boot configuration, device tree, or kernel command line.
    Config,
    /// Secure-world image (`TrustZone`, OP-TEE, Intel TXT ACM).
    SecureWorld,
    /// Application-layer measurement (device-specific use).
    Application,
    /// Platform security policy or configuration digest.
    Policy,
}

impl PcrSemantic {
    /// Returns the canonical PCR slot index for this semantic.
    ///
    /// All backends MUST use this mapping. The verifier uses it to locate
    /// the correct slot when evaluating semantic-based policy rules.
    #[must_use]
    pub const fn canonical_slot(self) -> usize {
        match self {
            Self::Firmware => 0,
            Self::Bootloader => 1,
            Self::Kernel => 2,
            Self::Initrd => 3,
            Self::Config => 4,
            Self::SecureWorld => 5,
            Self::Application => 6,
            Self::Policy => 7,
        }
    }

    /// Returns a human-readable description of what this slot measures.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Firmware => "boot firmware / UEFI / ROM",
            Self::Bootloader => "first-stage bootloader",
            Self::Kernel => "OS kernel image",
            Self::Initrd => "initial RAM disk / initramfs",
            Self::Config => "boot configuration / device tree",
            Self::SecureWorld => "secure-world / TrustZone image",
            Self::Application => "application-layer measurement",
            Self::Policy => "platform security policy",
        }
    }

    /// Resolves a raw slot index back to its canonical semantic.
    ///
    /// Returns `None` for indices ≥ 8 (out of range).
    #[must_use]
    pub const fn from_slot(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Firmware),
            1 => Some(Self::Bootloader),
            2 => Some(Self::Kernel),
            3 => Some(Self::Initrd),
            4 => Some(Self::Config),
            5 => Some(Self::SecureWorld),
            6 => Some(Self::Application),
            7 => Some(Self::Policy),
            _ => None,
        }
    }
}

// ── PcrMeasurement ────────────────────────────────────────────────────────

/// A single typed PCR measurement: slot index + semantic + digest.
///
/// The `semantic` field is the authoritative description of what was measured.
/// The `index` field is the hardware slot number (for cross-referencing with
/// raw TPM output). The `digest` carries the algorithm explicitly.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PcrMeasurement {
    /// Hardware PCR slot index (0–7).
    pub index: u8,
    /// Semantic meaning of this slot.
    pub semantic: PcrSemantic,
    /// The measured digest (algorithm-tagged).
    pub digest: TypedDigest,
}

impl PcrMeasurement {
    /// Constructs a measurement, verifying that `index` matches the canonical
    /// slot for `semantic`.
    ///
    /// # Errors
    ///
    /// Returns `Err(SlotSemanticMismatch)` if `index` does not equal
    /// `semantic.canonical_slot()`. This prevents silent slot reassignment.
    pub fn new(
        index: u8,
        semantic: PcrSemantic,
        digest: TypedDigest,
    ) -> Result<Self, SlotSemanticMismatch> {
        if usize::from(index) != semantic.canonical_slot() {
            return Err(SlotSemanticMismatch {
                index,
                semantic,
                expected_index: u8::try_from(semantic.canonical_slot()).unwrap_or(0),
            });
        }
        Ok(Self {
            index,
            semantic,
            digest,
        })
    }

    /// Constructs a measurement without checking slot/semantic consistency.
    ///
    /// Use only when the backend has a documented reason to deviate from the
    /// canonical mapping (e.g. a TPM that pre-assigns slots differently).
    /// The deviation must be noted in the backend's documentation.
    #[must_use]
    pub fn new_unchecked(index: u8, semantic: PcrSemantic, digest: TypedDigest) -> Self {
        Self {
            index,
            semantic,
            digest,
        }
    }

    /// Returns `true` if the digest uses the canonical SHA3-256 algorithm.
    #[must_use]
    pub fn is_normalized(&self) -> bool {
        self.digest.is_canonical()
    }
}

/// Error returned when a PCR slot index does not match the canonical semantic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotSemanticMismatch {
    /// The slot index that was provided.
    pub index: u8,
    /// The semantic that was provided.
    pub semantic: PcrSemantic,
    /// The slot index that the semantic requires.
    pub expected_index: u8,
}

// ── PcrBank ───────────────────────────────────────────────────────────────

/// A typed PCR bank: a collection of [`PcrMeasurement`] values.
///
/// Unlike the v1 `PcrBank` (which was a raw `[[u8;32]; 8]`), this type
/// carries full semantic and algorithm information for every slot.
///
/// Slots that were not measured are absent from `measurements` — there is
/// no "zero means unmeasured" ambiguity.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TypedPcrBank {
    /// The measured slots. May be a subset of all 8 slots.
    pub measurements: Vec<PcrMeasurement>,
}

impl TypedPcrBank {
    /// Creates an empty bank.
    #[must_use]
    pub fn new() -> Self {
        Self {
            measurements: Vec::new(),
        }
    }

    /// Adds a measurement to the bank.
    pub fn push(&mut self, m: PcrMeasurement) {
        self.measurements.push(m);
    }

    /// Looks up the measurement for a given semantic.
    ///
    /// Returns `None` if that semantic was not measured.
    #[must_use]
    pub fn get(&self, semantic: PcrSemantic) -> Option<&PcrMeasurement> {
        self.measurements.iter().find(|m| m.semantic == semantic)
    }

    /// Looks up the measurement for a raw slot index.
    #[must_use]
    pub fn get_by_index(&self, index: u8) -> Option<&PcrMeasurement> {
        self.measurements.iter().find(|m| m.index == index)
    }

    /// Returns `true` if all present measurements use the canonical algorithm.
    #[must_use]
    pub fn all_normalized(&self) -> bool {
        self.measurements.iter().all(PcrMeasurement::is_normalized)
    }

    /// Returns the number of measured slots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.measurements.len()
    }

    /// Returns `true` if no slots have been measured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.measurements.is_empty()
    }
}

impl Default for TypedPcrBank {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::{DigestAlgorithm, TypedDigest};

    fn sha3_digest(val: u8) -> TypedDigest {
        TypedDigest::new(DigestAlgorithm::Sha3_256, [val; 32])
    }

    #[test]
    fn canonical_slot_mapping_is_stable() {
        assert_eq!(PcrSemantic::Firmware.canonical_slot(), 0);
        assert_eq!(PcrSemantic::Bootloader.canonical_slot(), 1);
        assert_eq!(PcrSemantic::Kernel.canonical_slot(), 2);
        assert_eq!(PcrSemantic::Initrd.canonical_slot(), 3);
        assert_eq!(PcrSemantic::Config.canonical_slot(), 4);
        assert_eq!(PcrSemantic::SecureWorld.canonical_slot(), 5);
        assert_eq!(PcrSemantic::Application.canonical_slot(), 6);
        assert_eq!(PcrSemantic::Policy.canonical_slot(), 7);
    }

    #[test]
    fn from_slot_roundtrips() {
        for i in 0..8usize {
            let sem = PcrSemantic::from_slot(i).unwrap();
            assert_eq!(sem.canonical_slot(), i);
        }
        assert!(PcrSemantic::from_slot(8).is_none());
    }

    #[test]
    fn pcr_measurement_rejects_wrong_slot() {
        let err = PcrMeasurement::new(1, PcrSemantic::Firmware, sha3_digest(0)).unwrap_err();
        assert_eq!(err.index, 1);
        assert_eq!(err.expected_index, 0);
    }

    #[test]
    fn pcr_measurement_accepts_correct_slot() {
        let m = PcrMeasurement::new(0, PcrSemantic::Firmware, sha3_digest(0xab)).unwrap();
        assert_eq!(m.index, 0);
        assert_eq!(m.semantic, PcrSemantic::Firmware);
    }

    #[test]
    fn typed_pcr_bank_lookup_by_semantic() {
        let mut bank = TypedPcrBank::new();
        bank.push(PcrMeasurement::new(0, PcrSemantic::Firmware, sha3_digest(0x01)).unwrap());
        bank.push(PcrMeasurement::new(2, PcrSemantic::Kernel, sha3_digest(0x02)).unwrap());

        assert!(bank.get(PcrSemantic::Firmware).is_some());
        assert!(bank.get(PcrSemantic::Kernel).is_some());
        assert!(bank.get(PcrSemantic::Bootloader).is_none());
    }

    #[test]
    fn all_normalized_requires_sha3_256() {
        let mut bank = TypedPcrBank::new();
        bank.push(PcrMeasurement::new(0, PcrSemantic::Firmware, sha3_digest(0x01)).unwrap());
        assert!(bank.all_normalized());

        bank.push(PcrMeasurement::new_unchecked(
            1,
            PcrSemantic::Bootloader,
            TypedDigest::new(DigestAlgorithm::Sha256, [0x02; 32]),
        ));
        assert!(!bank.all_normalized());
    }
}
