//! Boot Chain Evidence
//!
//! Models the layered trust evaluation of the boot sequence, moving away
//! from opaque PCR values to explicitly named semantic trust boundaries.

use crate::digest::TypedDigest;
use crate::secure_boot::SecureBootEvidence;

/// Evidence of the explicit boot chain sequence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BootChainEvidence {
    /// Trust measurement of the firmware/BIOS (typically PCR 0).
    pub firmware: TypedDigest,
    /// Trust measurement of the bootloader (typically PCR 4 / 1).
    pub bootloader: TypedDigest,
    /// Trust measurement of the OS kernel.
    pub kernel: TypedDigest,
    /// Trust measurement of the initial ramdisk (initrd/initramfs), if present.
    pub initrd: Option<TypedDigest>,
    /// Secure Boot evidence providing constraints on the bootloader/kernel signatures.
    pub secure_boot: SecureBootEvidence,
}
