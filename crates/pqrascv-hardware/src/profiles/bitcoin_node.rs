//! Platform profile for a sovereign Bitcoin Node.

use crate::baseline::ExpectedPcr;
use crate::digest::{DigestAlgorithm, TypedDigest};
use crate::pcr::PcrSemantic;
use crate::platform_profiles::{PlatformClass, PlatformProfile, PlatformVendor};
use alloc::string::ToString;
use alloc::vec;

/// Returns the platform profile for a sovereign Bitcoin Node.
///
/// This profile enforces:
/// - Secure Boot enabled
/// - Coreboot firmware
/// - Verified bootloader and kernel PCRs
#[must_use]
pub fn sovereign_bitcoin_node_profile() -> PlatformProfile {
    PlatformProfile {
        profile_id: "bitcoin-node-sovereign-v1".to_string(),
        vendor: PlatformVendor::Coreboot,
        platform_class: PlatformClass::BitcoinNode,
        secure_boot_required: true,
        expected_pcrs: vec![
            ExpectedPcr {
                semantic: PcrSemantic::Firmware,
                expected_digest: TypedDigest::new(DigestAlgorithm::Sha3_256, [0x01; 32]),
            },
            ExpectedPcr {
                semantic: PcrSemantic::Bootloader,
                expected_digest: TypedDigest::new(DigestAlgorithm::Sha3_256, [0x02; 32]),
            },
            ExpectedPcr {
                semantic: PcrSemantic::Kernel,
                expected_digest: TypedDigest::new(DigestAlgorithm::Sha3_256, [0x03; 32]),
            },
            ExpectedPcr {
                semantic: PcrSemantic::Initrd,
                expected_digest: TypedDigest::new(DigestAlgorithm::Sha3_256, [0x04; 32]),
            },
        ],
        firmware_generation: 1,
        policy_epoch: 1,
    }
}
