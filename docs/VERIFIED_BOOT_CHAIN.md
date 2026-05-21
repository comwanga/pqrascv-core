# Verified Boot Chain Semantics

Rather than relying on opaque PCR slot arrays, the verifier models the boot chain explicitly using typed digest boundaries.

## Boot Chain Evidence

The `BootChainEvidence` struct exposes:
1. `firmware`: Hash representing UEFI/Coreboot/BIOS state.
2. `bootloader`: Hash of the bootloader binary (shim, GRUB, systemd-boot).
3. `kernel`: Hash of the operating system kernel image.
4. `initrd`: Optional hash of the initial ramdisk configuration.
5. `secure_boot`: Embedded `SecureBootEvidence`.

## Semantic Matching

In policy evaluation:
- `HardwarePolicyRule::RequireBootChain(expected_boot_chain)` ensures that the cryptographic measurements of the active boot components align exactly with known good configurations.
- Conflict detection flags configurations where two rules require contradictory boot chain hashes.
