# Sovereign Bitcoin Node Profile

This document outlines the strict platform attestation profile designed for running sovereign Bitcoin nodes.

## Profile Configuration

A sovereign Bitcoin node runs on bare metal or custom virtualized hardware requiring highly secure boot paths. The `sovereign_bitcoin_node_profile()` configures:

- **ID**: `bitcoin-node-sovereign-v1`
- **Vendor**: `Coreboot` (open-source firmware)
- **Class**: `BitcoinNode`
- **Secure Boot**: Enforced (`secure_boot_required: true`)
- **Firmware Generation**: `1`
- **Policy Epoch**: `1`

## Expected PCR Measurements (SHA3-256)

1. `PcrSemantic::Firmware`: `[0x01; 32]` (Coreboot BIOS / Platform Init)
2. `PcrSemantic::Bootloader`: `[0x02; 32]` (Trusted Bootloader)
3. `PcrSemantic::Kernel`: `[0x03; 32]` (Hardened Linux Kernel)
4. `PcrSemantic::Initrd`: `[0x04; 32]` (Minimal ramdisk containing only critical drivers)

Any variation in these values during a production deployment represents a drift that is rejected unless an authorized, versioned baseline upgrade transition is present.
