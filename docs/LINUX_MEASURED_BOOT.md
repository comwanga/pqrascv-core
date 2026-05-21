# Linux Measured Boot Semantics

This document describes how Linux boot components (Shim, GRUB, and Unified Kernel Images) map to TPM PCRs and are represented in the policy engine.

## TPM PCR Slot Mappings

In standard Linux boot flows, measurements are extended to the TPM:
- **PCR 0**: UEFI Firmware & Platform Config.
- **PCR 4**: Bootloader binary (e.g., GRUB, systemd-boot) and UEFI drivers.
- **PCR 5**: GPT Partition Table & Partition Config.
- **PCR 8**: Kernel Command Line parameters (measured by GRUB).
- **PCR 9**: Kernel Image and Initrd (measured by GRUB).

## Unified Kernel Images (UKI)

When using a Unified Kernel Image:
- The stub, kernel, command line, and initrd are bundled into a single PE executable.
- The UKI is measured by UEFI as a single unit in PCR 4.
- In PQ-RASCV v2, these are mapped to semantic types:
  - `PcrSemantic::Firmware` (PCR 0/12)
  - `PcrSemantic::Bootloader` (PCR 4)
  - `PcrSemantic::Kernel` (PCR 4 or 9)
  - `PcrSemantic::Initrd` (PCR 9)
