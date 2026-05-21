# Measured Boot Validation

## Overview

Hardware evidence alone is insufficient if the software booted on the device is untrusted. Measured Boot ensures that each boot stage securely measures the next stage into the TPM before execution.

The verifier uses `HardwarePolicyEngine` in `pqrascv-hardware/src/policy.rs` to validate the completeness of the boot chain based on semantic identifiers, decoupling policy logic from specific raw PCR indices.

## Required Policies

When utilizing the `RequireMeasuredBoot` preset, the verifier enforces that both `Firmware` and `Bootloader` semantics are present.
Granular control is available using individual requirements:
- `RequireFirmwareMeasurement`: Enforces the presence of the Core Root of Trust for Measurement (CRTM) firmware.
- `RequireBootloaderMeasurement`: Ensures the initial bootloader logic is captured.
- `RequireKernelMeasurement`: Requires the OS Kernel image digest to exist.

## Semantic Indexing

Measurements strictly map semantic identifiers (`PcrSemantic`) to canonical PCR slots (e.g., Firmware -> Slot 0, Bootloader -> Slot 1) to prevent "slot-shifting" attacks where an attacker might mimic a measurement in an unused register.
