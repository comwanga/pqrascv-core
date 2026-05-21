# Platform Profiles

Platform profiles represent a key semantic transition in PQ-RASCV v2 from checking raw, opaque PCR hash values to evaluating structural, platform-aware trust configurations.

## Architecture

Instead of comparing every PCR value directly in a flat policy, the verifier matches incoming attestation evidence against a `PlatformProfile` definition specific to a platform class (e.g., Linux Server, Sovereign Bitcoin Node).

```text
       Incoming Evidence
       (PCRs, Secure Boot, etc.)
                │
                ▼
      ┌──────────────────┐
      │  PlatformProfile │
      │  Verification    │◄────── DriftPolicyMode (Learning/Audit/Enforcing)
      └─────────┬────────┘
                │
        ┌───────┴───────┐
        ▼               ▼
     [Success]      [Failure]
               (DecisionReason)
```

## Key Structures

- `PlatformClass`: High-level classification of the target system (e.g., `LinuxServer`, `BitcoinNode`, `CloudVm`).
- `PlatformVendor`: Hardware or hypervisor vendor (e.g., `Intel`, `AMD`, `Coreboot`, `Qemu`).
- `PlatformProfile`: Explicit expectations, including:
  - `secure_boot_required`: Requirement for Secure Boot status.
  - `expected_pcrs`: Pre-calculated PCR measurements for each boot stage.
  - `firmware_generation`: Numeric identifier to prevent older firmware revision rollbacks.
  - `policy_epoch`: Monotonically increasing epoch number.

## Verification Decisions

When a platform profile matches but validation fails, the verifier yields a `VerificationDecisionReason`:
- `SecureBootDisabled`: Required Secure Boot state is missing.
- `BaselineRollbackDetected`: Rollback detected in baseline versioning or firmware generation.
- `UnknownFirmwareGeneration`: Unrecognized firmware version.
- `CriticalDriftDetected`: Severe, unauthorized deviation from the baseline.
- `MissingKernelMeasurement`: No kernel measurement found in PCR bank.
- `UnsupportedVendor`: Hypervisor/hardware vendor rejected.
- `InvalidPlatformProfile`: Malformed profile schema.
