# Measured Boot

## What is Measured Boot?

Measured boot is a process where each stage of the boot sequence measures
(hashes) the next stage before executing it, and records that measurement
in a TPM PCR. The result is a tamper-evident log of everything that ran
during boot.

## Boot Sequence

```
Power on
  └── CPU reset vector → TPM initializes
        └── Firmware (UEFI/ROM)
              ├── Measures itself → PCR[0]
              ├── Measures bootloader → PCR[1]
              └── Executes bootloader
                    ├── Measures kernel → PCR[2]
                    ├── Measures initrd → PCR[3]
                    ├── Measures config → PCR[4]
                    └── Executes kernel
                          └── Application
                                └── TPM2_Quote(nonce) → AttestationQuote
```

## Policy Enforcement

`HardwarePolicyRule::RequireMeasuredBoot` enforces that:
1. `PcrSemantic::Firmware` is present in the PCR bank
2. `PcrSemantic::Bootloader` is present in the PCR bank

For stricter enforcement, add explicit PCR value rules:

```rust
HardwarePolicyRule::RequirePcrValue {
    semantic: PcrSemantic::Kernel,
    expected: KNOWN_GOOD_KERNEL_HASH,
}
```

## Why Software Measurement is Insufficient

A software process that measures itself:
1. Runs AFTER the OS has loaded
2. Can be replaced by an attacker
3. Can pass any bytes to the hash function
4. Produces a valid signature over attacker-chosen data

Hardware measurement (TPM PCR extend) happens BEFORE the OS loads and
CANNOT be modified by software running on the CPU.

---

# Hardware Backends

## TPM 2.0

**Security boundary**: TPM is a separate chip with its own firmware.
Measurements occur before the OS loads.

**Evidence**: `TpmQuoteEvidence` — contains the raw `TPMS_ATTEST` structure,
AK signature, PCR bank, and clock info.

**Nonce binding**: The nonce is passed as `qualifying_data` to `TPM2_Quote`.
The TPM includes it in the signed quote blob, binding the quote to the
specific challenge.

**Counter**: TPM audit counter (`TPM2_PT_AUDIT_COUNTER_0`) — hardware-backed,
monotonically increasing.

## DICE

**Security boundary**: Hardware UDS (Unique Device Secret) stored in eFuse
or OTP. The CDI is derived before any mutable code runs.

**Evidence**: `DiceEvidence` — contains the attestation CDI and layered
firmware measurements.

**Nonce binding**: DICE does not natively support nonce binding. The nonce
must be incorporated at the quote layer (ML-DSA-65 signature over quote body
that includes the nonce).

**Counter**: Not supported. `CounterEvidence::Unsupported`.

## Intel TDX (Phase 4)

**Security boundary**: CPU microcode. The TD (Trust Domain) is isolated from
the VMM by hardware.

**Evidence**: `TdxEvidence` — raw TDX Quote from Intel DCAP library.

**Verification**: Requires Intel's PCK certificate hierarchy and DCAP library.
Not implemented in Phase 2.5 — placeholder types only.

## AMD SEV-SNP (Phase 4)

**Security boundary**: AMD PSP (Platform Security Processor) firmware.

**Evidence**: `SevSnpEvidence` — raw SNP Attestation Report from AMD PSP.

**Verification**: Requires AMD's ARK/ASK certificate chain and `snpguest` tool.
Not implemented in Phase 2.5 — placeholder types only.

## TestOnly (unsafe-test-backend feature)

**Security boundary**: None. This backend provides no attestation security.

**Usage**: Unit tests and CI pipelines without hardware.

**Production**: Impossible to use. `HardwarePolicyEngine::hardware_production()`
rejects it. The `unsafe-test-backend` feature must not be enabled in
production builds.
