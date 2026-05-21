# TPM PCR Specification

## Canonical Slot Mapping

All PQ-RASCV backends MUST use this mapping. Policy rules operate on
`PcrSemantic` values, not raw indices, making them portable across backends.

| Slot | `PcrSemantic` | What is measured | Who measures it |
|------|--------------|-----------------|-----------------|
| 0 | `Firmware` | Boot firmware / UEFI / ROM | TPM (before OS) |
| 1 | `Bootloader` | First-stage bootloader | Firmware |
| 2 | `Kernel` | OS kernel image | Bootloader |
| 3 | `Initrd` | Initial RAM disk | Bootloader |
| 4 | `Config` | Boot config / device tree | Bootloader |
| 5 | `SecureWorld` | TrustZone / OP-TEE image | Firmware |
| 6 | `Application` | Application measurement | Application |
| 7 | `Policy` | Platform security policy | Firmware/OS |

## Algorithm Normalization

TPM 2.0 hardware stores PCRs as SHA-256 digests. PQ-RASCV normalizes all
PCR values to SHA3-256 before policy evaluation:

```
stored_value = SHA3-256( raw_tpm_sha256_pcr )
```

This is implemented in `TypedDigest::normalize_to_sha3_256()`. The
`TypedPcrBank::all_normalized()` method verifies all slots are normalized
before the policy engine runs.

**Policy rules MUST NOT compare raw TPM SHA-256 values.** Always use
normalized SHA3-256 values.

## Measured Boot Minimum Requirements

`HardwarePolicyRule::RequireMeasuredBoot` requires:
- `PcrSemantic::Firmware` (slot 0) is present and non-zero
- `PcrSemantic::Bootloader` (slot 1) is present and non-zero

A device that has not measured its firmware and bootloader cannot be trusted,
regardless of what other PCRs contain.

## PCR Extend Semantics

TPM PCRs use an extend operation, not a simple write:

```
PCR[n] = SHA-256( PCR[n] || new_measurement )
```

This means PCR values are cumulative — they reflect the entire history of
measurements in that slot. A verifier checking `PCR[2] == expected_kernel`
is checking that the kernel was measured after a specific firmware and
bootloader sequence.

## TPM Clock Evidence

`TpmClockInfo` provides hardware-backed time evidence:

- `clock_ms`: milliseconds since last TPM clear (monotonic)
- `reset_count`: power cycle counter
- `restart_count`: restart-without-reset counter
- `safe`: `true` if the clock has been set since last clear

The `safe` flag MUST be `true` for the clock to be trusted. A `false` value
indicates the TPM was reset without a full clear, which could indicate tampering.

## AK/EK Trust Chain

```
TPM Manufacturer Root CA
  └── Manufacturer Intermediate CA
        └── EK Certificate (burned into TPM at manufacturing)
              └── EK Public Key (proves TPM is genuine hardware)
                    └── AK Certificate (issued by privacy CA)
                          └── AK Public Key (signs attestation quotes)
```

The verifier MUST validate the EK certificate chain to confirm the TPM is
genuine hardware before trusting the AK-signed quote.
