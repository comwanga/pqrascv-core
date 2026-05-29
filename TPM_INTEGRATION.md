# TPM Integration Guide

This document covers operational setup, PCR policy, hardware assumptions, and
known limitations for the `pqrascv-core` TPM 2.0 backend (`hardware-tpm` feature).

---

## Maturity Statement

| Dimension | Status |
|---|---|
| Architecture | Sound |
| Tested against real TPM hardware | No evidence |
| Tested against swtpm (software TPM) | No evidence |
| Production-validated | No |
| IMA integration | Via `pqrascv-hardware` `live-evidence` (separate) |

**This backend is experimental.** Do not deploy in regulated or high-assurance
environments until integration tests are established against real or simulated hardware.

---

## Requirements

### Linux

```
apt install tpm2-tss tpm2-tools          # Debian/Ubuntu
dnf install tpm2-tss-devel tpm2-tools   # RHEL/Fedora
```

Set the TCTI path before running:

```bash
export TPM2TOOLS_TCTI=device:/dev/tpm0          # real TPM
export TPM2TOOLS_TCTI=swtpm:port=2321           # software TPM simulation
```

### Windows

Not supported. The `tss-esapi-sys` build script explicitly rejects
`(x86_64, windows)`. TPM access on Windows requires a separate integration path.

---

## Cargo Feature

```toml
pqrascv-core = { version = "1.0.0-rc.5", features = ["hardware-tpm"] }
```

The `hardware-tpm` feature is excluded from `docs.rs` builds because it requires
the `tpm2-tss` system library.

---

## PCR Coverage

The backend reads PCRs 0–7 from the TPM SHA-256 bank and normalizes each to
SHA3-256 (`pcrs.digests[i] = SHA3-256(tpm_sha256_pcr[i])`).

| PCR | Standard meaning (UEFI / TCG PC Client) | Notes |
|-----|----------------------------------------|-------|
| 0 | SRTM, BIOS code, Host Platform extensions | Changes on BIOS update |
| 1 | BIOS configuration | |
| 2 | Option ROM code | |
| 3 | Option ROM configuration | |
| 4 | MBR / boot manager code | Changes on OS boot manager update |
| 5 | Boot manager configuration | |
| 6 | State transitions / wake events | |
| 7 | Secure Boot policy (DB / DBX / PK / KEK) | **Requires Secure Boot enabled** |

**PCRs 8–15 are not read.** These cover OS kernel, kernel modules, and the IMA
measurement log. If your threat model requires kernel integrity attestation, use
`pqrascv-hardware` with the `live-evidence` feature.

---

## Secure Boot Requirement (PCR 7)

PCR 7 is only meaningful when Secure Boot is enabled. With Secure Boot disabled:

- PCR 7 contains a TCG-defined placeholder value.
- The PCR cannot attest which keys are authorized or which certificates were checked.
- Policy rules comparing PCR 7 values will match any system with the same placeholder.

For production deployments that require boot chain integrity, enforce Secure Boot
at the firmware level before using PCR 7 in policy decisions.

---

## Firmware Hash — Important Limitation

The `firmware_hash` field in the attestation quote is computed locally by the
prover process (SHA3-256 of the bytes passed to `TpmRoT::new`). It is **not**
derived from or cross-checked against the TPM measurement log or any PCR extend
operation.

This means:

- A compromised OS process could supply different firmware bytes than what
  actually executed, and the TPM would not detect the substitution.
- The TPM PCRs and the firmware hash are independently computed and are not
  cryptographically linked to each other within the quote.

**Mitigation options:**

1. Verify caller-supplied firmware bytes against an IMA log entry or a
   pre-measured reference hash stored in TPM NV memory before calling `TpmRoT::new`.
2. Use `pqrascv-hardware` `live-evidence` to read IMA measurements directly.
3. Enforce PCR-based boot chain attestation separately and tie it to the quote
   via a policy rule.

---

## Event Counter

The event counter in the attestation quote uses `TPM2_PT_AUDIT_COUNTER_0`
(`AuditCounter0`). This counter increments with every audited TPM command in
the current session.

Limitations:

- **Not a boot counter.** It does not reset predictably on reboot.
- **Not strictly monotonic across reboots.** Depending on TPM state, the value
  may reset or wrap.
- **Not suitable for replay detection** on its own. Use the nonce mechanism for
  replay protection; treat the event counter as supplementary evidence only.

---

## swtpm Setup (Development / CI)

For testing without physical hardware:

```bash
# Install swtpm
apt install swtpm swtpm-tools    # Debian/Ubuntu

# Create a state directory and start swtpm
mkdir /tmp/mytpm
swtpm socket --tpmstate dir=/tmp/mytpm \
  --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 \
  --flags not-need-init --tpm2 &

# Configure TCTI
export TPM2TOOLS_TCTI=swtpm:port=2321

# Verify TPM is accessible
tpm2_getrandom 8 | xxd
```

Note: swtpm initializes PCRs to zero. Real-world PCR values from Secure Boot
and firmware measurement will differ substantially.

---

## Known Gaps

| Gap | Impact | Mitigation |
|-----|--------|-----------|
| No integration tests against real TPM | Cannot verify correct PCR reading | Planned — tracked separately |
| No integration tests against swtpm | Cannot verify CI pipeline | Planned — tracked separately |
| Firmware hash not TPM-derived | OS-level compromise can substitute firmware bytes | Validate bytes externally before attestation |
| PCR 8–15 not read | Kernel integrity not attested | Use `live-evidence` feature |
| Windows not supported | Cannot use on Windows servers | Separate integration path required |
| `AuditCounter0` not monotonic across reboots | Event counter not reliable for replay detection | Use nonce mechanism for replay protection |
