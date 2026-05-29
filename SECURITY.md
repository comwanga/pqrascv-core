# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.0-rc.x (latest) | ✅ |
| < 1.0.0-rc.3 | ❌ |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues by emailing **mwanga02717@gmail.com** with the subject line:
`[SECURITY] pqrascv-core — <brief description>`

Please include:

1. **Description** — What the vulnerability is and which component it affects.
2. **Reproduction steps** — Minimal code or command sequence to reproduce.
3. **Impact** — What an attacker could achieve (authentication bypass, key recovery, panic, etc.).
4. **Affected versions** — Which version(s) you tested against.
5. **Suggested fix** (optional) — If you have a proposed patch, attach it.

## Response Timeline

| Stage | Target |
|-------|--------|
| Initial acknowledgement | 48 hours |
| Severity assessment | 5 business days |
| Patch availability | 14 days (critical) / 30 days (high) |
| Public disclosure | Coordinated with reporter |

We follow [coordinated disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html).
Reporters who follow this policy will be credited in the release notes unless they prefer anonymity.

## Scope

Vulnerabilities in scope:

- Memory safety in `pqrascv-core`, `pqrascv-verifier`, `pqrascv-hardware`, `pqrascv-bitcoin-anchor`
- Cryptographic protocol vulnerabilities (signature bypass, nonce reuse, timing side-channels)
- Panic paths triggered by externally-supplied data (attestation quotes, certificates, CBOR)
- Policy engine bypasses (authentication bypass in `PolicyEngineV2`)
- Supply-chain vulnerabilities in build scripts or CI

Out of scope:

- Denial-of-service via oversized inputs (bounded at `MAX_QUOTE_CBOR_SIZE`)
- Vulnerabilities in `software-rot-unsafe` feature (documented as unsafe; not for production use)
- Issues requiring physical device compromise to exploit

## Security Design Notes

- **Post-quantum signatures**: All attestation quotes are signed with ML-DSA-65 (FIPS 204). No RSA or ECDSA in the attestation path.
- **Constant-time operations**: PQ operations use RustCrypto crates with constant-time guarantees.
- **Zeroize-on-drop**: `SigningKeySeed` zeroes its memory on drop.
- **No panics on external input**: All parsing and validation functions return `Result`; no `assert!` on externally-supplied data.
- **`SoftwareRoT` is test-only**: The `software-rot-unsafe` feature is rejected by `PolicyEngineV2::production()` and requires an explicit CLI flag.
