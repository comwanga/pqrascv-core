# TPM Quote Verification

## Overview

The `pqrascv-hardware` crate implements a cryptographically sound, native Rust TPM 2.0 quote verification pipeline. This document outlines how the verifier handles incoming quote evidence, parses the binary structures, recomputes digests, and verifies the cryptographic signatures without relying on bloated C libraries like `tss-esapi` on the verifier side.

## Process

1. **Parser Execution**: The verifier receives the raw `quote_blob` (which corresponds to `TPM2B_ATTEST`) and `quote_signature` (which corresponds to `TPMT_SIGNATURE`). It uses bounded parsers to decode these structures, ensuring that arbitrary payloads cannot trigger memory unsafe behavior or out-of-bounds reads.
2. **Nonce Binding**: The `extraData` field of the `TPMS_ATTEST` structure is strictly compared against the challenge nonce expected by the verifier to guarantee replay protection.
3. **PCR Canonical Recomputation**: The `TPMS_ATTEST` contains a `TPML_PCR_SELECTION` which declares which PCR slots and hashing algorithms were queried. The verifier uses the explicitly defined `TypedPcrBank` to map the reported values to the selected slots, re-hashes the concatenation, and matches the output against the `pcrDigest` contained within the `TPMS_QUOTE_INFO`.
4. **Signature Validation**: Finally, using the `tpm-crypto` feature flag, the verifier extracts the `TPMT_PUBLIC` structure representing the AK (Attestation Key), parses the RSA or ECC keys into generic PKCS/OpenSSL formats, and verifies the signature over the `TPMS_ATTEST` payload.

## Hardening Rules

- No SHA-1 usage is permitted; an explicit rejection is hardcoded in the `tpm_structures.rs` enumerator mapping.
- TPM clock parameters are checked to ensure no reset attacks occurred mid-attestation.
