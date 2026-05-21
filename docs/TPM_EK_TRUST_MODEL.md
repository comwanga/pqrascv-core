# TPM Endorsement Key (EK) Trust Model

## Overview

The Endorsement Key (EK) is the primary cryptographic identity of a Trusted Platform Module (TPM). Baked in at the factory by the manufacturer (e.g. Infineon, AMD, Intel, Nuvoton), it serves as the ultimate hardware trust anchor for the device.

In PQ-RASCV, the EK Trust Model is handled via the `EkCertChain` abstraction and evaluated using a manufacturer-specific `ManufacturerTrustStore`.

## EK Certificate Validation

During quote verification, the Attestation Key (AK) must be authenticated to prove it is securely resident on the TPM. This relies on validating the EK:
1. The device presents the `ek_pub` or the full X.509 `EkCertChain`.
2. The verifier checks the chain up to the Manufacturer's Root CA trust anchor.
3. Once the EK is deemed trusted, the verifier relies on the assumption that the TPM enforces AK creation securely (via MakeCredential operations in the onboarding phase, outside the scope of direct quote verification).

## Abstract Interfaces

The module `ek_framework.rs` supplies:
- `ManufacturerTrustStore` trait: Responsible for isolating the manufacturer-specific parsing, intermediate CA processing, and EK Extended Key Usage (EKU) validations.
- `EkCertChain`: A strongly typed representation of the EK certificate and its intermediates.
