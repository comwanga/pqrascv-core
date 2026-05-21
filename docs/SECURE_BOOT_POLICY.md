# Secure Boot Policy Semantics

This document describes how UEFI/Host Secure Boot states and cryptographic key databases (db, dbx, MOK) are validated during attestation.

## Secure Boot States

The attestation context tracks the platform's Secure Boot configuration via `SecureBootState`:
- `Enabled`: Policies are strictly enforced; bootloaders and kernels must be signed by trusted authorities.
- `Disabled`: Signature validation is not active.
- `SetupMode`: Platform is in enrollment mode where platform keys can be modified without signature verification.
- `Unknown`: Secure Boot status cannot be securely verified.

## Secure Boot Evidence

The `SecureBootEvidence` struct gathers measurements from the boot process:
1. `state`: Current `SecureBootState`.
2. `db_hash`: The hash of the authorized signature database (db).
3. `dbx_hash`: The hash of the forbidden signature database (dbx) containing revoked certificates and hashes.
4. `mok_hash`: The hash of the Machine Owner Key (MOK) database, widely used in Linux environments.

## Policy Rules

A verifier enforces Secure Boot rules using `HardwarePolicyRule::RequireSecureBootState(SecureBootState)`.
- If a rule mandates `SecureBootState::Enabled`, the policy engine rejects attestations where the state is `Disabled` or `SetupMode`.
- In conflict detection, specifying different required Secure Boot states (e.g., `Enabled` and `Disabled`) triggers a fail-closed `PolicyConflictError::ConflictingSecureBootStates`.
