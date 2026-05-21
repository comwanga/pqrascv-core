# Drift Detection Engine

The `DriftDetectionEngine` distinguishes between malicious modifications and authorized software/firmware upgrades.

## Drift Policy Modes

The engine evaluates measurement deviations according to a configurable `DriftPolicyMode`:
- **`Learning`**: Allows all drift levels. Useful for collecting actual hardware measurements and establishing initial baselines.
- **`Audit`**: Logs/warns on all drift levels, but only fails the attestation if `Critical` drift is found.
- **`Enforcing`**: Fails the attestation for both `Warning` and `Critical` drift.

## Severity Levels

- **`Informational`**: Low-risk deviations or authorized bootloader updates.
- **`Warning`**: Authorized kernel/firmware upgrades.
- **`Critical`**: Unrecognized bootloader, kernel, or firmware changes.

## Upgrade Detection Logic

When evaluating drift, an optional `upgrade_baseline` can be supplied. If:
1. The `upgrade_baseline` is a valid successor to the current baseline (i.e. strictly monotonic version increment).
2. The incoming measurement matches the digest defined in the `upgrade_baseline`.

Then, the deviation is classified as an **authorized transition** rather than a critical anomaly, resulting in lowered drift severity (e.g., downgrade to `Warning` or `Informational`).
