# Runtime Integrity Verification & Drift Analysis

Runtime Integrity is the trust domain responsible for verifying that the running system components (kernel modules, executables, libraries, and container runtimes) have not deviated from their trusted baselines. 

## The Runtime Integrity Domain

At runtime, the platform collects measurements of running files and processes. The verifier checks these measurements against whitelists and rolling upgrade databases. 

## Dynamic Drift Engine

The `RuntimeDriftEngine` compares actual runtime measurements against the expected whitelists:

```rust
pub struct RuntimeDriftEngine;

impl RuntimeDriftEngine {
    /// Compares runtime measurements against a whitelist of approved digests
    /// and a secondary list representing rolling upgrades.
    ///
    /// - An exact match in `whitelist` produces no drift.
    /// - A match in `rolling_upgrades` produces `Warning` drift.
    /// - An unknown digest produces `Critical` drift.
    pub fn detect_drift(
        actual: &[RuntimeMeasurement],
        whitelist: &[TypedDigest],
        rolling_upgrades: &[TypedDigest],
    ) -> Vec<RuntimeDriftReport> {
        // ...
    }
}
```

### Drift Severity Levels

Observed anomalies are classified into three severity levels defined by the `RuntimeDriftSeverity` enum:

- **Informational**: Expected, minor deviations such as harmless configuration changes. By default, these log warnings but do not fail policy evaluation.
- **Warning**: Staging changes or rolling upgrades. These indicate that a file matches a known "rolling update" digest.
- **Critical**: Unapproved or unknown kernel modules, executables, or processes. This immediately fails the verification policy.

### Policy Escalation

Production presets can be configured to escalate drift severity:
- An administrator can decide that any `Warning` or `Informational` drift should fail policy execution under a strict enforcement mode.
- In learning or audit modes, even `Critical` drift might be logged as a warning without rejecting the host.

## Policy Rules

The policy engine enforces runtime integrity using two main rules:

- `HardwarePolicyRule::RequireRuntimeIntegrity { whitelist, rolling_upgrades }`: Compares runtime measurements from `HardwarePolicyContext` against the whitelists.
- `HardwarePolicyRule::RequireIma`: Requires that the Integrity Measurement Architecture (IMA) is enabled and active.
