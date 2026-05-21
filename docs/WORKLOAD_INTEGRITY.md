# Workload Integrity Abstractions

Workload Integrity provides metadata-level tracking of active workloads (such as Docker containers, virtual machines, or system services) running on the platform.

## Workload Identity Model

A workload's identity is defined in `workload_integrity.rs` using the following structures:

```rust
pub struct WorkloadIdentity {
    /// Unique identifier of the workload (e.g., container ID, service name).
    pub workload_id: String,
    /// Cryptographic digest of the workload image/executable.
    pub image_digest: TypedDigest,
    /// Optional identifier of the supply-chain signer.
    pub signer: Option<String>,
}

pub struct WorkloadIntegrityEvidence {
    /// List of workloads observed on the system.
    pub workloads: Vec<WorkloadIdentity>,
}
```

## Security Warning & Scope

> [!WARNING]
> **Metadata Tracking Only**: The `WorkloadIdentity` structure is a high-level representation used by the verifier to audit what software has run. It does **NOT** provide:
> - Hardware-enforced runtime memory isolation (e.g. Intel SGX/TDX, AMD SEV).
> - Exploit prevention at the container or process level.
> - Sandbox isolation guarantees.
> 
> For hardware-enforced trusted execution environments, refer to [HARDWARE_BACKENDS.md](file:///c:/Users/mwang/Desktop/pqrascv-core/docs/HARDWARE_BACKENDS.md).
