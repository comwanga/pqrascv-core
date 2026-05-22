//! Bitcoin Workload Integrity
//!
//! Models the runtime integrity of a Bitcoin Core workload by capturing
//! its runtime identity, configuration, and execution state.

use crate::digest::TypedDigest;
use crate::runtime_attestation::RuntimeMeasurement;
use alloc::vec::Vec;

/// Evidence of a running Bitcoin node workload.
///
/// This provides explicitly typed evidence that `bitcoind` is running,
/// allowing the verifier to validate its binary, configuration, and
/// chainstate integrity without collapsing it into generic container security.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BitcoinWorkloadEvidence {
    /// The process ID of the running `bitcoind` instance.
    pub bitcoind_pid: u32,
    /// The runtime-measured hash of the `bitcoind` executable.
    pub executable_hash: TypedDigest,
    /// The runtime-measured hash of `bitcoin.conf`.
    pub config_hash: TypedDigest,
    /// Optional hash of the chainstate directory or a specific block/UTXO set commitment.
    pub chainstate_hash: Option<TypedDigest>,
    /// Raw runtime measurements associated with the workload execution.
    pub runtime_measurements: Vec<RuntimeMeasurement>,
}

impl BitcoinWorkloadEvidence {
    /// Creates a new `BitcoinWorkloadEvidence`.
    #[must_use]
    pub fn new(
        bitcoind_pid: u32,
        executable_hash: TypedDigest,
        config_hash: TypedDigest,
        chainstate_hash: Option<TypedDigest>,
        runtime_measurements: Vec<RuntimeMeasurement>,
    ) -> Self {
        Self {
            bitcoind_pid,
            executable_hash,
            config_hash,
            chainstate_hash,
            runtime_measurements,
        }
    }
}
