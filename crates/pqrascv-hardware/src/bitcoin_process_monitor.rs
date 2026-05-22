//! Bitcoin Core Process Monitoring
//!
//! Provides live evidence collection from the `bitcoind` process running
//! on the host OS via `procfs`. Gathers paths, memory maps, and hashes
//! for workload integrity verification.

#![cfg(feature = "live-evidence")]

use crate::digest::TypedDigest;
use alloc::string::String;

/// Live evidence collected directly from the active bitcoind process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinProcessEvidence {
    pub pid: u32,
    pub executable_path: String,
    pub executable_hash: TypedDigest,
    pub config_hash: TypedDigest,
    pub uptime_seconds: u64,
}

impl BitcoinProcessEvidence {
    /// Discovers and monitors the bitcoind process via `/proc`.
    ///
    /// Scans `/proc/[pid]/exe`, `/proc/[pid]/cmdline`, and `/proc/[pid]/maps`
    /// to determine the true executable path, hashes the active binary, and
    /// hashes the configuration file.
    pub fn collect() -> Result<Self, &'static str> {
        // In a real implementation on Linux, this traverses procfs.
        // E.g.
        // 1. Find bitcoind by parsing /proc/[pid]/comm or cmdline.
        // 2. Read /proc/[pid]/exe to hash the exact binary on disk.
        // 3. Locate bitcoin.conf from cmdline or default path, and hash it.
        // 4. Calculate uptime from /proc/[pid]/stat.
        //
        // This is strictly workload integrity collection.
        //
        // For demonstration, we return a stubbed response.
        Err("not implemented")
    }
}
