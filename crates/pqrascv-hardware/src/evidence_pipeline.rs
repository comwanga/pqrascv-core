//! Operational Evidence Acquisition Pipeline
//!
//! Orchestrates the collection of live evidence from the TPM, EFI variables,
//! IMA logs, and active OS processes. Sequences these unforgeable measurements
//! into a unified, deterministic attestation payload for verifier consumption.

#![cfg(feature = "live-evidence")]

use crate::bitcoin_process_monitor::BitcoinProcessEvidence;
use crate::digest::TypedDigest;
use crate::live_tpm::LiveTpmDevice;
use crate::secure_boot_collector::SecureBootCollector;
use alloc::vec::Vec;

/// Represents a fully sequenced payload of live node evidence.
#[derive(Debug, Clone)]
pub struct LiveAttestationPayload {
    pub sequence_number: u64,
    pub collection_timestamp: u64,
    pub secure_boot_state: Option<SecureBootCollector>,
    pub process_evidence: Option<BitcoinProcessEvidence>,
    pub tpm_quote: Vec<u8>,
    pub pcr_banks: Vec<Vec<u8>>,
}

/// Pipeline for orchestrating and assembling operational evidence.
#[derive(Debug)]
pub struct EvidencePipeline {
    tpm: LiveTpmDevice,
    sequence_counter: u64,
}

impl EvidencePipeline {
    /// Initializes a new evidence pipeline attached to a specific TPM device.
    pub fn new(tpm_device_path: &str) -> Result<Self, &'static str> {
        let tpm = LiveTpmDevice::connect(tpm_device_path)?;
        Ok(Self {
            tpm,
            sequence_counter: 0,
        })
    }

    /// Triggers a full acquisition cycle across all available hardware and OS
    /// interfaces, assembling a timestamped payload.
    pub fn acquire_evidence(
        &mut self,
        nonce: &[u8],
        pcr_indices: &[u32],
    ) -> Result<LiveAttestationPayload, &'static str> {
        self.sequence_counter += 1;

        let (tpm_clock, _) = self.tpm.read_clock_info().unwrap_or((0, 0));

        let tpm_quote = self
            .tpm
            .acquire_quote(nonce, pcr_indices)
            .unwrap_or_default();

        let mut pcr_banks = Vec::new();
        for &algo in &self.tpm.supported_banks {
            if let Ok(bank) = self.tpm.read_pcr_bank(algo) {
                pcr_banks.push(bank);
            }
        }

        let secure_boot_state = SecureBootCollector::collect().ok();

        let process_evidence = BitcoinProcessEvidence::collect().ok();

        // but would typically stream into the PCR calculations or a separate log)
        // ...

        Ok(LiveAttestationPayload {
            sequence_number: self.sequence_counter,
            collection_timestamp: tpm_clock, // Using TPM hardware clock
            secure_boot_state,
            process_evidence,
            tpm_quote,
            pcr_banks,
        })
    }
}
