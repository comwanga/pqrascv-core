//! TPM 2.0 Root-of-Trust backend.
//!
//! Reads PCR values from a TPM 2.0 device using the [`tss-esapi`] crate,
//! which wraps the TCG TSS2 Enhanced System API (ESAPI).
//!
//! # Availability
//!
//! Enabled by the `hardware-tpm` Cargo feature.  Requires:
//! - Linux: `libtss2-esys`, `libtss2-mu`, `libtss2-rc`, `libtss2-tctildr`
//!   (install via `apt install tpm2-tss` or `dnf install tpm2-tss-devel`).
//! - The TPM access path is configured via the `TPM2TOOLS_TCTI` environment
//!   variable (e.g. `device:/dev/tpm0` or `swtpm:port=2321` for simulation).
//!
//! # PCR bank selection
//!
//! The backend reads the SHA-256 PCR bank by default (PCRs 0–7).
//! SHA-384 is not used because our `Measurements` struct stores 32-byte digests.
//!
//! # Firmware measurement
//!
//! The caller supplies raw firmware bytes.  They are hashed locally with
//! SHA3-256 (not via the TPM hash command) to keep the hot path allocation-free
//! and independent of TPM latency.
//!
//! # Event counter
//!
//! Uses `TPM2_PT_NV_COUNTERS_AVAIL` to get a snapshot of the monotonic tick
//! count as a best-effort event counter.  If the TPM does not support it,
//! the counter is set to zero.

#[cfg(feature = "hardware-tpm")]
mod inner {
    use crate::{
        error::PqRascvError,
        measurement::{Measurements, PcrBank, RoT, PCR_COUNT, PCR_SIZE},
    };
    use sha3::{Digest as _, Sha3_256};
    use tss_esapi::{
        constants::{CapabilityType, PropertyTag},
        interface_types::algorithm::HashingAlgorithm,
        structures::{CapabilityData, PcrSelectionListBuilder, PcrSlot},
        tcti_ldr::TctiNameConf,
        Context,
    };

    // All 8 PCR slots we read (PCRs 0–7).
    const TPM_PCR_SLOTS: [PcrSlot; 8] = [
        PcrSlot::Slot0,
        PcrSlot::Slot1,
        PcrSlot::Slot2,
        PcrSlot::Slot3,
        PcrSlot::Slot4,
        PcrSlot::Slot5,
        PcrSlot::Slot6,
        PcrSlot::Slot7,
    ];

    /// TPM 2.0 Root-of-Trust.
    ///
    /// Opens the TPM connection on each call to [`RoT::measure`] to avoid
    /// holding a long-lived context (the TPM resource manager has limited
    /// concurrent session slots).  For high-frequency attestation consider
    /// pooling contexts externally.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pqrascv_core::backends::tpm::TpmRoT;
    /// use pqrascv_core::measurement::RoT;
    ///
    /// // TPM access path comes from TPM2TOOLS_TCTI env var.
    /// let rot = TpmRoT::new(b"my-firmware-image", None, 1);
    /// let measurements = rot.measure().expect("TPM measurement failed");
    /// ```
    pub struct TpmRoT<'a> {
        /// Bytes of the firmware image to measure (SHA3-256 hashed locally).
        firmware: &'a [u8],
        /// Optional AI model bytes. `None` → `ai_model_hash` is all zeros.
        ai_model: Option<&'a [u8]>,
        /// Caller-supplied baseline event counter (augmented with TPM tick).
        event_counter_base: u64,
    }

    impl<'a> TpmRoT<'a> {
        /// Creates a new [`TpmRoT`].
        ///
        /// The TPM connection is opened lazily inside [`RoT::measure`].
        /// Set `TPM2TOOLS_TCTI=device:/dev/tpm0` (or `swtpm:port=2321` for
        /// simulation) before calling `measure()`.
        #[must_use]
        pub fn new(
            firmware: &'a [u8],
            ai_model: Option<&'a [u8]>,
            event_counter_base: u64,
        ) -> Self {
            Self {
                firmware,
                ai_model,
                event_counter_base,
            }
        }
    }

    impl<'a> RoT for TpmRoT<'a> {
        fn measure(&self) -> Result<Measurements, PqRascvError> {
            // ── 1. Open TPM context ───────────────────────────────────────────
            let tcti = TctiNameConf::from_environment_variable()
                .map_err(|_| PqRascvError::MeasurementFailed)?;

            let mut ctx = Context::new(tcti).map_err(|_| PqRascvError::MeasurementFailed)?;

            // ── 2. Read PCR bank (SHA-256, PCRs 0–7) ────────────────────────
            let pcr_selection = PcrSelectionListBuilder::new()
                .with_selection(HashingAlgorithm::Sha256, &TPM_PCR_SLOTS)
                .build()
                .map_err(|_| PqRascvError::MeasurementFailed)?;

            let (_update_counter, _selection_out, digest_list) = ctx
                .execute_without_session(|c| c.pcr_read(pcr_selection))
                .map_err(|_| PqRascvError::MeasurementFailed)?;

            // ── 3. Copy digests into our PCR bank ────────────────────────────
            //
            // tss-esapi returns SHA-256 digests (32 bytes each).
            // We copy up to PCR_COUNT digests; extras are silently dropped.
            let mut pcrs = PcrBank::default();
            for (i, digest) in digest_list.value().iter().enumerate().take(PCR_COUNT) {
                let bytes = digest.value();
                if bytes.len() == PCR_SIZE {
                    pcrs.0[i].copy_from_slice(bytes);
                } else {
                    // Digest shorter than 32 bytes — left-pad with zeros.
                    let offset = PCR_SIZE - bytes.len().min(PCR_SIZE);
                    pcrs.0[i][offset..].copy_from_slice(&bytes[..bytes.len().min(PCR_SIZE)]);
                }
            }

            // ── 4. Hash firmware and AI model locally (SHA3-256) ─────────────
            let firmware_hash: [u8; 32] = {
                let mut h = Sha3_256::new();
                h.update(self.firmware);
                h.finalize().into()
            };

            let ai_model_hash: [u8; 32] = match self.ai_model {
                Some(model) => {
                    let mut h = Sha3_256::new();
                    h.update(model);
                    h.finalize().into()
                }
                None => [0u8; 32],
            };

            // ── 5. Get event counter (TPM audit counter as monotonic proxy) ────
            //
            // AuditCounter0 is a u32 variable property that increments with every
            // audited command, providing a best-effort monotonic counter.
            let event_counter = ctx
                .execute_without_session(|c| {
                    c.get_capability(
                        CapabilityType::TpmProperties,
                        PropertyTag::AuditCounter0.into(),
                        1,
                    )
                })
                .ok()
                .and_then(|(cap, _more_data)| {
                    if let CapabilityData::TpmProperties(props) = cap {
                        props
                            .find(PropertyTag::AuditCounter0)
                            .map(|p| u64::from(p.value()))
                    } else {
                        None
                    }
                })
                .unwrap_or(0)
                .wrapping_add(self.event_counter_base);

            Ok(Measurements {
                pcrs,
                firmware_hash,
                ai_model_hash,
                event_counter,
            })
        }
    }
}

// ── Public re-export (only when feature is enabled) ─────────────────────────

#[cfg(feature = "hardware-tpm")]
pub use inner::TpmRoT;

// ── Compile-time sentinel for non-TPM builds ─────────────────────────────────

/// Placeholder used when the `hardware-tpm` feature is disabled.
///
/// Calling [`RoT::measure`] on this type always returns
/// [`PqRascvError::BackendUnavailable`].
#[cfg(not(feature = "hardware-tpm"))]
pub struct TpmRoT;

#[cfg(not(feature = "hardware-tpm"))]
impl crate::measurement::RoT for TpmRoT {
    fn measure(&self) -> Result<crate::measurement::Measurements, crate::error::PqRascvError> {
        Err(crate::error::PqRascvError::BackendUnavailable)
    }
}
