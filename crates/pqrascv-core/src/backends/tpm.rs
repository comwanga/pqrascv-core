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
//! - Windows is not supported. TPM on Windows requires separate integration.
//!
//! See `TPM_INTEGRATION.md` at the repository root for hardware setup, swtpm
//! simulation, and PCR policy guidance.
//!
//! # Maturity
//!
//! Architecture: sound. Tested against real hardware: no evidence. Tested
//! against swtpm: no evidence. Production-validated: no. This backend should
//! be treated as **experimental** until integration tests against a real or
//! simulated TPM are established.
//!
//! # PCR bank — PCRs 0–7 (SHA-256, normalized to SHA3-256)
//!
//! | PCR | Standard meaning (UEFI / TCG PC Client) |
//! |-----|-----------------------------------------|
//! | 0   | SRTM, BIOS, Host Platform extensions |
//! | 1   | BIOS configuration |
//! | 2   | Option ROM code |
//! | 3   | Option ROM configuration |
//! | 4   | MBR / boot manager code |
//! | 5   | Boot manager configuration |
//! | 6   | State transitions / wake events |
//! | 7   | Secure Boot policy (DB / DBX / PK / KEK) |
//!
//! PCRs 8–15 (OS kernel, modules, IMA) are **not** read by this backend.
//! IMA measurement integration is available via `pqrascv-hardware` with the
//! `live-evidence` feature.
//!
//! **PCR 7 requires Secure Boot to be enabled** for meaningful attestation.
//! With Secure Boot disabled, PCR 7 contains a well-known placeholder and
//! cannot attest boot chain integrity.
//!
//! # PCR normalization
//!
//! The TPM hardware stores PCRs as SHA-256 digests. To ensure consistent
//! cross-backend comparisons and policy enforcement, this backend normalizes
//! each raw SHA-256 PCR value through SHA3-256:
//!
//! ```text
//! pcrs.digests[i] = SHA3-256( tpm_sha256_pcr[i] )
//! ```
//!
//! This means `pcrs.digests` values are **not** the raw TPM PCR values.
//! Policy rules that compare PCR values must account for this normalization.
//! The `pcrs.algorithm` field is always `PcrAlgorithm::Sha3_256`.
//!
//! # Firmware measurement
//!
//! The caller supplies raw firmware bytes.  They are hashed locally with
//! SHA3-256 (not via the TPM hash command) to keep the hot path allocation-free
//! and independent of TPM latency.
//!
//! **The firmware hash is not derived from or verified against the TPM
//! measurement log.** A compromised OS controlling the caller could supply
//! different firmware bytes than what actually executed. For higher-assurance
//! deployments, validate caller-supplied bytes against a trusted reference or
//! the IMA log before passing them to [`TpmRoT::new`].
//!
//! # Event counter
//!
//! Uses `TPM2_PT_AUDIT_COUNTER_0` (`AuditCounter0`) as a best-effort monotonic
//! proxy — it increments with every audited TPM command.  This is **not** a
//! boot counter and should not be relied on for strict monotonicity guarantees
//! across reboots.  If the property is unavailable, the counter is set to zero.

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
    /// Opens a fresh TPM connection on every call to [`RoT::measure`] rather
    /// than keeping one around. The TPM resource manager only has a handful of
    /// session slots, so holding one open would starve other processes. If
    /// you're measuring frequently, manage a connection pool yourself.
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
        /// The actual TPM connection is opened when you call `measure()`, not here.
        /// Set `TPM2TOOLS_TCTI=device:/dev/tpm0` (or `swtpm:port=2321` for
        /// simulation) before you call `measure()`.
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

            // ── 3. Normalize SHA-256 PCRs → SHA3-256 ────────────────────────
            //
            // The TPM returns SHA-256 digests. We normalize each one through
            // SHA3-256 so that pcrs.digests is always algorithm-consistent with
            // the SoftwareRoT and DiceRoT backends. Policy rules can then
            // compare PCR values across backends without algorithm confusion.
            //
            // Stored value: SHA3-256( raw_tpm_sha256_pcr )
            let mut pcrs = PcrBank::default();
            for (i, digest) in digest_list.value().iter().enumerate().take(PCR_COUNT) {
                let raw: &[u8] = digest.as_ref();
                let mut padded = [0u8; PCR_SIZE];
                let copy_len = raw.len().min(PCR_SIZE);
                padded[PCR_SIZE - copy_len..].copy_from_slice(&raw[..copy_len]);

                let mut h = Sha3_256::new();
                h.update(padded);
                pcrs.digests[i] = h.finalize().into();
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

            // ── 5. Get event counter ─────────────────────────────────────────
            //
            // TPM2_PT_AUDIT_COUNTER_0 (AuditCounter0) ticks with every audited
            // TPM command. It is a best-effort monotonic proxy, not a boot
            // counter — see module docs for the full caveat.
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
