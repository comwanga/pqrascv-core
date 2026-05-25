//! Intel TDX (Trust Domain Extensions) Root-of-Trust backend.
//!
//! Reads the TDREPORT from `/dev/tdx_guest` via the `TDX_CMD_GET_REPORT0`
//! ioctl, extracts MRTD and RTMR[0..3], and normalizes each 48-byte
//! SHA-384 register to a 32-byte SHA3-256 digest for PCR slot storage.
//!
//! # PCR slot mapping
//!
//! | PCR | Source | Meaning |
//! |-----|--------|---------|
//! | 0 | `SHA3-256(MRTD)` | Initial TD measurement |
//! | 1 | `SHA3-256(RTMR[0])` | Firmware/BIOS extensions |
//! | 2 | `SHA3-256(RTMR[1])` | OS-loader extensions |
//! | 3 | `SHA3-256(RTMR[2])` | OS-kernel extensions |
//! | 4 | `SHA3-256(RTMR[3])` | Application-layer extensions |
//! | 5–7 | zero | Unused |
//!
//! # Feature
//!
//! Enabled by the `intel-tdx` Cargo feature. Returns
//! [`PqRascvError::BackendUnavailable`] when the feature is disabled or
//! the host is not a TDX guest.

#[cfg(feature = "intel-tdx")]
mod inner {
    use crate::{
        error::PqRascvError,
        measurement::{Measurements, PcrBank, RoT},
    };
    use sha3::{Digest as _, Sha3_256};

    const MRTD_OFFSET: usize = 0x090;
    const RTMR0_OFFSET: usize = 0x150;
    const RTMR1_OFFSET: usize = 0x180;
    const RTMR2_OFFSET: usize = 0x1B0;
    const RTMR3_OFFSET: usize = 0x1E0;
    const SHA384_LEN: usize = 48;
    pub(super) const TDREPORT_LEN: usize = 1024;

    #[cfg(target_os = "linux")]
    const REPORTDATA_LEN: usize = 64;

    #[cfg(target_os = "linux")]
    const TDX_CMD_GET_REPORT0: u64 = 0xc480_4701;

    #[cfg(target_os = "linux")]
    #[repr(C)]
    struct TdxReportReq {
        reportdata: [u8; REPORTDATA_LEN],
        tdreport: [u8; TDREPORT_LEN],
    }

    /// Intel TDX Root-of-Trust.
    pub struct IntelTdxRoT<'a> {
        #[cfg(target_os = "linux")]
        firmware: &'a [u8],
        #[cfg(target_os = "linux")]
        ai_model: Option<&'a [u8]>,
        #[cfg(target_os = "linux")]
        event_counter: u64,
        #[cfg(not(target_os = "linux"))]
        _phantom: core::marker::PhantomData<&'a ()>,
    }

    impl<'a> IntelTdxRoT<'a> {
        #[must_use]
        #[cfg(target_os = "linux")]
        pub fn new(firmware: &'a [u8], ai_model: Option<&'a [u8]>, event_counter: u64) -> Self {
            Self {
                firmware,
                ai_model,
                event_counter,
            }
        }

        #[must_use]
        #[cfg(not(target_os = "linux"))]
        pub fn new(_firmware: &'a [u8], _ai_model: Option<&'a [u8]>, _event_counter: u64) -> Self {
            Self {
                _phantom: core::marker::PhantomData,
            }
        }

        /// Parse a raw 1024-byte TDREPORT and produce [`Measurements`].
        ///
        /// Used in tests with synthetic data and by `measure()` with real hardware output.
        pub fn measurements_from_report(
            tdreport: &[u8; TDREPORT_LEN],
            firmware: &[u8],
            ai_model: Option<&[u8]>,
            event_counter: u64,
        ) -> Result<Measurements, PqRascvError> {
            let normalize = |offset: usize| -> [u8; 32] {
                Sha3_256::digest(&tdreport[offset..offset + SHA384_LEN]).into()
            };

            let mut pcrs = PcrBank::default();
            pcrs.digests[0] = normalize(MRTD_OFFSET);
            pcrs.digests[1] = normalize(RTMR0_OFFSET);
            pcrs.digests[2] = normalize(RTMR1_OFFSET);
            pcrs.digests[3] = normalize(RTMR2_OFFSET);
            pcrs.digests[4] = normalize(RTMR3_OFFSET);

            let firmware_hash: [u8; 32] = Sha3_256::digest(firmware).into();
            let ai_model_hash: [u8; 32] = match ai_model {
                Some(m) => Sha3_256::digest(m).into(),
                None => [0u8; 32],
            };

            Ok(Measurements {
                pcrs,
                firmware_hash,
                ai_model_hash,
                event_counter,
            })
        }
    }

    #[cfg(target_os = "linux")]
    impl RoT for IntelTdxRoT<'_> {
        fn measure(&self) -> Result<Measurements, PqRascvError> {
            use std::fs::OpenOptions;
            use std::os::unix::io::AsRawFd;

            let fw_hash: [u8; 32] = Sha3_256::digest(self.firmware).into();
            let mut req = TdxReportReq {
                reportdata: [0u8; REPORTDATA_LEN],
                tdreport: [0u8; TDREPORT_LEN],
            };
            req.reportdata[..32].copy_from_slice(&fw_hash);

            let dev = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tdx_guest")
                .map_err(|_| PqRascvError::BackendUnavailable)?;

            let ret = unsafe {
                libc::ioctl(
                    dev.as_raw_fd(),
                    TDX_CMD_GET_REPORT0,
                    &mut req as *mut TdxReportReq,
                )
            };
            if ret != 0 {
                return Err(PqRascvError::MeasurementFailed);
            }

            Self::measurements_from_report(
                &req.tdreport,
                self.firmware,
                self.ai_model,
                self.event_counter,
            )
        }
    }

    #[cfg(not(target_os = "linux"))]
    impl RoT for IntelTdxRoT<'_> {
        fn measure(&self) -> Result<Measurements, PqRascvError> {
            Err(PqRascvError::BackendUnavailable)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn fake_tdreport(mrtd: [u8; 48], rtmr0: [u8; 48]) -> [u8; TDREPORT_LEN] {
            let mut r = [0u8; TDREPORT_LEN];
            r[MRTD_OFFSET..MRTD_OFFSET + 48].copy_from_slice(&mrtd);
            r[RTMR0_OFFSET..RTMR0_OFFSET + 48].copy_from_slice(&rtmr0);
            r
        }

        #[test]
        fn mrtd_maps_to_pcr0() {
            let mrtd = [0x42u8; 48];
            let report = fake_tdreport(mrtd, [0u8; 48]);
            let m = IntelTdxRoT::measurements_from_report(&report, b"fw", None, 0).unwrap();
            let expected: [u8; 32] = Sha3_256::digest(mrtd).into();
            assert_eq!(m.pcrs.digests[0], expected);
        }

        #[test]
        fn rtmr0_maps_to_pcr1() {
            let rtmr0 = [0xAAu8; 48];
            let report = fake_tdreport([0u8; 48], rtmr0);
            let m = IntelTdxRoT::measurements_from_report(&report, b"fw", None, 0).unwrap();
            let expected: [u8; 32] = Sha3_256::digest(rtmr0).into();
            assert_eq!(m.pcrs.digests[1], expected);
        }

        #[test]
        fn zero_mrtd_maps_to_nonzero_pcr0() {
            let report = [0u8; TDREPORT_LEN];
            let m = IntelTdxRoT::measurements_from_report(&report, b"fw", None, 0).unwrap();
            assert_ne!(m.pcrs.digests[0], [0u8; 32]);
        }

        #[test]
        fn firmware_hash_from_local_bytes() {
            let report = [0u8; TDREPORT_LEN];
            let m = IntelTdxRoT::measurements_from_report(&report, b"my-fw", None, 0).unwrap();
            let expected: [u8; 32] = Sha3_256::digest(b"my-fw").into();
            assert_eq!(m.firmware_hash, expected);
        }

        #[test]
        fn distinct_mrtd_values_produce_distinct_pcr0() {
            let r1 = fake_tdreport([0x11u8; 48], [0u8; 48]);
            let r2 = fake_tdreport([0x22u8; 48], [0u8; 48]);
            let m1 = IntelTdxRoT::measurements_from_report(&r1, b"fw", None, 0).unwrap();
            let m2 = IntelTdxRoT::measurements_from_report(&r2, b"fw", None, 0).unwrap();
            assert_ne!(m1.pcrs.digests[0], m2.pcrs.digests[0]);
        }
    }
}

#[cfg(feature = "intel-tdx")]
pub use inner::IntelTdxRoT;

/// Stub — `intel-tdx` feature not compiled in.
#[cfg(not(feature = "intel-tdx"))]
pub struct IntelTdxRoT;

#[cfg(not(feature = "intel-tdx"))]
impl crate::measurement::RoT for IntelTdxRoT {
    fn measure(&self) -> Result<crate::measurement::Measurements, crate::error::PqRascvError> {
        Err(crate::error::PqRascvError::BackendUnavailable)
    }
}
