//! AMD SEV-SNP (Secure Encrypted Virtualization — Secure Nested Paging) backend.
//!
//! Reads the SNP attestation report from `/dev/sev-guest` via
//! `SNP_GET_REPORT` ioctl, extracts the `measurement` and `policy` fields,
//! and normalizes them to SHA3-256 digests for PCR slot storage.
//!
//! # PCR slot mapping
//!
//! | PCR | Source | Meaning |
//! |-----|--------|---------|
//! | 0 | `SHA3-256(measurement[0..48])` | VM launch measurement |
//! | 1 | `SHA3-256(policy[0..8])` | SNP policy flags |
//! | 2–7 | zero | Unused |
//!
//! # Feature
//!
//! Enabled by the `amd-sev-snp` Cargo feature.

#[cfg(feature = "amd-sev-snp")]
mod inner {
    use crate::{
        error::PqRascvError,
        measurement::{Measurements, PcrBank, RoT},
    };
    use sha3::{Digest as _, Sha3_256};

    // Offsets within the raw attestation report (after MSG_HDR_LEN-byte kernel header).
    const REPORT_POLICY_OFFSET: usize = 0x008;
    const REPORT_MEASUREMENT_OFFSET: usize = 0x090;
    const SHA384_LEN: usize = 48;
    const POLICY_LEN: usize = 8;
    pub(super) const REPORT_LEN: usize = 0x4A0;
    const MSG_HDR_LEN: usize = 0x20;

    // _IOWR(SEV_GUEST_IOC_TYPE=0x53, 0x0, struct snp_guest_request_ioctl)
    // linux/sev-guest.h, verified against kernel 6.5.
    #[cfg(target_os = "linux")]
    const SNP_GET_REPORT: u64 = 0xc030_5300;

    #[cfg(target_os = "linux")]
    #[repr(C)]
    struct SnpReportReq {
        user_data: [u8; 64],
        vmpl: u32,
        rsvd: [u8; 28],
    }

    #[cfg(target_os = "linux")]
    #[repr(C)]
    struct SnpReportResp {
        data: [u8; REPORT_LEN],
    }

    #[cfg(target_os = "linux")]
    #[repr(C)]
    struct SnpGuestRequestIoctl {
        msg_version: u8,
        req_data: u64,
        resp_data: u64,
        exitinfo2: u64,
    }

    /// AMD SEV-SNP Root-of-Trust.
    pub struct AmdSevSnpRoT<'a> {
        #[cfg(target_os = "linux")]
        firmware: &'a [u8],
        #[cfg(target_os = "linux")]
        ai_model: Option<&'a [u8]>,
        #[cfg(target_os = "linux")]
        event_counter: u64,
        #[cfg(not(target_os = "linux"))]
        _phantom: core::marker::PhantomData<&'a ()>,
    }

    impl<'a> AmdSevSnpRoT<'a> {
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

        /// Parse a raw attestation report response buffer and produce [`Measurements`].
        ///
        /// `resp_data` is the full `snp_report_resp.data` buffer (`REPORT_LEN` bytes).
        /// Used in tests with synthetic data; called by `measure()` with real hardware output.
        pub fn measurements_from_resp(
            resp_data: &[u8; REPORT_LEN],
            firmware: &[u8],
            ai_model: Option<&[u8]>,
            event_counter: u64,
        ) -> Result<Measurements, PqRascvError> {
            let report = &resp_data[MSG_HDR_LEN..];

            if report.len() < REPORT_MEASUREMENT_OFFSET + SHA384_LEN {
                return Err(PqRascvError::MeasurementFailed);
            }

            let measurement =
                &report[REPORT_MEASUREMENT_OFFSET..REPORT_MEASUREMENT_OFFSET + SHA384_LEN];
            let policy = &report[REPORT_POLICY_OFFSET..REPORT_POLICY_OFFSET + POLICY_LEN];

            let mut pcrs = PcrBank::default();
            pcrs.digests[0] = Sha3_256::digest(measurement).into();
            pcrs.digests[1] = Sha3_256::digest(policy).into();

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
    impl RoT for AmdSevSnpRoT<'_> {
        fn measure(&self) -> Result<Measurements, PqRascvError> {
            use std::fs::OpenOptions;
            use std::os::unix::io::AsRawFd;

            let fw_hash: [u8; 32] = Sha3_256::digest(self.firmware).into();
            let mut req = SnpReportReq {
                user_data: [0u8; 64],
                vmpl: 0,
                rsvd: [0u8; 28],
            };
            req.user_data[..32].copy_from_slice(&fw_hash);

            let mut resp = SnpReportResp {
                data: [0u8; REPORT_LEN],
            };

            let mut ioctl_req = SnpGuestRequestIoctl {
                msg_version: 1,
                req_data: &req as *const SnpReportReq as u64,
                resp_data: &mut resp as *mut SnpReportResp as u64,
                exitinfo2: 0,
            };

            let dev = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/sev-guest")
                .map_err(|_| PqRascvError::BackendUnavailable)?;

            let ret = unsafe {
                libc::ioctl(
                    dev.as_raw_fd(),
                    SNP_GET_REPORT,
                    &mut ioctl_req as *mut SnpGuestRequestIoctl,
                )
            };
            if ret != 0 {
                return Err(PqRascvError::MeasurementFailed);
            }

            Self::measurements_from_resp(
                &resp.data,
                self.firmware,
                self.ai_model,
                self.event_counter,
            )
        }
    }

    #[cfg(not(target_os = "linux"))]
    impl RoT for AmdSevSnpRoT<'_> {
        fn measure(&self) -> Result<Measurements, PqRascvError> {
            Err(PqRascvError::BackendUnavailable)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn fake_resp(measurement: [u8; 48], policy: [u8; 8]) -> [u8; REPORT_LEN] {
            let mut r = [0u8; REPORT_LEN];
            r[MSG_HDR_LEN + REPORT_MEASUREMENT_OFFSET
                ..MSG_HDR_LEN + REPORT_MEASUREMENT_OFFSET + 48]
                .copy_from_slice(&measurement);
            r[MSG_HDR_LEN + REPORT_POLICY_OFFSET..MSG_HDR_LEN + REPORT_POLICY_OFFSET + 8]
                .copy_from_slice(&policy);
            r
        }

        #[test]
        fn measurement_maps_to_pcr0() {
            let meas = [0x42u8; 48];
            let resp = fake_resp(meas, [0u8; 8]);
            let m = AmdSevSnpRoT::measurements_from_resp(&resp, b"fw", None, 0).unwrap();
            let expected: [u8; 32] = Sha3_256::digest(meas).into();
            assert_eq!(m.pcrs.digests[0], expected);
        }

        #[test]
        fn policy_maps_to_pcr1() {
            let policy = [0xAAu8; 8];
            let resp = fake_resp([0u8; 48], policy);
            let m = AmdSevSnpRoT::measurements_from_resp(&resp, b"fw", None, 0).unwrap();
            let expected: [u8; 32] = Sha3_256::digest(policy).into();
            assert_eq!(m.pcrs.digests[1], expected);
        }

        #[test]
        fn distinct_measurements_produce_distinct_pcr0() {
            let r1 = fake_resp([0x11u8; 48], [0u8; 8]);
            let r2 = fake_resp([0x22u8; 48], [0u8; 8]);
            let m1 = AmdSevSnpRoT::measurements_from_resp(&r1, b"fw", None, 0).unwrap();
            let m2 = AmdSevSnpRoT::measurements_from_resp(&r2, b"fw", None, 0).unwrap();
            assert_ne!(m1.pcrs.digests[0], m2.pcrs.digests[0]);
        }

        #[test]
        fn firmware_hash_from_local_bytes() {
            let resp = fake_resp([0u8; 48], [0u8; 8]);
            let m = AmdSevSnpRoT::measurements_from_resp(&resp, b"my-fw", None, 0).unwrap();
            let expected: [u8; 32] = Sha3_256::digest(b"my-fw").into();
            assert_eq!(m.firmware_hash, expected);
        }

        #[test]
        fn pcrs_2_through_7_are_zero() {
            let resp = fake_resp([0x42u8; 48], [0xBBu8; 8]);
            let m = AmdSevSnpRoT::measurements_from_resp(&resp, b"fw", None, 0).unwrap();
            for slot in 2..8 {
                assert_eq!(m.pcrs.digests[slot], [0u8; 32], "PCR {slot} must be zero");
            }
        }
    }
}

#[cfg(feature = "amd-sev-snp")]
pub use inner::AmdSevSnpRoT;

/// Stub — `amd-sev-snp` feature not compiled in.
#[cfg(not(feature = "amd-sev-snp"))]
pub struct AmdSevSnpRoT;

#[cfg(not(feature = "amd-sev-snp"))]
impl crate::measurement::RoT for AmdSevSnpRoT {
    fn measure(&self) -> Result<crate::measurement::Measurements, crate::error::PqRascvError> {
        Err(crate::error::PqRascvError::BackendUnavailable)
    }
}
