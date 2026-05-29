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
//! | 2 | `SHA3-256([policy_flags, abi_major, abi_minor])` | Decoded policy summary |
//! | 3–7 | zero | Unused |
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
    const REPORT_DATA_OFFSET: usize = 0x050;
    const REPORT_DATA_FW_HASH_LEN: usize = 32;
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

    /// Decoded SNP policy fields from the attestation report.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SnpPolicy {
        pub smt_allowed: bool,
        pub debug_allowed: bool,
        pub migrate_ma_allowed: bool,
        pub abi_major: u8,
        pub abi_minor: u8,
    }

    impl SnpPolicy {
        pub fn from_le_bytes(policy: [u8; 8]) -> Self {
            let bits = u64::from_le_bytes(policy);
            Self {
                smt_allowed: (bits >> 16) & 1 == 1,
                debug_allowed: (bits >> 19) & 1 == 1,
                migrate_ma_allowed: (bits >> 18) & 1 == 1,
                abi_major: ((bits >> 32) & 0xFF) as u8,
                abi_minor: ((bits >> 40) & 0xFF) as u8,
            }
        }
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

            // Verify REPORT_DATA binding: first 32 bytes must match SHA3-256(firmware).
            let fw_hash: [u8; 32] = Sha3_256::digest(firmware).into();
            let report_data_fw = &report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_FW_HASH_LEN];
            if report_data_fw != fw_hash.as_ref() {
                return Err(PqRascvError::MeasurementFailed);
            }

            let measurement = &report[REPORT_MEASUREMENT_OFFSET..REPORT_MEASUREMENT_OFFSET + SHA384_LEN];
            let policy_bytes: [u8; 8] = report[REPORT_POLICY_OFFSET..REPORT_POLICY_OFFSET + POLICY_LEN]
                .try_into()
                .map_err(|_| PqRascvError::MeasurementFailed)?;

            let snp_policy = SnpPolicy::from_le_bytes(policy_bytes);
            let policy_flags: u8 = (snp_policy.smt_allowed as u8)
                | ((snp_policy.debug_allowed as u8) << 1)
                | ((snp_policy.migrate_ma_allowed as u8) << 2);

            let mut pcrs = PcrBank::default();
            pcrs.digests[0] = Sha3_256::digest(measurement).into();
            pcrs.digests[1] = Sha3_256::digest(&policy_bytes).into();
            pcrs.digests[2] = Sha3_256::digest(&[policy_flags, snp_policy.abi_major, snp_policy.abi_minor]).into();

            let ai_model_hash: [u8; 32] = match ai_model {
                Some(m) => Sha3_256::digest(m).into(),
                None => [0u8; 32],
            };

            Ok(Measurements { pcrs, firmware_hash: fw_hash, ai_model_hash, event_counter })
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

            // SAFETY:
            // 1. `dev` is a valid, open file descriptor for `/dev/sev-guest`.
            // 2. `SNP_GET_REPORT` is the stable ioctl number from the Linux kernel
            //    SEV-SNP uAPI (include/uapi/linux/sev-guest.h, verified against kernel 6.5).
            //    It is a _IOWR ioctl — the kernel reads `req_data` and writes the attestation
            //    report into the buffer pointed to by `resp_data`. No other memory is accessed.
            // 3. `ioctl_req` is a stack-allocated `SnpGuestRequestIoctl` with `repr(C)` layout
            //    matching the kernel struct. `req_data` and `resp_data` are raw pointers to
            //    `req` and `resp` which are live stack allocations at this call site.
            // 4. All raw pointers are valid for the duration of the ioctl call and are not
            //    aliased. `req` is read-only after initialization; `resp` is write-only.
            // 5. This call does not create data races: all locals are exclusively owned here.
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
            if ioctl_req.exitinfo2 != 0 {
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
            let fw_hash: [u8; 32] = Sha3_256::digest(b"fw").into();
            fake_resp_with_report_data(measurement, policy, fw_hash)
        }

        fn fake_resp_with_report_data(
            measurement: [u8; 48],
            policy: [u8; 8],
            report_data: [u8; 32],
        ) -> [u8; REPORT_LEN] {
            let mut r = [0u8; REPORT_LEN];
            r[MSG_HDR_LEN + REPORT_MEASUREMENT_OFFSET..MSG_HDR_LEN + REPORT_MEASUREMENT_OFFSET + 48]
                .copy_from_slice(&measurement);
            r[MSG_HDR_LEN + REPORT_POLICY_OFFSET..MSG_HDR_LEN + REPORT_POLICY_OFFSET + 8]
                .copy_from_slice(&policy);
            r[MSG_HDR_LEN + REPORT_DATA_OFFSET..MSG_HDR_LEN + REPORT_DATA_OFFSET + 32]
                .copy_from_slice(&report_data);
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
            let fw = b"my-fw";
            let fw_hash: [u8; 32] = Sha3_256::digest(fw).into();
            let resp = fake_resp_with_report_data([0u8; 48], [0u8; 8], fw_hash);
            let m = AmdSevSnpRoT::measurements_from_resp(&resp, fw, None, 0).unwrap();
            let expected: [u8; 32] = Sha3_256::digest(fw).into();
            assert_eq!(m.firmware_hash, expected);
        }

        #[test]
        fn pcrs_2_through_7_are_zero() {
            let resp = fake_resp([0x42u8; 48], [0xBBu8; 8]);
            let m = AmdSevSnpRoT::measurements_from_resp(&resp, b"fw", None, 0).unwrap();
            for slot in 3..8 {
                assert_eq!(m.pcrs.digests[slot], [0u8; 32], "PCR {slot} must be zero");
            }
        }

        #[test]
        fn report_data_binding_rejects_mismatched_fw_hash() {
            // fake_resp pre-populates REPORT_DATA with SHA3-256(b"fw")
            // but we pass b"wrong-firmware" → mismatch → MeasurementFailed
            let resp = fake_resp([0x42u8; 48], [0u8; 8]);
            let result = AmdSevSnpRoT::measurements_from_resp(&resp, b"wrong-firmware", None, 0);
            assert!(
                matches!(result, Err(PqRascvError::MeasurementFailed)),
                "mismatched REPORT_DATA must fail, got {result:?}"
            );
        }

        #[test]
        fn report_data_binding_accepts_matching_fw_hash() {
            let fw = b"correct-firmware";
            let fw_hash: [u8; 32] = Sha3_256::digest(fw).into();
            let resp = fake_resp_with_report_data([0x42u8; 48], [0u8; 8], fw_hash);
            let result = AmdSevSnpRoT::measurements_from_resp(&resp, fw, None, 0);
            assert!(result.is_ok(), "matching REPORT_DATA must succeed, got {result:?}");
        }

        #[test]
        fn snp_policy_debug_not_allowed_decodes_correctly() {
            // bits: SMT_ALLOWED=bit16=1, DEBUG_ALLOWED=bit19=0 → smt_allowed=true, debug_allowed=false
            let policy: u64 = 1u64 << 16;
            let decoded = SnpPolicy::from_le_bytes(policy.to_le_bytes());
            assert!(!decoded.debug_allowed);
            assert!(decoded.smt_allowed);
        }
    }
}

#[cfg(feature = "amd-sev-snp")]
pub use inner::{AmdSevSnpRoT, SnpPolicy};

/// Stub — `amd-sev-snp` feature not compiled in.
#[cfg(not(feature = "amd-sev-snp"))]
pub struct AmdSevSnpRoT;

#[cfg(not(feature = "amd-sev-snp"))]
impl crate::measurement::RoT for AmdSevSnpRoT {
    fn measure(&self) -> Result<crate::measurement::Measurements, crate::error::PqRascvError> {
        Err(crate::error::PqRascvError::BackendUnavailable)
    }
}
