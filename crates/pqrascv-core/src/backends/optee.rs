//! OP-TEE (Open Portable Trusted Execution Environment) backend.
//!
//! Connects to an attestation Trusted Application (TA) via the Linux TEE
//! character device `/dev/tee0`, retrieves a 32-byte measurement from the TA,
//! and maps it into PCR 0.
//!
//! # PCR slot mapping
//!
//! | PCR | Source | Meaning |
//! |-----|--------|---------|
//! | 0   | `SHA3-256(ta_measurement || firmware_hash)` | TA-attested measurement |
//! | 1–7 | zero   | Unused |
//!
//! # Feature
//!
//! Enabled by the `op-tee` Cargo feature.

#[cfg(feature = "op-tee")]
mod inner {
    use crate::{
        error::PqRascvError,
        measurement::{Measurements, PcrBank, RoT},
    };
    use sha3::{Digest as _, Sha3_256};

    pub(super) const TA_MEASUREMENT_LEN: usize = 32;

    /// Parse a 32-byte TA measurement into Measurements.
    pub fn measurements_from_ta_output(
        ta_measurement: &[u8; TA_MEASUREMENT_LEN],
        firmware: &[u8],
        ai_model: Option<&[u8]>,
        event_counter: u64,
    ) -> Result<Measurements, PqRascvError> {
        let fw_hash: [u8; 32] = Sha3_256::digest(firmware).into();
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(ta_measurement);
        combined[32..].copy_from_slice(&fw_hash);

        let mut pcrs = PcrBank::default();
        pcrs.digests[0] = Sha3_256::digest(&combined).into();

        let ai_model_hash: [u8; 32] = match ai_model {
            Some(m) => Sha3_256::digest(m).into(),
            None => [0u8; 32],
        };

        Ok(Measurements {
            pcrs,
            firmware_hash: fw_hash,
            ai_model_hash,
            event_counter,
        })
    }

    pub struct OpTeeRoT<'a> {
        #[cfg(target_os = "linux")]
        firmware: &'a [u8],
        #[cfg(target_os = "linux")]
        ai_model: Option<&'a [u8]>,
        #[cfg(target_os = "linux")]
        event_counter: u64,
        #[cfg(not(target_os = "linux"))]
        _phantom: core::marker::PhantomData<&'a ()>,
    }

    impl<'a> OpTeeRoT<'a> {
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
    }

    #[cfg(target_os = "linux")]
    impl RoT for OpTeeRoT<'_> {
        fn measure(&self) -> Result<Measurements, PqRascvError> {
            use std::fs::OpenOptions;
            use std::os::unix::io::AsRawFd;

            // TEE_IOC_VERSION = _IOR(0xa4, 0xa, struct tee_ioversion)
            // struct tee_ioversion { u32 impl_id; u32 impl_caps; u32 gen_caps } = 12 bytes
            const TEE_IOC_VERSION: u64 = 0x800c_a40a;
            const OPTEE_IMPL_ID: u32 = 1;

            #[repr(C)]
            struct TeeIoVersion {
                impl_id: u32,
                impl_caps: u32,
                gen_caps: u32,
            }

            let dev = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tee0")
                .map_err(|_| PqRascvError::BackendUnavailable)?;

            let mut version = TeeIoVersion {
                impl_id: 0,
                impl_caps: 0,
                gen_caps: 0,
            };

            // SAFETY:
            // 1. `dev` is a valid, open file descriptor for `/dev/tee0`.
            // 2. `TEE_IOC_VERSION` (0x800c_a40a) is the stable read ioctl from
            //    include/uapi/linux/tee.h (_IOR(0xa4, 0xa, struct tee_ioversion)),
            //    verified against Linux kernel 6.5. The kernel reads `impl_id` into the
            //    struct and returns 0 on success.
            // 3. `version` is a stack-allocated repr(C) struct matching the kernel layout.
            //    The pointer is valid and not aliased for the duration of the ioctl.
            let ret = unsafe {
                libc::ioctl(
                    dev.as_raw_fd(),
                    TEE_IOC_VERSION,
                    &mut version as *mut TeeIoVersion,
                )
            };
            if ret != 0 || version.impl_id != OPTEE_IMPL_ID {
                return Err(PqRascvError::BackendUnavailable);
            }

            // Full TA session (TEE_IOC_OPEN_SESSION + TEE_IOC_INVOKE) not yet implemented.
            Err(PqRascvError::BackendUnavailable)
        }
    }

    #[cfg(not(target_os = "linux"))]
    impl RoT for OpTeeRoT<'_> {
        fn measure(&self) -> Result<Measurements, PqRascvError> {
            Err(PqRascvError::BackendUnavailable)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn ta_output_maps_to_pcr0() {
            let ta_meas = [0x42u8; TA_MEASUREMENT_LEN];
            let m = measurements_from_ta_output(&ta_meas, b"fw", None, 0).unwrap();
            assert_ne!(m.pcrs.digests[0], [0u8; 32], "PCR 0 must be non-zero");
        }

        #[test]
        fn distinct_ta_outputs_produce_distinct_pcr0() {
            let m1 = measurements_from_ta_output(&[0x11u8; 32], b"fw", None, 0).unwrap();
            let m2 = measurements_from_ta_output(&[0x22u8; 32], b"fw", None, 0).unwrap();
            assert_ne!(m1.pcrs.digests[0], m2.pcrs.digests[0]);
        }

        #[test]
        fn same_ta_output_different_firmware_produces_distinct_pcr0() {
            let ta_meas = [0x42u8; 32];
            let m1 = measurements_from_ta_output(&ta_meas, b"fw-A", None, 0).unwrap();
            let m2 = measurements_from_ta_output(&ta_meas, b"fw-B", None, 0).unwrap();
            assert_ne!(m1.pcrs.digests[0], m2.pcrs.digests[0]);
        }

        #[test]
        fn pcrs_1_through_7_are_zero() {
            let m = measurements_from_ta_output(&[0u8; 32], b"fw", None, 0).unwrap();
            for slot in 1..8 {
                assert_eq!(m.pcrs.digests[slot], [0u8; 32], "PCR {slot} must be zero");
            }
        }
    }
}

#[cfg(feature = "op-tee")]
pub use inner::OpTeeRoT;

#[cfg(not(feature = "op-tee"))]
pub struct OpTeeRoT;

#[cfg(not(feature = "op-tee"))]
impl crate::measurement::RoT for OpTeeRoT {
    fn measure(&self) -> Result<crate::measurement::Measurements, crate::error::PqRascvError> {
        Err(crate::error::PqRascvError::BackendUnavailable)
    }
}
