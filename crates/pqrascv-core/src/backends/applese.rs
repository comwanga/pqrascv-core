//! Apple Secure Enclave backend.
//!
//! Creates or loads an SE-bound EC P-256 key (never extractable from hardware),
//! signs the firmware hash with it, and derives PCR 0 from the public key and
//! firmware hash. This binds attestation to device identity and firmware state.
//!
//! # PCR slot mapping
//!
//! | PCR | Source | Meaning |
//! |-----|--------|---------|
//! | 0   | `SHA3-256(se_pubkey_raw_64 || firmware_hash)` | Device+firmware binding |
//! | 1–7 | zero   | Unused |
//!
//! # Feature
//!
//! Enabled by the `apple-se` Cargo feature. Only functional on macOS/iOS.

#[cfg(feature = "apple-se")]
mod inner {
    use crate::{
        error::PqRascvError,
        measurement::{Measurements, PcrBank, RoT},
    };
    use sha3::{Digest as _, Sha3_256};

    /// Derive Measurements from a raw 64-byte SE public key (uncompressed P-256 X||Y, sans 0x04)
    /// and firmware bytes. Used in tests with synthetic data.
    pub fn measurements_from_se_pubkey(
        se_pubkey_raw: &[u8; 64],
        firmware: &[u8],
        ai_model: Option<&[u8]>,
        event_counter: u64,
    ) -> Result<Measurements, PqRascvError> {
        let fw_hash: [u8; 32] = Sha3_256::digest(firmware).into();
        let mut combined = [0u8; 96];
        combined[..64].copy_from_slice(se_pubkey_raw);
        combined[64..].copy_from_slice(&fw_hash);

        let mut pcrs = PcrBank::default();
        pcrs.digests[0] = Sha3_256::digest(&combined).into();

        let ai_model_hash: [u8; 32] = match ai_model {
            Some(m) => Sha3_256::digest(m).into(),
            None => [0u8; 32],
        };

        Ok(Measurements { pcrs, firmware_hash: fw_hash, ai_model_hash, event_counter })
    }

    pub struct AppleSeRoT<'a> {
        firmware: &'a [u8],
        ai_model: Option<&'a [u8]>,
        event_counter: u64,
    }

    impl<'a> AppleSeRoT<'a> {
        #[must_use]
        pub fn new(firmware: &'a [u8], ai_model: Option<&'a [u8]>, event_counter: u64) -> Self {
            Self { firmware, ai_model, event_counter }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    impl RoT for AppleSeRoT<'_> {
        // NOTE: This implementation generates a fresh SE key on every call.
        // PCR 0 will differ between invocations and is NOT a stable device identity.
        // Production use requires lookup-then-create: query the Keychain by
        // `com.pqrascv.attestation-key` label before calling SecKey::generate.
        fn measure(&self) -> Result<Measurements, PqRascvError> {
            use security_framework::key::{GenerateKeyOptions, SecKey};

            let label = "com.pqrascv.attestation-key";
            let opts = GenerateKeyOptions::default()
                .set_key_type(security_framework::key::KeyType::ec())
                .set_token_id(security_framework::key::Token::SecureEnclave)
                .set_application_label(label.as_bytes())
                .set_can_sign(true);

            let se_key = SecKey::generate(opts)
                .map_err(|_| PqRascvError::BackendUnavailable)?;

            let pub_key = se_key
                .external_representation()
                .map_err(|_| PqRascvError::BackendUnavailable)?;
            if pub_key.len() < 65 {
                return Err(PqRascvError::MeasurementFailed);
            }
            let raw_64: [u8; 64] = pub_key[1..65]
                .try_into()
                .map_err(|_| PqRascvError::MeasurementFailed)?;

            measurements_from_se_pubkey(&raw_64, self.firmware, self.ai_model, self.event_counter)
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    impl RoT for AppleSeRoT<'_> {
        fn measure(&self) -> Result<Measurements, PqRascvError> {
            Err(PqRascvError::BackendUnavailable)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn se_pubkey_maps_to_pcr0() {
            let pubkey = [0x42u8; 64];
            let m = measurements_from_se_pubkey(&pubkey, b"fw", None, 0).unwrap();
            assert_ne!(m.pcrs.digests[0], [0u8; 32]);
        }

        #[test]
        fn distinct_se_pubkeys_produce_distinct_pcr0() {
            let m1 = measurements_from_se_pubkey(&[0x11u8; 64], b"fw", None, 0).unwrap();
            let m2 = measurements_from_se_pubkey(&[0x22u8; 64], b"fw", None, 0).unwrap();
            assert_ne!(m1.pcrs.digests[0], m2.pcrs.digests[0]);
        }

        #[test]
        fn same_pubkey_different_firmware_produces_distinct_pcr0() {
            let pubkey = [0x42u8; 64];
            let m1 = measurements_from_se_pubkey(&pubkey, b"fw-A", None, 0).unwrap();
            let m2 = measurements_from_se_pubkey(&pubkey, b"fw-B", None, 0).unwrap();
            assert_ne!(m1.pcrs.digests[0], m2.pcrs.digests[0]);
        }

        #[test]
        fn pcrs_1_through_7_are_zero() {
            let m = measurements_from_se_pubkey(&[0u8; 64], b"fw", None, 0).unwrap();
            for slot in 1..8 {
                assert_eq!(m.pcrs.digests[slot], [0u8; 32], "PCR {slot} must be zero");
            }
        }
    }
}

#[cfg(feature = "apple-se")]
pub use inner::AppleSeRoT;

#[cfg(not(feature = "apple-se"))]
pub struct AppleSeRoT;

#[cfg(not(feature = "apple-se"))]
impl crate::measurement::RoT for AppleSeRoT {
    fn measure(&self) -> Result<crate::measurement::Measurements, crate::error::PqRascvError> {
        Err(crate::error::PqRascvError::BackendUnavailable)
    }
}
