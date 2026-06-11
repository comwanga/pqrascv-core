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
    use subtle::ConstantTimeEq;

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
        #[must_use]
        pub fn from_le_bytes(policy: [u8; 8]) -> Self {
            let bits = u64::from_le_bytes(policy);
            Self {
                abi_minor: (bits & 0xFF) as u8,
                abi_major: ((bits >> 8) & 0xFF) as u8,
                smt_allowed: (bits >> 16) & 1 == 1,
                migrate_ma_allowed: (bits >> 18) & 1 == 1,
                debug_allowed: (bits >> 19) & 1 == 1,
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
            let report_data_fw =
                &report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_FW_HASH_LEN];
            if report_data_fw.ct_eq(fw_hash.as_ref()).unwrap_u8() == 0 {
                return Err(PqRascvError::MeasurementFailed);
            }

            let measurement =
                &report[REPORT_MEASUREMENT_OFFSET..REPORT_MEASUREMENT_OFFSET + SHA384_LEN];
            let policy_bytes: [u8; 8] = report
                [REPORT_POLICY_OFFSET..REPORT_POLICY_OFFSET + POLICY_LEN]
                .try_into()
                .map_err(|_| PqRascvError::MeasurementFailed)?;

            let snp_policy = SnpPolicy::from_le_bytes(policy_bytes);
            let policy_flags: u8 = u8::from(snp_policy.smt_allowed)
                | (u8::from(snp_policy.debug_allowed) << 1)
                | (u8::from(snp_policy.migrate_ma_allowed) << 2);

            let mut pcrs = PcrBank::default();
            pcrs.digests[0] = Sha3_256::digest(measurement).into();
            pcrs.digests[1] = Sha3_256::digest(policy_bytes).into();
            pcrs.digests[2] =
                Sha3_256::digest([policy_flags, snp_policy.abi_major, snp_policy.abi_minor]).into();

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

    //
    // The collector above (`measure`) only extracts measurements; it performs no
    // cryptographic verification. Genuine remote attestation requires verifying
    // that the report was signed by AMD silicon: the report carries an ECDSA
    // P-384 signature by the VCEK, whose certificate chains VCEK → ASK → ARK up
    // to AMD's pinned root. This section adds that verification.

    use p384::ecdsa::{signature::Verifier as _, Signature as P384Signature, VerifyingKey};

    /// Offset of the SIGNATURE field within the SNP attestation report; also the
    /// length of the signed region (the report is signed over bytes
    /// `[0, REPORT_SIG_OFFSET)`).
    ///
    /// Source: AMD SEV-SNP ABI Specification (Rev 1.55) §7.3,
    /// `ATTESTATION_REPORT.SIGNATURE` at byte offset 0x2A0.
    const REPORT_SIG_OFFSET: usize = 0x2A0;
    /// Each ECDSA component (`r`, `s`) occupies a 72-byte little-endian field in
    /// the report SIGNATURE; for P-384 only the low 48 bytes are significant.
    const SIG_COMPONENT_FIELD: usize = 72;
    /// Byte length of a P-384 scalar.
    const P384_SCALAR_LEN: usize = 48;

    /// Errors from SEV-SNP attestation verification.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SevSnpVerifyError {
        /// The report buffer is too short to contain a signature.
        MalformedReport,
        /// The VCEK public key could not be decoded as an uncompressed P-384 point.
        MalformedVcekKey,
        /// The report signature did not verify under the VCEK public key.
        ReportSignatureInvalid,
        /// A certificate (VCEK, ASK, or ARK) could not be parsed as DER X.509,
        /// or a contained public key could not be decoded.
        CertParse,
        /// A certificate's signature did not verify under its issuer's public key.
        ChainSignatureInvalid,
        /// The supplied ARK's `SubjectPublicKeyInfo` did not match the pinned root.
        UntrustedRoot,
        /// A certificate's `notAfter` is before the supplied verification time.
        CertExpired,
        /// A certificate's `notBefore` is after the supplied verification time.
        CertNotYetValid,
        /// A certificate's signature algorithm is not a supported AMD algorithm
        /// (RSASSA-PSS with SHA-384).
        UnsupportedSignatureAlgorithm,
    }

    /// Verifies the ECDSA P-384 signature embedded in an SNP attestation
    /// `report` against the VCEK public key (uncompressed SEC1 encoding).
    ///
    /// The signed region is `report[0..0x2A0]`. The signature is two 72-byte
    /// little-endian fields (`r`, then `s`) starting at 0x2A0, of which the low
    /// 48 bytes of each are the P-384 scalars (FIPS 186-4 ECDSA, SHA-384).
    ///
    /// Returns `Ok(())` only if the signature is valid. This authenticates the
    /// *report contents* against a key; binding that key to AMD requires the
    /// certificate-chain check (VCEK → ASK → ARK), performed separately.
    pub fn verify_report_signature(
        report: &[u8],
        vcek_pubkey_sec1: &[u8],
    ) -> Result<(), SevSnpVerifyError> {
        if report.len() < REPORT_SIG_OFFSET + 2 * SIG_COMPONENT_FIELD {
            return Err(SevSnpVerifyError::MalformedReport);
        }
        let signed = &report[..REPORT_SIG_OFFSET];

        // r and s are stored little-endian; convert the low 48 bytes of each to
        // the big-endian r‖s layout the `ecdsa` crate expects.
        let r_le = &report[REPORT_SIG_OFFSET..REPORT_SIG_OFFSET + P384_SCALAR_LEN];
        let s_start = REPORT_SIG_OFFSET + SIG_COMPONENT_FIELD;
        let s_le = &report[s_start..s_start + P384_SCALAR_LEN];

        let mut sig_be = [0u8; 2 * P384_SCALAR_LEN];
        for (i, b) in r_le.iter().enumerate() {
            sig_be[P384_SCALAR_LEN - 1 - i] = *b;
        }
        for (i, b) in s_le.iter().enumerate() {
            sig_be[2 * P384_SCALAR_LEN - 1 - i] = *b;
        }

        let signature = P384Signature::from_slice(&sig_be)
            .map_err(|_| SevSnpVerifyError::ReportSignatureInvalid)?;
        let vk = VerifyingKey::from_sec1_bytes(vcek_pubkey_sec1)
            .map_err(|_| SevSnpVerifyError::MalformedVcekKey)?;
        vk.verify(signed, &signature)
            .map_err(|_| SevSnpVerifyError::ReportSignatureInvalid)
    }

    //
    // AMD's trust chain: the report is signed by the VCEK; the VCEK X.509 cert
    // (ECDSA P-384 subject key) is signed by the ASK; the ASK cert (RSA) is
    // signed by the ARK; the ARK cert (RSA) is self-signed and is AMD's root.
    // All cert signatures are RSASSA-PSS with SHA-384 (MGF1-SHA-384, salt 48).

    use der::{Decode as _, Encode as _};
    use rsa::pss::Pss;
    use rsa::RsaPublicKey;
    use sha2::Sha384; // `Digest` trait is already in scope via the sha3 import above.
    use x509_cert::spki::{DecodePublicKey as _, ObjectIdentifier};
    use x509_cert::Certificate;

    /// OID for `id-RSASSA-PSS` (1.2.840.113549.1.1.10), the only certificate
    /// signature algorithm AMD's SEV-SNP PKI uses.
    const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
    /// OID for `id-ecPublicKey` (1.2.840.10045.2.1) — the VCEK subject key type.
    const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

    /// AMD cert signatures use SHA-384 with a 48-byte salt (= digest length),
    /// per the AMD KDS-issued ARK/ASK/VCEK certificates.
    const PSS_SALT_LEN: usize = 48;

    /// A verified SNP attestation: returned only after the full VCEK → ASK → ARK
    /// chain, the root pin, all validity windows, and the report signature have
    /// been checked. The fields are copied out of the now-trusted report.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VerifiedSnpReport {
        /// The 48-byte launch measurement (`report[0x090..0x0D8]`).
        pub measurement: Vec<u8>,
        /// The 64-byte `REPORT_DATA` field (`report[0x050..0x090]`).
        pub report_data: Vec<u8>,
    }

    /// Verifies that `cert`'s signature is a valid RSASSA-PSS-SHA384 signature
    /// by `issuer_rsa`, computed over `cert`'s re-encoded `tbs_certificate`.
    ///
    /// Dispatches on the certificate's `signature_algorithm`; only
    /// RSASSA-PSS-SHA384 is supported (AMD's only cert signature algorithm).
    fn verify_cert_signature(
        cert: &Certificate,
        issuer_rsa: &RsaPublicKey,
    ) -> Result<(), SevSnpVerifyError> {
        // The signature algorithm in the outer Certificate and the one inside
        // the TBS MUST match (RFC 5280 §4.1.1.2). Reject if they diverge.
        if cert.signature_algorithm.oid != cert.tbs_certificate.signature.oid {
            return Err(SevSnpVerifyError::ChainSignatureInvalid);
        }
        if cert.signature_algorithm.oid != ID_RSASSA_PSS {
            return Err(SevSnpVerifyError::UnsupportedSignatureAlgorithm);
        }

        // Re-encode the parsed TBS to DER; this is the exact byte string the
        // issuer signed.
        let tbs_der = cert
            .tbs_certificate
            .to_der()
            .map_err(|_| SevSnpVerifyError::CertParse)?;

        let sig = cert
            .signature
            .as_bytes()
            .ok_or(SevSnpVerifyError::ChainSignatureInvalid)?;

        // SHA-384 prehash, then PSS verify (MGF1-SHA-384, salt = 48).
        let hashed = Sha384::digest(&tbs_der);
        issuer_rsa
            .verify(Pss::new_with_salt::<Sha384>(PSS_SALT_LEN), &hashed, sig)
            .map_err(|_| SevSnpVerifyError::ChainSignatureInvalid)
    }

    /// Returns `Ok(())` iff `now_unix` is within `[notBefore, notAfter]` of the
    /// certificate's validity window.
    fn check_validity(cert: &Certificate, now_unix: u64) -> Result<(), SevSnpVerifyError> {
        let not_before = cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let not_after = cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();
        if now_unix < not_before {
            return Err(SevSnpVerifyError::CertNotYetValid);
        }
        if now_unix > not_after {
            return Err(SevSnpVerifyError::CertExpired);
        }
        Ok(())
    }

    /// Extracts an [`RsaPublicKey`] from a certificate's `subjectPublicKeyInfo`.
    fn cert_rsa_pubkey(cert: &Certificate) -> Result<RsaPublicKey, SevSnpVerifyError> {
        // Re-encode the SPKI and decode it as an RSA public key.
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| SevSnpVerifyError::CertParse)?;
        RsaPublicKey::from_public_key_der(&spki_der).map_err(|_| SevSnpVerifyError::CertParse)
    }

    /// Extracts the VCEK P-384 public key as uncompressed SEC1 bytes from the
    /// VCEK certificate's `subjectPublicKeyInfo`.
    fn vcek_sec1_pubkey(cert: &Certificate) -> Result<Vec<u8>, SevSnpVerifyError> {
        let spki = &cert.tbs_certificate.subject_public_key_info;
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(SevSnpVerifyError::CertParse);
        }
        // For id-ecPublicKey the subjectPublicKey BIT STRING is the raw SEC1
        // point (uncompressed: 0x04 || X || Y). Hand the raw bytes to the
        // existing P-384 verifier, which decodes them with from_sec1_bytes.
        spki.subject_public_key
            .as_bytes()
            .map(<[u8]>::to_vec)
            .ok_or(SevSnpVerifyError::CertParse)
    }

    /// SHA-384 over a certificate's DER-encoded `subjectPublicKeyInfo` — the
    /// value pinned for AMD's root (ARK).
    fn spki_sha384(cert: &Certificate) -> Result<[u8; 48], SevSnpVerifyError> {
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| SevSnpVerifyError::CertParse)?;
        Ok(Sha384::digest(&spki_der).into())
    }

    /// Full SEV-SNP remote-attestation verification.
    ///
    /// `report` is the SNP attestation report whose byte 0 is the report start
    /// (i.e. *post* the kernel `MSG_HDR`, the same convention as
    /// [`verify_report_signature`], which signs over `report[0..0x2A0]`).
    ///
    /// Verifies, in order:
    /// 1. all three certificates parse as DER X.509;
    /// 2. the supplied ARK's `subjectPublicKeyInfo` SHA-384 equals
    ///    `pinned_ark_spki_sha384` (root pinning → [`SevSnpVerifyError::UntrustedRoot`]);
    /// 3. the ASK certificate is signed by the ARK, and the VCEK certificate is
    ///    signed by the ASK (RSASSA-PSS-SHA384 chain signatures);
    /// 4. all three certificates' validity windows contain `now_unix`;
    /// 5. the report's ECDSA-P384 signature verifies under the VCEK key.
    ///
    /// On success returns the verified `measurement` and `report_data`.
    // `ask`/`ark` (and `ask_rsa`/`ark_rsa`) are AMD's standard component names
    // for the SEV Signing Key and AMD Root Key; keeping them verbatim aids
    // cross-referencing AMD's spec, so we silence `similar_names` here.
    #[allow(clippy::similar_names)]
    pub fn verify_snp_attestation(
        report: &[u8],
        vcek_der: &[u8],
        ask_der: &[u8],
        ark_der: &[u8],
        pinned_ark_spki_sha384: &[u8; 48],
        now_unix: u64,
    ) -> Result<VerifiedSnpReport, SevSnpVerifyError> {
        // 1. Parse all three certificates.
        let vcek = Certificate::from_der(vcek_der).map_err(|_| SevSnpVerifyError::CertParse)?;
        let ask = Certificate::from_der(ask_der).map_err(|_| SevSnpVerifyError::CertParse)?;
        let ark = Certificate::from_der(ark_der).map_err(|_| SevSnpVerifyError::CertParse)?;

        // 2. Root pinning: the supplied ARK must be the pinned AMD root.
        let ark_spki_hash = spki_sha384(&ark)?;
        if ark_spki_hash
            .ct_eq(pinned_ark_spki_sha384.as_ref())
            .unwrap_u8()
            == 0
        {
            return Err(SevSnpVerifyError::UntrustedRoot);
        }

        // 3. Chain signatures: ARK signs ASK, ASK signs VCEK.
        let ark_rsa = cert_rsa_pubkey(&ark)?;
        verify_cert_signature(&ask, &ark_rsa)?;
        let ask_rsa = cert_rsa_pubkey(&ask)?;
        verify_cert_signature(&vcek, &ask_rsa)?;

        // 4. Validity windows.
        check_validity(&ark, now_unix)?;
        check_validity(&ask, now_unix)?;
        check_validity(&vcek, now_unix)?;

        // 5. Report signature under the VCEK key.
        let vcek_sec1 = vcek_sec1_pubkey(&vcek)?;
        verify_report_signature(report, &vcek_sec1)?;

        // Extract trusted fields. `report` byte 0 is the report start, so the
        // offsets below are the post-header offsets used elsewhere in this file.
        if report.len() < REPORT_MEASUREMENT_OFFSET + SHA384_LEN {
            return Err(SevSnpVerifyError::MalformedReport);
        }
        let measurement =
            report[REPORT_MEASUREMENT_OFFSET..REPORT_MEASUREMENT_OFFSET + SHA384_LEN].to_vec();
        // REPORT_DATA is 64 bytes ([0x050..0x090]).
        let report_data = report[REPORT_DATA_OFFSET..REPORT_MEASUREMENT_OFFSET].to_vec();

        Ok(VerifiedSnpReport {
            measurement,
            report_data,
        })
    }

    #[cfg(test)]
    mod tests {
        // Synthetic-PKI helpers use AMD's verbatim component names (ARK/ASK) and
        // spec identifiers in doc comments; these style lints are noise here.
        #![allow(clippy::similar_names, clippy::doc_markdown)]
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
            r[MSG_HDR_LEN + REPORT_MEASUREMENT_OFFSET
                ..MSG_HDR_LEN + REPORT_MEASUREMENT_OFFSET + 48]
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
        fn pcrs_3_through_7_are_zero() {
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
            assert!(
                result.is_ok(),
                "matching REPORT_DATA must succeed, got {result:?}"
            );
        }

        #[test]
        fn snp_policy_debug_not_allowed_decodes_correctly() {
            // Policy: ABI_MINOR=3, ABI_MAJOR=2, SMT_ALLOWED=bit16=1, DEBUG=bit19=0
            let policy: u64 = 3u64        // ABI_MINOR in bits 7:0
                | (2u64 << 8)            // ABI_MAJOR in bits 15:8
                | (1u64 << 16); // SMT_ALLOWED in bit 16
            let decoded = SnpPolicy::from_le_bytes(policy.to_le_bytes());
            assert_eq!(decoded.abi_minor, 3);
            assert_eq!(decoded.abi_major, 2);
            assert!(!decoded.debug_allowed);
            assert!(decoded.smt_allowed);
        }

        // ── Report signature verification tests ──────────────────────────────
        //
        // These exercise the verification LOGIC (signature parsing, LE→BE scalar
        // conversion, ECDSA-P384 verify) using a synthetic VCEK key. Byte-exact
        // agreement with real AMD silicon additionally depends on the ABI offset
        // constants, which are documented against the SEV-SNP spec but should be
        // re-confirmed against a real attestation vector when one is available.

        use p384::ecdsa::{signature::Signer as _, SigningKey};

        /// Deterministic P-384 signer for tests (fixed scalar, no RNG needed).
        fn test_vcek() -> (SigningKey, Vec<u8>) {
            let sk = SigningKey::from_slice(&[0x11u8; 48]).unwrap();
            let vk_sec1 = sk
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            (sk, vk_sec1)
        }

        /// Builds a report whose `[0, 0x2A0)` region is `signed_region`, signed
        /// by `sk` and encoded into the little-endian SIGNATURE fields exactly
        /// as `verify_report_signature` expects to decode them.
        fn synthetic_signed_report(
            signed_region: &[u8; REPORT_SIG_OFFSET],
            sk: &SigningKey,
        ) -> Vec<u8> {
            let sig: P384Signature = sk.sign(signed_region);
            let be = sig.to_bytes(); // 96 bytes, r‖s big-endian
            let mut report = vec![0u8; REPORT_SIG_OFFSET + 2 * SIG_COMPONENT_FIELD];
            report[..REPORT_SIG_OFFSET].copy_from_slice(signed_region);
            for (i, b) in be[..P384_SCALAR_LEN].iter().enumerate() {
                report[REPORT_SIG_OFFSET + (P384_SCALAR_LEN - 1 - i)] = *b;
            }
            for (i, b) in be[P384_SCALAR_LEN..].iter().enumerate() {
                report[REPORT_SIG_OFFSET + SIG_COMPONENT_FIELD + (P384_SCALAR_LEN - 1 - i)] = *b;
            }
            report
        }

        #[test]
        fn valid_report_signature_verifies() {
            let (sk, vk) = test_vcek();
            let region = [0xAAu8; REPORT_SIG_OFFSET];
            let report = synthetic_signed_report(&region, &sk);
            assert!(verify_report_signature(&report, &vk).is_ok());
        }

        #[test]
        fn forged_report_body_is_rejected() {
            let (sk, vk) = test_vcek();
            let region = [0xAAu8; REPORT_SIG_OFFSET];
            let mut report = synthetic_signed_report(&region, &sk);
            report[10] ^= 0xFF; // tamper the signed region after signing
            assert_eq!(
                verify_report_signature(&report, &vk),
                Err(SevSnpVerifyError::ReportSignatureInvalid)
            );
        }

        #[test]
        fn report_signed_by_wrong_key_is_rejected() {
            let (sk, _vk) = test_vcek();
            let other = SigningKey::from_slice(&[0x22u8; 48]).unwrap();
            let other_vk = other
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            let region = [0xAAu8; REPORT_SIG_OFFSET];
            let report = synthetic_signed_report(&region, &sk);
            assert_eq!(
                verify_report_signature(&report, &other_vk),
                Err(SevSnpVerifyError::ReportSignatureInvalid)
            );
        }

        #[test]
        fn truncated_report_is_malformed() {
            let (_sk, vk) = test_vcek();
            let short = [0u8; REPORT_SIG_OFFSET]; // no signature field present
            assert_eq!(
                verify_report_signature(&short, &vk),
                Err(SevSnpVerifyError::MalformedReport)
            );
        }

        #[test]
        fn malformed_vcek_key_is_rejected() {
            let (sk, _vk) = test_vcek();
            let region = [0xAAu8; REPORT_SIG_OFFSET];
            let report = synthetic_signed_report(&region, &sk);
            assert_eq!(
                verify_report_signature(&report, &[0u8; 10]),
                Err(SevSnpVerifyError::MalformedVcekKey)
            );
        }

        // ── Certificate-chain validation tests ───────────────────────────────
        //
        // Synthetic AMD-style PKI: ARK (RSA self-signed) → ASK (RSA, signed by
        // ARK) → VCEK (ECDSA P-384, signed by ASK). All cert signatures are
        // RSASSA-PSS-SHA384 (salt 48), matching the production verification
        // path. RSA-2048 is used (not 4096) purely to keep key generation fast;
        // the verifier is key-size agnostic.
        //
        // Certificates are built directly from `x509-cert`/`der`/`spki` types
        // already in the dependency graph (no extra dev-dependency such as
        // rcgen is needed): we assemble the TBSCertificate, DER-encode it, sign
        // the encoding with RSA-PSS-SHA384, and wrap it as a Certificate.

        use der::asn1::BitString;
        use rsa::pss::Pss;
        use rsa::rand_core::{CryptoRng, RngCore};
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use sha2::Sha384;
        use std::str::FromStr as _;
        use x509_cert::certificate::{TbsCertificate, Version};
        use x509_cert::der::asn1::GeneralizedTime;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::{
            AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned,
        };
        use x509_cert::time::{Time, Validity};
        use x509_cert::Certificate;

        const ID_RSASSA_PSS: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        const ID_EC_PUBLIC_KEY: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
        const SECP_384_R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
        const PSS_SALT_LEN: usize = 48;

        /// Deterministic, reproducible RNG for fast RSA key generation in tests.
        ///
        /// SHA3-256 in counter mode over a fixed seed. NOT cryptographically
        /// strong, but `RsaPrivateKey::new` only needs enough entropy to find
        /// primes; reproducibility keeps tests deterministic and avoids pulling
        /// in OS entropy. The `CryptoRng` marker is asserted solely to satisfy
        /// the `rsa` API bound — this RNG is test-only.
        struct CounterRng {
            state: [u8; 32],
            buf: [u8; 32],
            pos: usize,
        }

        impl CounterRng {
            fn seeded(seed: u64) -> Self {
                let mut state = [0u8; 32];
                state[..8].copy_from_slice(&seed.to_le_bytes());
                Self {
                    state,
                    buf: [0u8; 32],
                    pos: 32,
                }
            }
            fn refill(&mut self) {
                use sha3::{Digest as _, Sha3_256};
                self.buf = Sha3_256::digest(self.state).into();
                // bump counter
                for b in &mut self.state {
                    *b = b.wrapping_add(1);
                    if *b != 0 {
                        break;
                    }
                }
                self.pos = 0;
            }
        }

        impl RngCore for CounterRng {
            fn next_u32(&mut self) -> u32 {
                let mut b = [0u8; 4];
                self.fill_bytes(&mut b);
                u32::from_le_bytes(b)
            }
            fn next_u64(&mut self) -> u64 {
                let mut b = [0u8; 8];
                self.fill_bytes(&mut b);
                u64::from_le_bytes(b)
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                for d in dest.iter_mut() {
                    if self.pos >= self.buf.len() {
                        self.refill();
                    }
                    *d = self.buf[self.pos];
                    self.pos += 1;
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl CryptoRng for CounterRng {}

        /// The PSS AlgorithmIdentifier our verifier recognizes. Our verifier
        /// dispatches on the OID only and assumes SHA-384/salt-48, so we encode
        /// `parameters: None`. Real AMD certs carry full RSASSA-PSS-params; this
        /// is noted in the task report as a place needing real-vector
        /// confirmation of the exact MGF1/salt encoding.
        fn pss_alg_id() -> AlgorithmIdentifierOwned {
            AlgorithmIdentifierOwned {
                oid: ID_RSASSA_PSS,
                parameters: None,
            }
        }

        /// Build an EC P-384 SubjectPublicKeyInfo from an uncompressed SEC1 point.
        fn ec_p384_spki(sec1_uncompressed: &[u8]) -> SubjectPublicKeyInfoOwned {
            // parameters = secp384r1 named curve OID, encoded as an `Any`.
            let curve_any = der::Any::from_der(&SECP_384_R1.to_der().unwrap()).unwrap();
            SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: ID_EC_PUBLIC_KEY,
                    parameters: Some(curve_any),
                },
                subject_public_key: BitString::from_bytes(sec1_uncompressed).unwrap(),
            }
        }

        /// Build an RSA SubjectPublicKeyInfo (PKCS#1 RSAPublicKey inside the
        /// standard rsaEncryption SPKI) from a public key.
        fn rsa_spki(pk: &RsaPublicKey) -> SubjectPublicKeyInfoOwned {
            use rsa::pkcs8::EncodePublicKey as _;
            let der = pk.to_public_key_der().unwrap();
            SubjectPublicKeyInfoOwned::from_der(der.as_bytes()).unwrap()
        }

        /// notBefore/notAfter as unix seconds → Validity.
        fn validity(not_before: u64, not_after: u64) -> Validity {
            use core::time::Duration;
            let nb = GeneralizedTime::from_unix_duration(Duration::from_secs(not_before)).unwrap();
            let na = GeneralizedTime::from_unix_duration(Duration::from_secs(not_after)).unwrap();
            Validity {
                not_before: Time::GeneralTime(nb),
                not_after: Time::GeneralTime(na),
            }
        }

        /// Assemble + RSA-PSS-SHA384-sign a certificate. `issuer_sk` signs the
        /// TBS; `spki` is the subject's public key info.
        fn make_cert(
            serial: u64,
            subject: &str,
            issuer: &str,
            spki: SubjectPublicKeyInfoOwned,
            valid: Validity,
            issuer_sk: &RsaPrivateKey,
            rng: &mut CounterRng,
        ) -> Vec<u8> {
            let tbs = TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(&serial.to_be_bytes()).unwrap(),
                signature: pss_alg_id(),
                issuer: Name::from_str(issuer).unwrap(),
                validity: valid,
                subject: Name::from_str(subject).unwrap(),
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: None,
            };
            let tbs_der = tbs.to_der().unwrap();
            let hashed = Sha384::digest(&tbs_der);
            let sig = issuer_sk
                .sign_with_rng(rng, Pss::new_with_salt::<Sha384>(PSS_SALT_LEN), &hashed)
                .unwrap();
            let cert = Certificate {
                tbs_certificate: tbs,
                signature_algorithm: pss_alg_id(),
                signature: BitString::from_bytes(&sig).unwrap(),
            };
            cert.to_der().unwrap()
        }

        /// A fully assembled synthetic SNP attestation: the DER for each cert,
        /// the signed report, the pinned ARK SPKI hash, and the embedded
        /// measurement / report_data.
        struct SyntheticChain {
            vcek_der: Vec<u8>,
            ask_der: Vec<u8>,
            ark_der: Vec<u8>,
            report: Vec<u8>,
            pinned_ark: [u8; 48],
            measurement: [u8; 48],
            report_data: [u8; 64],
            now: u64,
        }

        /// Builds a valid chain. `vcek_issuer_sk` lets a test sign the VCEK with
        /// a key OTHER than the ASK (to exercise the broken-link path).
        fn build_chain(
            vcek_not_before: u64,
            vcek_not_after: u64,
            vcek_issuer_sk: Option<&RsaPrivateKey>,
        ) -> SyntheticChain {
            let mut rng = CounterRng::seeded(0xC0_FFEE);
            // RSA-2048 ARK (self-signed) and ASK (signed by ARK).
            let ark_sk = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let ask_sk = RsaPrivateKey::new(&mut rng, 2048).unwrap();

            let now: u64 = 1_700_000_000;
            let wide = validity(now - 1000, now + 1_000_000);

            // ARK self-signed.
            let ark_der = make_cert(
                1,
                "CN=ARK",
                "CN=ARK",
                rsa_spki(&RsaPublicKey::from(&ark_sk)),
                wide,
                &ark_sk,
                &mut rng,
            );
            // ASK signed by ARK.
            let ask_der = make_cert(
                2,
                "CN=ASK",
                "CN=ARK",
                rsa_spki(&RsaPublicKey::from(&ask_sk)),
                wide,
                &ark_sk,
                &mut rng,
            );

            // VCEK: ECDSA P-384, signed by ASK (or an alternate issuer).
            let (vcek_sk, vcek_sec1) = test_vcek();
            let vcek_valid = validity(vcek_not_before, vcek_not_after);
            let issuer = vcek_issuer_sk.unwrap_or(&ask_sk);
            let vcek_der = make_cert(
                3,
                "CN=VCEK",
                "CN=ASK",
                ec_p384_spki(&vcek_sec1),
                vcek_valid,
                issuer,
                &mut rng,
            );

            // Build the report: embed measurement at 0x090, report_data at
            // 0x050, then sign region [0..0x2A0] with the VCEK key.
            let measurement = [0x5Au8; 48];
            let report_data = [0xA5u8; 64];
            let mut region = [0u8; REPORT_SIG_OFFSET];
            region[REPORT_MEASUREMENT_OFFSET..REPORT_MEASUREMENT_OFFSET + 48]
                .copy_from_slice(&measurement);
            region[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64].copy_from_slice(&report_data);
            let report = synthetic_signed_report(&region, &vcek_sk);

            // Pin the (correct) ARK SPKI hash.
            let ark = Certificate::from_der(&ark_der).unwrap();
            let pinned_ark: [u8; 48] = Sha384::digest(
                ark.tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .unwrap(),
            )
            .into();

            SyntheticChain {
                vcek_der,
                ask_der,
                ark_der,
                report,
                pinned_ark,
                measurement,
                report_data,
                now,
            }
        }

        #[test]
        fn valid_chain_and_report_verifies() {
            let c = build_chain(1_699_000_000, 1_800_000_000, None);
            let v = verify_snp_attestation(
                &c.report,
                &c.vcek_der,
                &c.ask_der,
                &c.ark_der,
                &c.pinned_ark,
                c.now,
            )
            .expect("valid chain must verify");
            assert_eq!(v.measurement, c.measurement.to_vec());
            assert_eq!(v.report_data, c.report_data.to_vec());
        }

        #[test]
        fn forged_report_body_fails_chain() {
            let c = build_chain(1_699_000_000, 1_800_000_000, None);
            let mut report = c.report.clone();
            report[0x100] ^= 0xFF; // tamper signed region after signing
            assert_eq!(
                verify_snp_attestation(
                    &report,
                    &c.vcek_der,
                    &c.ask_der,
                    &c.ark_der,
                    &c.pinned_ark,
                    c.now,
                ),
                Err(SevSnpVerifyError::ReportSignatureInvalid)
            );
        }

        #[test]
        fn wrong_root_pin_is_untrusted() {
            let c = build_chain(1_699_000_000, 1_800_000_000, None);
            let mut bad_pin = c.pinned_ark;
            bad_pin[0] ^= 0xFF;
            assert_eq!(
                verify_snp_attestation(
                    &c.report,
                    &c.vcek_der,
                    &c.ask_der,
                    &c.ark_der,
                    &bad_pin,
                    c.now,
                ),
                Err(SevSnpVerifyError::UntrustedRoot)
            );
        }

        #[test]
        fn expired_vcek_is_rejected() {
            // VCEK not_after well before `now`.
            let c = build_chain(1_600_000_000, 1_600_100_000, None);
            assert_eq!(
                verify_snp_attestation(
                    &c.report,
                    &c.vcek_der,
                    &c.ask_der,
                    &c.ark_der,
                    &c.pinned_ark,
                    c.now,
                ),
                Err(SevSnpVerifyError::CertExpired)
            );
        }

        #[test]
        fn not_yet_valid_vcek_is_rejected() {
            // VCEK not_before well after `now`.
            let c = build_chain(1_900_000_000, 2_000_000_000, None);
            assert_eq!(
                verify_snp_attestation(
                    &c.report,
                    &c.vcek_der,
                    &c.ask_der,
                    &c.ark_der,
                    &c.pinned_ark,
                    c.now,
                ),
                Err(SevSnpVerifyError::CertNotYetValid)
            );
        }

        #[test]
        fn broken_chain_link_is_rejected() {
            // Sign the VCEK with a key that is NOT the ASK.
            let mut rng = CounterRng::seeded(0xBA_DBAD);
            let rogue = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let c = build_chain(1_699_000_000, 1_800_000_000, Some(&rogue));
            assert_eq!(
                verify_snp_attestation(
                    &c.report,
                    &c.vcek_der,
                    &c.ask_der,
                    &c.ark_der,
                    &c.pinned_ark,
                    c.now,
                ),
                Err(SevSnpVerifyError::ChainSignatureInvalid)
            );
        }
    }
}

#[cfg(feature = "amd-sev-snp")]
pub use inner::{
    verify_report_signature, verify_snp_attestation, AmdSevSnpRoT, SevSnpVerifyError, SnpPolicy,
    VerifiedSnpReport,
};

/// Stub — `amd-sev-snp` feature not compiled in.
#[cfg(not(feature = "amd-sev-snp"))]
pub struct AmdSevSnpRoT;

#[cfg(not(feature = "amd-sev-snp"))]
impl crate::measurement::RoT for AmdSevSnpRoT {
    fn measure(&self) -> Result<crate::measurement::Measurements, crate::error::PqRascvError> {
        Err(crate::error::PqRascvError::BackendUnavailable)
    }
}
