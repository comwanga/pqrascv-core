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
    use subtle::ConstantTimeEq;

    const MRTD_OFFSET: usize = 0x210; // TdInfo starts at 0x200; MRTD at TdInfo+0x010
    const RTMR0_OFFSET: usize = 0x2D0;
    const RTMR1_OFFSET: usize = 0x300;
    const RTMR2_OFFSET: usize = 0x330;
    const RTMR3_OFFSET: usize = 0x360;
    const SHA384_LEN: usize = 48;
    pub(super) const TDREPORT_LEN: usize = 1024;

    // REPORTDATA: guest-supplied 64-byte nonce at REPORTMACSTRUCT+0x090.
    // Source: Intel TDX Module ABI Spec §22.3, REPORTMACSTRUCT.REPORTDATA.
    const REPORTDATA_OFFSET: usize = 0x090;
    const REPORTDATA_FW_HASH_LEN: usize = 32;

    // Attributes field at start of TDINFO (TdInfo starts at offset 0x200).
    // Bit 0 = DEBUG: if set, TD is running in debug mode.
    // Source: Intel TDX Module ABI Spec §22.3, TD_ATTRIBUTES.DEBUG.
    const ATTRIBUTES_OFFSET: usize = 0x200;

    #[cfg(target_os = "linux")]
    const REPORTDATA_LEN: usize = 64;

    // _IOWR('G', 0x01, struct tdx_report_req) — Linux ≥ 5.19
    // arch/x86/include/uapi/asm/tdx.h, verified against kernel 6.5.
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
            // Validate REPORTDATA binding: first 32 bytes must equal SHA3-256(firmware).
            let fw_hash: [u8; 32] = Sha3_256::digest(firmware).into();
            let report_data_fw =
                &tdreport[REPORTDATA_OFFSET..REPORTDATA_OFFSET + REPORTDATA_FW_HASH_LEN];
            if report_data_fw.ct_eq(fw_hash.as_ref()).unwrap_u8() == 0 {
                return Err(PqRascvError::MeasurementFailed);
            }

            // Reject debug-mode TDs (ATTRIBUTES bit 0 set).
            if tdreport[ATTRIBUTES_OFFSET] & 0x01 != 0 {
                return Err(PqRascvError::MeasurementFailed);
            }

            let normalize = |offset: usize| -> [u8; 32] {
                Sha3_256::digest(&tdreport[offset..offset + SHA384_LEN]).into()
            };

            let mut pcrs = PcrBank::default();
            pcrs.digests[0] = normalize(MRTD_OFFSET);
            pcrs.digests[1] = normalize(RTMR0_OFFSET);
            pcrs.digests[2] = normalize(RTMR1_OFFSET);
            pcrs.digests[3] = normalize(RTMR2_OFFSET);
            pcrs.digests[4] = normalize(RTMR3_OFFSET);

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

            // SAFETY:
            // 1. `dev` is a valid, open file descriptor for `/dev/tdx_guest`.
            // 2. `TDX_CMD_GET_REPORT0` is the stable ioctl number from the Linux kernel
            //    TDX uAPI (arch/x86/include/uapi/asm/tdx.h, verified against kernel 6.5).
            //    It is a _IOWR ioctl — the kernel reads from `req.reportdata` (our nonce)
            //    and writes the TDREPORT into `req.tdreport`. No other memory is accessed.
            // 3. `req` is a stack-allocated `TdxReportReq` with `repr(C)` layout matching
            //    the kernel struct definition. Its fields are fully initialized above.
            // 4. The raw pointer `&mut req` is valid for the duration of the ioctl call.
            // 5. This call does not create data races: `req` is exclusively owned here.
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

    // ── DCAP TD-Quote (v4) remote-attestation verification ──────────────────
    //
    // The collector above (`measure`) reads a locally-MAC'd TDREPORT, which is
    // NOT remotely verifiable. Genuine remote attestation uses a DCAP TD-Quote:
    // the Quoting Enclave (QE) re-signs the TD measurements with an ECDSA
    // attestation key, and the QE itself is certified by Intel's SGX PCK
    // certificate chain (PCK leaf → Intel SGX intermediate CA → Intel SGX Root
    // CA). This section verifies that full chain of trust.
    //
    // The entire DCAP ECDSA-P256 chain is verified here:
    //   1. quote_signature (att-key) over Header||TDReportBody,
    //   2. QE→att-key binding (SHA-256(att_key || qe_auth_data)),
    //   3. qe_report_signature (PCK leaf) over the QE report,
    //   4. PCK chain (leaf←intermediate←root) + root pin + validity windows.

    use der::{Decode as _, Encode as _, Reader as _};
    use p256::ecdsa::{signature::Verifier as _, Signature as P256Signature, VerifyingKey};
    use sha2::{Sha256, Sha384}; // `Digest` is already in scope via the sha3 import above.
    use x509_cert::spki::ObjectIdentifier;
    use x509_cert::Certificate;

    // ── DCAP TD-Quote v4 layout constants ───────────────────────────────────
    // Source: Intel SGX/TDX DCAP "Quote Generation Library" Quote v4 format.
    /// Quote header length.
    const HEADER_LEN: usize = 48;
    /// TD report body (TD10) length.
    const TD_REPORT_BODY_LEN: usize = 584;
    /// Offset of the TD report body within the quote.
    const TD_BODY_OFFSET: usize = HEADER_LEN;
    /// End of the signed region (`Header || TDReportBody`).
    const SIGNED_LEN: usize = HEADER_LEN + TD_REPORT_BODY_LEN; // 632
    /// Offset of the `u32` signature-data length.
    const SIG_DATA_LEN_OFFSET: usize = SIGNED_LEN; // 632
    /// Offset where signature data begins.
    const SIG_DATA_OFFSET: usize = SIG_DATA_LEN_OFFSET + 4; // 636

    /// Quote version we support (v4).
    const QUOTE_VERSION_V4: u16 = 4;
    /// Attestation-key type ECDSA-P256.
    const ATT_KEY_TYPE_ECDSA_P256: u16 = 2;
    /// TEE type TDX (`0x0000_0081`).
    const TEE_TYPE_TDX: u32 = 0x0000_0081;

    /// Length of a raw ECDSA-P256 signature (`r || s`, big-endian, 32+32).
    const ECDSA_P256_SIG_LEN: usize = 64;
    /// Length of a raw ECDSA-P256 public key (`x || y`, big-endian, 32+32).
    const ECDSA_P256_KEY_LEN: usize = 64;
    /// Length of an SGX report body (the QE report).
    const SGX_REPORT_BODY_LEN: usize = 384;
    /// `cert_data_type` for "PCK certificate chain (PEM)".
    const CERT_DATA_TYPE_PCK_CHAIN: u16 = 5;

    // ── Offsets inside the TD10 report body (relative to body start) ─────────
    /// MRTD offset within the TD report body.
    const BODY_MRTD_OFFSET: usize = 16 + 48 + 48 + 8 + 8 + 8; // 136
    /// RTMR0 offset within the TD report body.
    const BODY_RTMR0_OFFSET: usize = BODY_MRTD_OFFSET + 48 + 48 + 48 + 48; // 328
    /// Length of a single measurement register (SHA-384).
    const REG_LEN: usize = 48;
    /// `report_data` is the final 64 bytes of the body.
    const BODY_REPORT_DATA_OFFSET: usize = TD_REPORT_BODY_LEN - 64; // 520

    /// `report_data` is the final 64 bytes of an SGX report body.
    const SGX_REPORT_DATA_OFFSET: usize = SGX_REPORT_BODY_LEN - 64; // 320

    /// OID `id-ecPublicKey` (1.2.840.10045.2.1) — PCK subject key type.
    const ID_EC_PUBLIC_KEY: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    /// OID `ecdsa-with-SHA256` (1.2.840.10045.4.3.2) — DCAP cert signature alg.
    const ECDSA_WITH_SHA256: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    /// Errors from DCAP TD-Quote verification.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TdxVerifyError {
        /// The quote buffer is too short or internally inconsistent.
        MalformedQuote,
        /// The quote `version` field is not a supported value (only v4).
        UnsupportedQuoteVersion,
        /// The quote signature did not verify under the attestation key.
        QuoteSignatureInvalid,
        /// `qe_report.report_data[0..32]` did not equal
        /// `SHA-256(att_key || qe_auth_data)`.
        QeReportBindingInvalid,
        /// The QE report signature did not verify under the PCK leaf key.
        QeSignatureInvalid,
        /// A PCK certificate could not be parsed, or a key could not be decoded.
        CertParse,
        /// A PCK certificate's signature did not verify under its issuer.
        ChainSignatureInvalid,
        /// The PCK root's `subjectPublicKeyInfo` did not match the pinned root.
        UntrustedRoot,
        /// A certificate's `notAfter` is before the supplied verification time.
        CertExpired,
        /// A certificate's `notBefore` is after the supplied verification time.
        CertNotYetValid,
        /// A certificate signature algorithm is not ECDSA-with-SHA256.
        UnsupportedSignatureAlgorithm,
    }

    /// A verified TD quote: returned only after the attestation-key signature,
    /// the QE binding, the QE-report signature, the full PCK chain, the root
    /// pin, and all validity windows have been checked. Fields are copied out
    /// of the now-trusted TD report body.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VerifiedTdQuote {
        /// The 48-byte MRTD (initial TD measurement).
        pub mrtd: Vec<u8>,
        /// The four 48-byte RTMRs (RTMR0..RTMR3).
        pub rtmrs: [Vec<u8>; 4],
        /// The 64-byte `report_data` field of the TD report body.
        pub report_data: Vec<u8>,
    }

    /// Reads a little-endian `u16` at `off`, or `MalformedQuote`.
    fn read_u16_le(buf: &[u8], off: usize) -> Result<u16, TdxVerifyError> {
        buf.get(off..off + 2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_le_bytes)
            .ok_or(TdxVerifyError::MalformedQuote)
    }

    /// Reads a little-endian `u32` at `off`, or `MalformedQuote`.
    fn read_u32_le(buf: &[u8], off: usize) -> Result<u32, TdxVerifyError> {
        buf.get(off..off + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(TdxVerifyError::MalformedQuote)
    }

    /// Builds a P-256 [`VerifyingKey`] from a raw 64-byte `x || y` (big-endian)
    /// point by prepending the SEC1 uncompressed tag `0x04`.
    fn p256_vk_from_xy(xy: &[u8]) -> Result<VerifyingKey, TdxVerifyError> {
        if xy.len() != ECDSA_P256_KEY_LEN {
            return Err(TdxVerifyError::MalformedQuote);
        }
        let mut sec1 = [0u8; 1 + ECDSA_P256_KEY_LEN];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(xy);
        VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| TdxVerifyError::MalformedQuote)
    }

    /// Verifies `sig_rs` (raw 64-byte big-endian `r || s`) over `msg` under
    /// `vk`, mapping any failure to `on_err`.
    fn verify_raw_ecdsa_vk(
        msg: &[u8],
        vk: &VerifyingKey,
        sig_rs: &[u8],
        on_err: TdxVerifyError,
    ) -> Result<(), TdxVerifyError> {
        let sig = P256Signature::from_slice(sig_rs).map_err(|_| on_err)?;
        vk.verify(msg, &sig).map_err(|_| on_err)
    }

    /// Verifies `sig_rs` (raw 64-byte big-endian `r || s`) over `msg` under the
    /// raw 64-byte `x || y` key, mapping any failure to `on_err`.
    fn verify_raw_ecdsa(
        msg: &[u8],
        xy: &[u8],
        sig_rs: &[u8],
        on_err: TdxVerifyError,
    ) -> Result<(), TdxVerifyError> {
        let vk = p256_vk_from_xy(xy)?;
        verify_raw_ecdsa_vk(msg, &vk, sig_rs, on_err)
    }

    /// Verifies that `cert`'s ECDSA-with-SHA256 signature is valid under
    /// `issuer`'s P-256 public key, over `cert`'s re-encoded `tbs_certificate`.
    fn verify_cert_signature(
        cert: &Certificate,
        issuer: &VerifyingKey,
    ) -> Result<(), TdxVerifyError> {
        // The outer and TBS signature algorithms MUST match (RFC 5280 §4.1.1.2).
        if cert.signature_algorithm.oid != cert.tbs_certificate.signature.oid {
            return Err(TdxVerifyError::ChainSignatureInvalid);
        }
        if cert.signature_algorithm.oid != ECDSA_WITH_SHA256 {
            return Err(TdxVerifyError::UnsupportedSignatureAlgorithm);
        }
        let tbs_der = cert
            .tbs_certificate
            .to_der()
            .map_err(|_| TdxVerifyError::CertParse)?;
        // ECDSA signatures in X.509 are DER-encoded (SEQUENCE { r, s }).
        let sig_der = cert
            .signature
            .as_bytes()
            .ok_or(TdxVerifyError::ChainSignatureInvalid)?;
        let sig = P256Signature::from_der(sig_der)
            .map_err(|_| TdxVerifyError::ChainSignatureInvalid)?;
        issuer
            .verify(&tbs_der, &sig)
            .map_err(|_| TdxVerifyError::ChainSignatureInvalid)
    }

    /// Extracts the P-256 public key from a certificate's
    /// `subjectPublicKeyInfo` (raw SEC1 point in the BIT STRING).
    fn cert_p256_pubkey(cert: &Certificate) -> Result<VerifyingKey, TdxVerifyError> {
        let spki = &cert.tbs_certificate.subject_public_key_info;
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(TdxVerifyError::CertParse);
        }
        let sec1 = spki
            .subject_public_key
            .as_bytes()
            .ok_or(TdxVerifyError::CertParse)?;
        VerifyingKey::from_sec1_bytes(sec1).map_err(|_| TdxVerifyError::CertParse)
    }

    /// SHA-384 over a certificate's DER-encoded `subjectPublicKeyInfo` — the
    /// value pinned for Intel's SGX Root CA.
    fn spki_sha384(cert: &Certificate) -> Result<[u8; 48], TdxVerifyError> {
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| TdxVerifyError::CertParse)?;
        Ok(Sha384::digest(&spki_der).into())
    }

    /// Returns `Ok(())` iff `now_unix` is within `[notBefore, notAfter]`.
    fn check_validity(cert: &Certificate, now_unix: u64) -> Result<(), TdxVerifyError> {
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
            return Err(TdxVerifyError::CertNotYetValid);
        }
        if now_unix > not_after {
            return Err(TdxVerifyError::CertExpired);
        }
        Ok(())
    }

    /// Splits a DER-concatenated cert blob into its constituent X.509
    /// certificates, in order (PCK leaf, intermediate CA, root CA).
    ///
    /// DCAP's production `qe_cert_data` type 5 is concatenated PEM. The `der`
    /// crate is built here WITHOUT its `pem` feature, so to avoid adding a
    /// dependency/feature we standardize on DER-concatenated encoding: the
    /// `cert_data` bytes are the three certs' DER one after another. The
    /// synthetic test PKI emits the same encoding. A production deployment that
    /// receives PEM `cert_data` must first strip the PEM armor (Base64-decode
    /// each `CERTIFICATE` block) before calling this verifier — see the task
    /// caveats.
    fn parse_der_chain(der_blob: &[u8]) -> Result<Vec<Certificate>, TdxVerifyError> {
        let mut reader =
            der::SliceReader::new(der_blob).map_err(|_| TdxVerifyError::CertParse)?;
        let mut certs = Vec::new();
        while !reader.is_finished() {
            let cert =
                Certificate::decode(&mut reader).map_err(|_| TdxVerifyError::CertParse)?;
            certs.push(cert);
        }
        if certs.is_empty() {
            return Err(TdxVerifyError::CertParse);
        }
        Ok(certs)
    }

    /// Full DCAP TD-Quote (v4) remote-attestation verification.
    ///
    /// `quote` is a complete DCAP v4 TD quote (`Header || TDReportBody ||
    /// SigDataLen || SigData`). `pinned_root_spki_sha384` is the SHA-384 of the
    /// Intel SGX Root CA's DER `subjectPublicKeyInfo`. `now_unix` is the
    /// verification time used for the PCK chain validity windows.
    ///
    /// Verifies, in order:
    /// 1. header: `version == 4`, `att_key_type == 2`, `tee_type == 0x81`;
    /// 2. the quote signature (ECDSA-P256/SHA-256) over `quote[0..632]` under
    ///    the embedded attestation key;
    /// 3. the QE→att-key binding
    ///    (`qe_report.report_data[0..32] == SHA-256(att_key || qe_auth_data)`);
    /// 4. the QE report signature (ECDSA-P256/SHA-256) under the PCK leaf key;
    /// 5. the PCK chain (leaf←intermediate←root), root pin (constant-time
    ///    SHA-384 SPKI compare), and all three validity windows.
    ///
    /// On success returns the verified MRTD, RTMRs, and `report_data`.
    // The function is a single linear verification pipeline; keeping the parse
    // and the ordered cryptographic checks together makes the security ordering
    // auditable, so we allow the length lint rather than fragment the flow.
    #[allow(clippy::too_many_lines)]
    pub fn verify_tdx_quote(
        quote: &[u8],
        pinned_root_spki_sha384: &[u8; 48],
        now_unix: u64,
    ) -> Result<VerifiedTdQuote, TdxVerifyError> {
        // 1. Header checks.
        if quote.len() < SIG_DATA_OFFSET {
            return Err(TdxVerifyError::MalformedQuote);
        }
        let version = read_u16_le(quote, 0)?;
        if version != QUOTE_VERSION_V4 {
            return Err(TdxVerifyError::UnsupportedQuoteVersion);
        }
        let att_key_type = read_u16_le(quote, 2)?;
        let tee_type = read_u32_le(quote, 4)?;
        if att_key_type != ATT_KEY_TYPE_ECDSA_P256 || tee_type != TEE_TYPE_TDX {
            return Err(TdxVerifyError::MalformedQuote);
        }

        // Bound the signature data by its declared length.
        let sig_data_len = read_u32_le(quote, SIG_DATA_LEN_OFFSET)? as usize;
        let sig_data = quote
            .get(SIG_DATA_OFFSET..SIG_DATA_OFFSET + sig_data_len)
            .ok_or(TdxVerifyError::MalformedQuote)?;

        // SigData layout: quote_signature(64) || att_key(64) || qe_report(384)
        //   || qe_report_signature(64) || qe_auth_data(u16 len + bytes)
        //   || qe_cert_data(u16 type + u32 size + bytes).
        let mut p = 0usize;
        let quote_sig = sig_data
            .get(p..p + ECDSA_P256_SIG_LEN)
            .ok_or(TdxVerifyError::MalformedQuote)?;
        p += ECDSA_P256_SIG_LEN;
        let att_key = sig_data
            .get(p..p + ECDSA_P256_KEY_LEN)
            .ok_or(TdxVerifyError::MalformedQuote)?;
        p += ECDSA_P256_KEY_LEN;
        let qe_report = sig_data
            .get(p..p + SGX_REPORT_BODY_LEN)
            .ok_or(TdxVerifyError::MalformedQuote)?;
        p += SGX_REPORT_BODY_LEN;
        let qe_report_sig = sig_data
            .get(p..p + ECDSA_P256_SIG_LEN)
            .ok_or(TdxVerifyError::MalformedQuote)?;
        p += ECDSA_P256_SIG_LEN;
        let qe_auth_len = read_u16_le(sig_data, p)? as usize;
        p += 2;
        let qe_auth_data = sig_data
            .get(p..p + qe_auth_len)
            .ok_or(TdxVerifyError::MalformedQuote)?;
        p += qe_auth_len;
        let cert_data_type = read_u16_le(sig_data, p)?;
        p += 2;
        let cert_data_size = read_u32_le(sig_data, p)? as usize;
        p += 4;
        let cert_data = sig_data
            .get(p..p + cert_data_size)
            .ok_or(TdxVerifyError::MalformedQuote)?;
        if cert_data_type != CERT_DATA_TYPE_PCK_CHAIN {
            return Err(TdxVerifyError::CertParse);
        }

        // 2. Quote signature over Header||TDReportBody under the att key.
        verify_raw_ecdsa(
            &quote[..SIGNED_LEN],
            att_key,
            quote_sig,
            TdxVerifyError::QuoteSignatureInvalid,
        )?;

        // 3. QE→att-key binding.
        let mut binding = Sha256::new();
        binding.update(att_key);
        binding.update(qe_auth_data);
        let expected: [u8; 32] = binding.finalize().into();
        let qe_report_data = qe_report
            .get(SGX_REPORT_DATA_OFFSET..SGX_REPORT_DATA_OFFSET + 64)
            .ok_or(TdxVerifyError::MalformedQuote)?;
        if qe_report_data[..32].ct_eq(&expected).unwrap_u8() == 0 {
            return Err(TdxVerifyError::QeReportBindingInvalid);
        }

        // 4. Parse the PCK chain and verify the QE report signature under the
        //    PCK leaf key.
        let chain = parse_der_chain(cert_data)?;
        if chain.len() < 3 {
            return Err(TdxVerifyError::CertParse);
        }
        let leaf = &chain[0];
        let intermediate = &chain[1];
        let root = &chain[2];

        let leaf_key = cert_p256_pubkey(leaf)?;
        verify_raw_ecdsa_vk(
            qe_report,
            &leaf_key,
            qe_report_sig,
            TdxVerifyError::QeSignatureInvalid,
        )?;

        // 5. PCK chain: leaf signed by intermediate, intermediate signed by root.
        let intermediate_key = cert_p256_pubkey(intermediate)?;
        let root_key = cert_p256_pubkey(root)?;
        verify_cert_signature(leaf, &intermediate_key)?;
        verify_cert_signature(intermediate, &root_key)?;

        // Root pin (constant-time SHA-384 SPKI compare).
        let root_spki_hash = spki_sha384(root)?;
        if root_spki_hash
            .ct_eq(pinned_root_spki_sha384.as_ref())
            .unwrap_u8()
            == 0
        {
            return Err(TdxVerifyError::UntrustedRoot);
        }

        // Validity windows.
        check_validity(leaf, now_unix)?;
        check_validity(intermediate, now_unix)?;
        check_validity(root, now_unix)?;

        // Extract trusted fields from the TD report body.
        let body = &quote[TD_BODY_OFFSET..TD_BODY_OFFSET + TD_REPORT_BODY_LEN];
        let mrtd = body[BODY_MRTD_OFFSET..BODY_MRTD_OFFSET + REG_LEN].to_vec();
        let rtmrs = [
            body[BODY_RTMR0_OFFSET..BODY_RTMR0_OFFSET + REG_LEN].to_vec(),
            body[BODY_RTMR0_OFFSET + REG_LEN..BODY_RTMR0_OFFSET + 2 * REG_LEN].to_vec(),
            body[BODY_RTMR0_OFFSET + 2 * REG_LEN..BODY_RTMR0_OFFSET + 3 * REG_LEN].to_vec(),
            body[BODY_RTMR0_OFFSET + 3 * REG_LEN..BODY_RTMR0_OFFSET + 4 * REG_LEN].to_vec(),
        ];
        let report_data = body[BODY_REPORT_DATA_OFFSET..BODY_REPORT_DATA_OFFSET + 64].to_vec();

        Ok(VerifiedTdQuote {
            mrtd,
            rtmrs,
            report_data,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn fake_tdreport_with_reportdata(
            mrtd: [u8; 48],
            rtmr0: [u8; 48],
            report_data: [u8; 32],
        ) -> [u8; TDREPORT_LEN] {
            let mut r = [0u8; TDREPORT_LEN];
            r[MRTD_OFFSET..MRTD_OFFSET + 48].copy_from_slice(&mrtd);
            r[RTMR0_OFFSET..RTMR0_OFFSET + 48].copy_from_slice(&rtmr0);
            r[REPORTDATA_OFFSET..REPORTDATA_OFFSET + 32].copy_from_slice(&report_data);
            r
        }

        fn fake_tdreport(mrtd: [u8; 48], rtmr0: [u8; 48]) -> [u8; TDREPORT_LEN] {
            let fw_hash: [u8; 32] = Sha3_256::digest(b"fw").into();
            fake_tdreport_with_reportdata(mrtd, rtmr0, fw_hash)
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
            let report = fake_tdreport([0u8; 48], [0u8; 48]);
            let m = IntelTdxRoT::measurements_from_report(&report, b"fw", None, 0).unwrap();
            assert_ne!(m.pcrs.digests[0], [0u8; 32]);
        }

        #[test]
        fn firmware_hash_from_local_bytes() {
            use sha3::{Digest as _, Sha3_256};
            let fw = b"my-fw";
            let fw_hash: [u8; 32] = Sha3_256::digest(fw).into();
            let report = fake_tdreport_with_reportdata([0u8; 48], [0u8; 48], fw_hash);
            let m = IntelTdxRoT::measurements_from_report(&report, fw, None, 0).unwrap();
            let expected: [u8; 32] = Sha3_256::digest(fw).into();
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

        #[test]
        fn reportdata_binding_rejects_mismatched_fw_hash() {
            // fake_tdreport embeds SHA3-256(b"fw") in REPORTDATA,
            // but we pass b"real-firmware" as firmware — hash mismatch → error.
            let report = fake_tdreport([0x42u8; 48], [0u8; 48]);
            let err = IntelTdxRoT::measurements_from_report(&report, b"real-firmware", None, 0);
            assert!(matches!(err, Err(PqRascvError::MeasurementFailed)));
        }

        #[test]
        fn reportdata_binding_accepts_matching_fw_hash() {
            let fw = b"real-firmware";
            let fw_hash: [u8; 32] = Sha3_256::digest(fw).into();
            let report = fake_tdreport_with_reportdata([0x42u8; 48], [0u8; 48], fw_hash);
            let m = IntelTdxRoT::measurements_from_report(&report, fw, None, 0).unwrap();
            assert_eq!(m.firmware_hash, fw_hash);
        }

        #[test]
        fn debug_mode_td_is_rejected() {
            let fw = b"fw";
            let fw_hash: [u8; 32] = Sha3_256::digest(fw).into();
            let mut report = fake_tdreport_with_reportdata([0u8; 48], [0u8; 48], fw_hash);
            // Set debug bit (bit 0) in ATTRIBUTES
            report[ATTRIBUTES_OFFSET] |= 0x01;
            let err = IntelTdxRoT::measurements_from_report(&report, fw, None, 0);
            assert!(matches!(err, Err(PqRascvError::MeasurementFailed)));
        }
    }

    #[cfg(test)]
    mod verify_tests {
        // Synthetic Intel-PKI helpers use Intel/spec identifiers in docs and
        // similar local names (leaf/intermediate/root keys); silence the noise.
        #![allow(clippy::similar_names, clippy::doc_markdown)]
        use super::*;
        use p256::ecdsa::{signature::Signer as _, DerSignature, SigningKey};
        use der::asn1::BitString;
        use std::str::FromStr as _;
        use x509_cert::certificate::{TbsCertificate, Version};
        use x509_cert::der::asn1::GeneralizedTime;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::{
            AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned,
        };
        use x509_cert::time::{Time, Validity};

        const SECP_256_R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

        /// Deterministic P-256 signer from a fixed 32-byte scalar (no RNG).
        fn signer(seed: u8) -> SigningKey {
            SigningKey::from_slice(&[seed; 32]).unwrap()
        }

        /// Raw 64-byte `x || y` of a verifying key (SEC1 uncompressed, tag stripped).
        fn raw_xy(sk: &SigningKey) -> [u8; 64] {
            let ep = sk.verifying_key().to_encoded_point(false);
            let mut xy = [0u8; 64];
            xy.copy_from_slice(&ep.as_bytes()[1..]);
            xy
        }

        /// `ecdsa-with-SHA256` AlgorithmIdentifier (parameters absent).
        fn ecdsa_sha256_alg() -> AlgorithmIdentifierOwned {
            AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256,
                parameters: None,
            }
        }

        /// EC P-256 SubjectPublicKeyInfo from raw `x || y`.
        fn ec_p256_spki(xy: &[u8; 64]) -> SubjectPublicKeyInfoOwned {
            let mut sec1 = [0u8; 65];
            sec1[0] = 0x04;
            sec1[1..].copy_from_slice(xy);
            let curve_any = der::Any::from_der(&SECP_256_R1.to_der().unwrap()).unwrap();
            SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: ID_EC_PUBLIC_KEY,
                    parameters: Some(curve_any),
                },
                subject_public_key: BitString::from_bytes(&sec1).unwrap(),
            }
        }

        fn validity(not_before: u64, not_after: u64) -> Validity {
            use core::time::Duration;
            let nb = GeneralizedTime::from_unix_duration(Duration::from_secs(not_before)).unwrap();
            let na = GeneralizedTime::from_unix_duration(Duration::from_secs(not_after)).unwrap();
            Validity {
                not_before: Time::GeneralTime(nb),
                not_after: Time::GeneralTime(na),
            }
        }

        /// Assemble + ECDSA-P256-SHA256-sign a certificate (DER output).
        fn make_cert(
            serial: u64,
            subject: &str,
            issuer: &str,
            spki: SubjectPublicKeyInfoOwned,
            valid: Validity,
            issuer_sk: &SigningKey,
        ) -> Vec<u8> {
            let tbs = TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(&serial.to_be_bytes()).unwrap(),
                signature: ecdsa_sha256_alg(),
                issuer: Name::from_str(issuer).unwrap(),
                validity: valid,
                subject: Name::from_str(subject).unwrap(),
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: None,
            };
            let tbs_der = tbs.to_der().unwrap();
            let sig: DerSignature = issuer_sk.sign(&tbs_der);
            let cert = Certificate {
                tbs_certificate: tbs,
                signature_algorithm: ecdsa_sha256_alg(),
                signature: BitString::from_bytes(sig.as_bytes()).unwrap(),
            };
            cert.to_der().unwrap()
        }

        /// A fully assembled synthetic DCAP v4 TD quote plus the pinned root.
        struct SyntheticQuote {
            quote: Vec<u8>,
            pinned_root: [u8; 48],
            mrtd: [u8; 48],
            rtmrs: [[u8; 48]; 4],
            report_data: [u8; 64],
            now: u64,
        }

        /// Assembles a header.
        fn header() -> [u8; HEADER_LEN] {
            let mut h = [0u8; HEADER_LEN];
            h[0..2].copy_from_slice(&QUOTE_VERSION_V4.to_le_bytes());
            h[2..4].copy_from_slice(&ATT_KEY_TYPE_ECDSA_P256.to_le_bytes());
            h[4..8].copy_from_slice(&TEE_TYPE_TDX.to_le_bytes());
            h
        }

        /// Builds a valid TD quote with a synthetic PCK chain.
        ///
        /// `leaf_issuer` lets a test sign the PCK leaf with a key OTHER than the
        /// intermediate (to exercise the broken-link path). `leaf_validity`
        /// overrides the leaf cert window.
        fn build_quote(
            leaf_issuer: Option<&SigningKey>,
            leaf_validity: Option<Validity>,
        ) -> SyntheticQuote {
            let now: u64 = 1_700_000_000;
            let wide = validity(now - 1000, now + 1_000_000);

            // PCK chain: root (self-signed) → intermediate → leaf.
            let root_sk = signer(0x01);
            let inter_sk = signer(0x02);
            let leaf_sk = signer(0x03);

            let root_der = make_cert(
                1,
                "CN=Intel SGX Root CA",
                "CN=Intel SGX Root CA",
                ec_p256_spki(&raw_xy(&root_sk)),
                wide,
                &root_sk,
            );
            let inter_der = make_cert(
                2,
                "CN=Intel SGX PCK Processor CA",
                "CN=Intel SGX Root CA",
                ec_p256_spki(&raw_xy(&inter_sk)),
                wide,
                &root_sk,
            );
            let leaf_signer = leaf_issuer.unwrap_or(&inter_sk);
            let leaf_der = make_cert(
                3,
                "CN=Intel SGX PCK Certificate",
                "CN=Intel SGX PCK Processor CA",
                ec_p256_spki(&raw_xy(&leaf_sk)),
                leaf_validity.unwrap_or(wide),
                leaf_signer,
            );

            // DER-concatenated chain: leaf || intermediate || root.
            let mut cert_data = Vec::new();
            cert_data.extend_from_slice(&leaf_der);
            cert_data.extend_from_slice(&inter_der);
            cert_data.extend_from_slice(&root_der);

            // Attestation key (deterministic).
            let att_sk = signer(0x10);
            let att_key = raw_xy(&att_sk);

            // TD report body.
            let mrtd = [0x5Au8; 48];
            let rtmrs = [[0x11u8; 48], [0x22u8; 48], [0x33u8; 48], [0x44u8; 48]];
            let report_data = [0xA5u8; 64];
            let mut body = [0u8; TD_REPORT_BODY_LEN];
            body[BODY_MRTD_OFFSET..BODY_MRTD_OFFSET + 48].copy_from_slice(&mrtd);
            for (i, r) in rtmrs.iter().enumerate() {
                let o = BODY_RTMR0_OFFSET + i * REG_LEN;
                body[o..o + 48].copy_from_slice(r);
            }
            body[BODY_REPORT_DATA_OFFSET..BODY_REPORT_DATA_OFFSET + 64]
                .copy_from_slice(&report_data);

            // Signed region = header || body.
            let mut signed = [0u8; SIGNED_LEN];
            signed[..HEADER_LEN].copy_from_slice(&header());
            signed[HEADER_LEN..].copy_from_slice(&body);
            let quote_sig: DerSignature = att_sk.sign(&signed);
            // Convert DER sig to raw r||s (big-endian) for the DCAP layout.
            let quote_sig_rs = P256Signature::from_der(quote_sig.as_bytes())
                .unwrap()
                .to_bytes();

            // QE auth data (arbitrary).
            let qe_auth_data: Vec<u8> = vec![0x77u8; 8];

            // QE report (SGX body): bind att_key + qe_auth_data.
            let mut qe_report = [0u8; SGX_REPORT_BODY_LEN];
            let mut binding = Sha256::new();
            binding.update(att_key);
            binding.update(&qe_auth_data);
            let bind_hash: [u8; 32] = binding.finalize().into();
            qe_report[SGX_REPORT_DATA_OFFSET..SGX_REPORT_DATA_OFFSET + 32]
                .copy_from_slice(&bind_hash);

            // QE report signed by the PCK leaf key.
            let qe_sig: DerSignature = leaf_sk.sign(&qe_report);
            let qe_sig_rs = P256Signature::from_der(qe_sig.as_bytes()).unwrap().to_bytes();

            // Assemble SigData.
            let mut sig_data = Vec::new();
            sig_data.extend_from_slice(&quote_sig_rs);
            sig_data.extend_from_slice(&att_key);
            sig_data.extend_from_slice(&qe_report);
            sig_data.extend_from_slice(&qe_sig_rs);
            sig_data.extend_from_slice(&u16::try_from(qe_auth_data.len()).unwrap().to_le_bytes());
            sig_data.extend_from_slice(&qe_auth_data);
            sig_data.extend_from_slice(&CERT_DATA_TYPE_PCK_CHAIN.to_le_bytes());
            sig_data.extend_from_slice(&u32::try_from(cert_data.len()).unwrap().to_le_bytes());
            sig_data.extend_from_slice(&cert_data);

            // Assemble the full quote.
            let mut quote = Vec::new();
            quote.extend_from_slice(&signed);
            quote.extend_from_slice(&u32::try_from(sig_data.len()).unwrap().to_le_bytes());
            quote.extend_from_slice(&sig_data);

            // Pin the root SPKI hash.
            let root = Certificate::from_der(&root_der).unwrap();
            let pinned_root: [u8; 48] = Sha384::digest(
                root.tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .unwrap(),
            )
            .into();

            SyntheticQuote {
                quote,
                pinned_root,
                mrtd,
                rtmrs,
                report_data,
                now,
            }
        }

        #[test]
        fn tdx_valid_quote_verifies() {
            let q = build_quote(None, None);
            let v = verify_tdx_quote(&q.quote, &q.pinned_root, q.now)
                .expect("valid quote must verify");
            assert_eq!(v.mrtd, q.mrtd.to_vec());
            for (i, r) in q.rtmrs.iter().enumerate() {
                assert_eq!(v.rtmrs[i], r.to_vec());
            }
            assert_eq!(v.report_data, q.report_data.to_vec());
        }

        #[test]
        fn tdx_forged_td_body_fails_quote_signature() {
            let q = build_quote(None, None);
            let mut quote = q.quote.clone();
            // Tamper a byte inside the TD report body (still in signed region).
            quote[TD_BODY_OFFSET + BODY_MRTD_OFFSET] ^= 0xFF;
            assert_eq!(
                verify_tdx_quote(&quote, &q.pinned_root, q.now),
                Err(TdxVerifyError::QuoteSignatureInvalid)
            );
        }

        #[test]
        fn tdx_tampered_qe_binding_is_rejected() {
            let q = build_quote(None, None);
            let mut quote = q.quote.clone();
            // The att_key sits right after the 64-byte quote_signature in SigData.
            let att_key_off = SIG_DATA_OFFSET + ECDSA_P256_SIG_LEN;
            // Flip a byte in qe_auth_data instead, so the att-key signature still
            // holds but the QE binding hash no longer matches.
            // qe_auth_data starts after quote_sig+att_key+qe_report+qe_sig+len(2).
            let qe_auth_off =
                att_key_off + ECDSA_P256_KEY_LEN + SGX_REPORT_BODY_LEN + ECDSA_P256_SIG_LEN + 2;
            quote[qe_auth_off] ^= 0xFF;
            assert_eq!(
                verify_tdx_quote(&quote, &q.pinned_root, q.now),
                Err(TdxVerifyError::QeReportBindingInvalid)
            );
        }

        #[test]
        fn tdx_wrong_root_pin_is_untrusted() {
            let q = build_quote(None, None);
            let mut bad = q.pinned_root;
            bad[0] ^= 0xFF;
            assert_eq!(
                verify_tdx_quote(&q.quote, &bad, q.now),
                Err(TdxVerifyError::UntrustedRoot)
            );
        }

        #[test]
        fn tdx_expired_pck_leaf_is_rejected() {
            let now: u64 = 1_700_000_000;
            let expired = validity(1_600_000_000, 1_600_100_000);
            let q = build_quote(None, Some(expired));
            assert_eq!(
                verify_tdx_quote(&q.quote, &q.pinned_root, now),
                Err(TdxVerifyError::CertExpired)
            );
        }

        #[test]
        fn tdx_broken_chain_link_is_rejected() {
            // Sign the PCK leaf with a rogue key (not the intermediate).
            let rogue = signer(0x55);
            let q = build_quote(Some(&rogue), None);
            assert_eq!(
                verify_tdx_quote(&q.quote, &q.pinned_root, q.now),
                Err(TdxVerifyError::ChainSignatureInvalid)
            );
        }

        #[test]
        fn tdx_bad_quote_version_is_rejected() {
            let q = build_quote(None, None);
            let mut quote = q.quote.clone();
            quote[0] = 0x03; // version 3
            assert_eq!(
                verify_tdx_quote(&quote, &q.pinned_root, q.now),
                Err(TdxVerifyError::UnsupportedQuoteVersion)
            );
        }
    }
}

#[cfg(feature = "intel-tdx")]
pub use inner::{verify_tdx_quote, IntelTdxRoT, TdxVerifyError, VerifiedTdQuote};

/// Stub — `intel-tdx` feature not compiled in.
#[cfg(not(feature = "intel-tdx"))]
pub struct IntelTdxRoT;

#[cfg(not(feature = "intel-tdx"))]
impl crate::measurement::RoT for IntelTdxRoT {
    fn measure(&self) -> Result<crate::measurement::Measurements, crate::error::PqRascvError> {
        Err(crate::error::PqRascvError::BackendUnavailable)
    }
}
