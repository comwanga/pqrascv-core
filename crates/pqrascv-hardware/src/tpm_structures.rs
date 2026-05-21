//! Strongly typed TPM 2.0 structure parsing.
//!
//! Provides bounded, big-endian safe decoders for the subset of TPM 2.0
//! structures required for cryptographically verifying a quote.
//!
//! # Hardening
//!
//! All parsers check bounds, explicitly reject unsupported algorithms (e.g. SHA-1),
//! and ensure trailing bytes are handled according to strict validation rules.

extern crate alloc;
use alloc::vec::Vec;
use core::convert::TryFrom;

// ── Algorithm Types ───────────────────────────────────────────────────────

/// TPM Algorithm Identifiers (`TPM_ALG_ID`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TpmAlgId {
    Rsa = 0x0001,
    Sha256 = 0x000B,
    Sha384 = 0x000C,
    Sha512 = 0x000D,
    Null = 0x0010,
    Ecdsa = 0x0018,
    Ecc = 0x0023,
    Rsapss = 0x0016,
    Sha3_256 = 0x0027,
    Sha3_384 = 0x0028,
    Sha3_512 = 0x0029,
}

impl TryFrom<u16> for TpmAlgId {
    type Error = TpmParseError;

    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0001 => Ok(Self::Rsa),
            0x000B => Ok(Self::Sha256),
            0x000C => Ok(Self::Sha384),
            0x000D => Ok(Self::Sha512),
            0x0010 => Ok(Self::Null),
            0x0018 => Ok(Self::Ecdsa),
            0x0023 => Ok(Self::Ecc),
            0x0016 => Ok(Self::Rsapss),
            0x0027 => Ok(Self::Sha3_256),
            0x0028 => Ok(Self::Sha3_384),
            0x0029 => Ok(Self::Sha3_512),
            0x0004 => Err(TpmParseError::UnsupportedAlgorithm(
                "SHA-1 explicitly rejected",
            )),
            _ => Err(TpmParseError::UnsupportedAlgorithm("unknown algorithm")),
        }
    }
}

/// TPM ECC Curve Identifiers (`TPM_ECC_CURVE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TpmEccCurve {
    NistP256 = 0x0003,
    NistP384 = 0x0004,
}

impl TryFrom<u16> for TpmEccCurve {
    type Error = TpmParseError;

    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0003 => Ok(Self::NistP256),
            0x0004 => Ok(Self::NistP384),
            _ => Err(TpmParseError::UnsupportedCurve),
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TpmParseError {
    BufferTooShort,
    BufferTrailingBytes,
    InvalidMagic,
    InvalidType,
    UnsupportedAlgorithm(&'static str),
    UnsupportedCurve,
    TooManyPcrSelections,
    OversizedBuffer,
}

impl core::fmt::Display for TpmParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooShort => f.write_str("buffer too short for structure"),
            Self::BufferTrailingBytes => f.write_str("unexpected trailing bytes in structure"),
            Self::InvalidMagic => f.write_str("invalid TPM magic number"),
            Self::InvalidType => f.write_str("invalid TPM structure type"),
            Self::UnsupportedAlgorithm(msg) => write!(f, "unsupported algorithm: {msg}"),
            Self::UnsupportedCurve => f.write_str("unsupported ECC curve"),
            Self::TooManyPcrSelections => f.write_str("too many PCR selections (TPM_RC_VALUE)"),
            Self::OversizedBuffer => f.write_str("structure size exceeds safe limit"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TpmParseError {}

// ── Deserializer Utilities ────────────────────────────────────────────────

/// A simple bounds-checked, big-endian reader for parsing TPM structures.
pub struct TpmBuffer<'a> {
    data: &'a [u8],
}

impl<'a> TpmBuffer<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn read_u8(&mut self) -> Result<u8, TpmParseError> {
        if self.data.is_empty() {
            return Err(TpmParseError::BufferTooShort);
        }
        let val = self.data[0];
        self.data = &self.data[1..];
        Ok(val)
    }

    pub fn read_u16(&mut self) -> Result<u16, TpmParseError> {
        if self.data.len() < 2 {
            return Err(TpmParseError::BufferTooShort);
        }
        let val = u16::from_be_bytes([self.data[0], self.data[1]]);
        self.data = &self.data[2..];
        Ok(val)
    }

    pub fn read_u32(&mut self) -> Result<u32, TpmParseError> {
        if self.data.len() < 4 {
            return Err(TpmParseError::BufferTooShort);
        }
        let val = u32::from_be_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]);
        self.data = &self.data[4..];
        Ok(val)
    }

    pub fn read_u64(&mut self) -> Result<u64, TpmParseError> {
        if self.data.len() < 8 {
            return Err(TpmParseError::BufferTooShort);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[..8]);
        let val = u64::from_be_bytes(buf);
        self.data = &self.data[8..];
        Ok(val)
    }

    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], TpmParseError> {
        if self.data.len() < len {
            return Err(TpmParseError::BufferTooShort);
        }
        let (head, tail) = self.data.split_at(len);
        self.data = tail;
        Ok(head)
    }

    pub fn read_byte_buffer(&mut self) -> Result<&'a [u8], TpmParseError> {
        let len = self.read_u16()? as usize;
        self.read_bytes(len)
    }

    pub fn read_alg_id(&mut self) -> Result<TpmAlgId, TpmParseError> {
        TpmAlgId::try_from(self.read_u16()?)
    }
}

// ── TPM2B_ATTEST / TPMS_ATTEST ────────────────────────────────────────────

/// Represents a parsed `TPMS_ATTEST` structure.
#[derive(Debug, Clone)]
pub struct TpmsAttest<'a> {
    pub magic: u32,
    pub attest_type: u16, // TPM_ST_ATTEST_QUOTE is 0x8018
    pub qualified_signer: &'a [u8],
    pub extra_data: &'a [u8],
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
    pub firmware_version: u64,
    pub attested: TpmsQuoteInfo<'a>,
}

#[derive(Debug, Clone)]
pub struct TpmsQuoteInfo<'a> {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: &'a [u8],
}

impl<'a> TpmsAttest<'a> {
    /// Parses a `TPM2B_ATTEST` containing a `TPMS_ATTEST`.
    pub fn parse_tpm2b(data: &'a [u8]) -> Result<Self, TpmParseError> {
        let mut buf = TpmBuffer::new(data);
        let len = buf.read_u16()? as usize;
        if len > 2048 {
            return Err(TpmParseError::OversizedBuffer);
        }
        let attest_data = buf.read_bytes(len)?;
        if !buf.is_empty() {
            return Err(TpmParseError::BufferTrailingBytes);
        }
        Self::parse(&mut TpmBuffer::new(attest_data))
    }

    /// Parses a raw `TPMS_ATTEST` structure.
    pub fn parse(buf: &mut TpmBuffer<'a>) -> Result<Self, TpmParseError> {
        let magic = buf.read_u32()?;
        if magic != 0xFF54_4347 {
            // TPM_GENERATED_VALUE
            return Err(TpmParseError::InvalidMagic);
        }

        let attest_type = buf.read_u16()?;
        if attest_type != 0x8018 {
            // TPM_ST_ATTEST_QUOTE
            return Err(TpmParseError::InvalidType);
        }

        let qualified_signer = buf.read_byte_buffer()?;
        let extra_data = buf.read_byte_buffer()?;

        // TPMS_CLOCK_INFO
        let clock = buf.read_u64()?;
        let reset_count = buf.read_u32()?;
        let restart_count = buf.read_u32()?;
        let safe = buf.read_u8()? != 0;

        let firmware_version = buf.read_u64()?;

        // TPMS_QUOTE_INFO
        let pcr_select = TpmlPcrSelection::parse(buf)?;
        let pcr_digest = buf.read_byte_buffer()?;

        Ok(Self {
            magic,
            attest_type,
            qualified_signer,
            extra_data,
            clock,
            reset_count,
            restart_count,
            safe,
            firmware_version,
            attested: TpmsQuoteInfo {
                pcr_select,
                pcr_digest,
            },
        })
    }
}

// ── TPML_PCR_SELECTION ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TpmlPcrSelection {
    pub selections: Vec<TpmsPcrSelection>,
}

#[derive(Debug, Clone)]
pub struct TpmsPcrSelection {
    pub hash: TpmAlgId,
    pub pcr_select: Vec<u8>,
}

impl TpmlPcrSelection {
    pub fn parse(buf: &mut TpmBuffer<'_>) -> Result<Self, TpmParseError> {
        let count = buf.read_u32()?;
        if count > 16 {
            // TPM_PT_PCR_COUNT max is typically 24, but banks are few
            return Err(TpmParseError::TooManyPcrSelections);
        }
        let mut selections = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let hash = buf.read_alg_id()?;
            let size = buf.read_u8()? as usize;
            if size > 4 {
                // PCR count is max 32 for PC Client
                return Err(TpmParseError::TooManyPcrSelections);
            }
            let select_bytes = buf.read_bytes(size)?;
            selections.push(TpmsPcrSelection {
                hash,
                pcr_select: select_bytes.to_vec(),
            });
        }
        Ok(Self { selections })
    }
}

// ── TPMT_SIGNATURE ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum TpmtSignature<'a> {
    Rsapss {
        hash: TpmAlgId,
        sig: &'a [u8],
    },
    Ecdsa {
        hash: TpmAlgId,
        r: &'a [u8],
        s: &'a [u8],
    },
}

impl<'a> TpmtSignature<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, TpmParseError> {
        let mut buf = TpmBuffer::new(data);
        let sig_alg = buf.read_alg_id()?;
        match sig_alg {
            TpmAlgId::Rsapss => {
                let hash = buf.read_alg_id()?;
                let sig = buf.read_byte_buffer()?;
                Ok(Self::Rsapss { hash, sig })
            }
            TpmAlgId::Ecdsa => {
                let hash = buf.read_alg_id()?;
                let r = buf.read_byte_buffer()?;
                let s = buf.read_byte_buffer()?;
                Ok(Self::Ecdsa { hash, r, s })
            }
            _ => Err(TpmParseError::UnsupportedAlgorithm(
                "signature algorithm not supported",
            )),
        }
    }
}

// ── TPMT_PUBLIC ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum TpmtPublic<'a> {
    Rsa {
        name_alg: TpmAlgId,
        public_exponent: u32,
        unique: &'a [u8],
    },
    Ecc {
        name_alg: TpmAlgId,
        curve: TpmEccCurve,
        x: &'a [u8],
        y: &'a [u8],
    },
}

impl<'a> TpmtPublic<'a> {
    pub fn parse_tpm2b(data: &'a [u8]) -> Result<Self, TpmParseError> {
        let mut buf = TpmBuffer::new(data);
        let size = buf.read_u16()? as usize;
        if size > 2048 {
            return Err(TpmParseError::OversizedBuffer);
        }
        let pub_data = buf.read_bytes(size)?;
        Self::parse(&mut TpmBuffer::new(pub_data))
    }

    pub fn parse(buf: &mut TpmBuffer<'a>) -> Result<Self, TpmParseError> {
        let type_alg = buf.read_alg_id()?;
        let name_alg = buf.read_alg_id()?;

        // objectAttributes (TPMA_OBJECT)
        let _object_attributes = buf.read_u32()?;

        // authPolicy (TPM2B_DIGEST)
        let _auth_policy = buf.read_byte_buffer()?;

        match type_alg {
            TpmAlgId::Rsa => {
                // TPMS_RSA_PARMS
                let _symmetric = buf.read_u16()?; // symmetric alg
                let _scheme = buf.read_u16()?; // scheme
                let _key_bits = buf.read_u16()?; // keyBits
                let exponent = buf.read_u32()?; // exponent

                // TPM2B_PUBLIC_KEY_RSA
                let unique = buf.read_byte_buffer()?;
                Ok(Self::Rsa {
                    name_alg,
                    public_exponent: exponent,
                    unique,
                })
            }
            TpmAlgId::Ecc => {
                // TPMS_ECC_PARMS
                let _symmetric = buf.read_u16()?;
                let _scheme = buf.read_u16()?;
                let curve = TpmEccCurve::try_from(buf.read_u16()?)?;
                let _kdf = buf.read_u16()?;

                // TPMS_ECC_POINT
                let x = buf.read_byte_buffer()?;
                let y = buf.read_byte_buffer()?;
                Ok(Self::Ecc {
                    name_alg,
                    curve,
                    x,
                    y,
                })
            }
            _ => Err(TpmParseError::UnsupportedAlgorithm(
                "unsupported public key type",
            )),
        }
    }
}
