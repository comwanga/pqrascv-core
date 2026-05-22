//! Linux IMA/Appraisal Integration
//!
//! Provides structures and binary parsers for Linux Integrity Measurement
//! Architecture (IMA) logs, enabling post-boot integrity checks.

use crate::digest::{DigestAlgorithm, TypedDigest};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A single entry parsed from the Linux IMA measurement log.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImaMeasurement {
    /// PCR index where the measurement was extended (typically PCR 10).
    pub pcr: u32,
    /// The template hash recorded in the IMA log.
    pub template_hash: [u8; 20],
    /// The IMA template name (e.g., "ima", "ima-ng", "ima-sig").
    pub template_name: String,
    /// Normalized cryptographic hash of the measured file.
    pub file_hash: TypedDigest,
    /// Absolute or relative path of the measured file.
    pub file_path: String,
}

/// Linux IMA and Appraisal subsystem status and logs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImaEvidence {
    /// Indicates whether IMA measurement is active.
    pub ima_enabled: bool,
    /// Indicates whether Appraisal/EVM enforcement is active.
    pub appraisal_enabled: bool,
    /// Parsed measurements from the binary runtime log.
    pub measurements: Vec<ImaMeasurement>,
}

/// Error types from parsing binary IMA event streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImaParseError {
    /// The event stream ended prematurely while reading fields.
    UnexpectedEof,
    /// A parsed field value was malformed or exceeded safety bounds.
    MalformedField,
    /// The template format is unsupported by the parser.
    UnsupportedTemplate(&'static str),
    /// The event stream exceeded the maximum permissible event limit.
    StreamTooLong,
}

impl core::fmt::Display for ImaParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("IMA log ended unexpectedly"),
            Self::MalformedField => {
                f.write_str("IMA log contained a malformed field or invalid length")
            }
            Self::UnsupportedTemplate(t) => write!(f, "IMA template is unsupported: {t}"),
            Self::StreamTooLong => f.write_str("IMA log exceeded max events limit"),
        }
    }
}

impl ImaEvidence {
    /// Parses a binary IMA measurement list safely under event and size bounds.
    ///
    /// # Errors
    ///
    /// Returns `ImaParseError` if any field size exceeds safety bounds, or
    /// if the stream is truncated or has invalid structure.
    ///
    /// # Errors
    ///
    /// Returns `ImaParseError` if parsing fails.
    #[allow(clippy::too_many_lines, clippy::missing_panics_doc)]
    pub fn parse_binary(mut data: &[u8], max_events: usize) -> Result<Self, ImaParseError> {
        let mut measurements = Vec::new();

        while !data.is_empty() {
            if measurements.len() >= max_events {
                return Err(ImaParseError::StreamTooLong);
            }

            if data.len() < 28 {
                return Err(ImaParseError::UnexpectedEof);
            }

            // PCR (4 bytes) + Template Hash (20 bytes) + Template Name Len (4 bytes)
            let pcr = u32::from_le_bytes(data[0..4].try_into().unwrap());
            let mut template_hash = [0u8; 20];
            template_hash.copy_from_slice(&data[4..24]);

            let name_len = u32::from_le_bytes(data[24..28].try_into().unwrap()) as usize;
            if name_len > 64 || name_len == 0 {
                return Err(ImaParseError::MalformedField);
            }

            if data.len() < 28 + name_len {
                return Err(ImaParseError::UnexpectedEof);
            }

            let name_bytes = &data[28..28 + name_len];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_len);
            let template_name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();

            let mut offset = 28 + name_len;

            let file_hash;
            let file_path;

            if template_name == "ima" {
                // file_hash (20 bytes) + path_len (4 bytes) + path
                if data.len() < offset + 24 {
                    return Err(ImaParseError::UnexpectedEof);
                }
                let mut hash_val = [0u8; 32];
                hash_val[..20].copy_from_slice(&data[offset..offset + 20]);
                file_hash = TypedDigest::new(DigestAlgorithm::Sha3_256, hash_val);
                offset += 20;

                let path_len =
                    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
                if path_len > 1024 {
                    return Err(ImaParseError::MalformedField);
                }
                offset += 4;

                if data.len() < offset + path_len {
                    return Err(ImaParseError::UnexpectedEof);
                }
                file_path = String::from_utf8_lossy(&data[offset..offset + path_len]).into_owned();
                offset += path_len;
            } else if template_name == "ima-ng" || template_name == "ima-sig" {
                // file_hash_len (4 bytes) + file_hash (variable) + path_len (4 bytes) + path
                if data.len() < offset + 4 {
                    return Err(ImaParseError::UnexpectedEof);
                }
                let hash_len =
                    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
                if hash_len > 256 || hash_len == 0 {
                    return Err(ImaParseError::MalformedField);
                }
                offset += 4;

                if data.len() < offset + hash_len + 4 {
                    return Err(ImaParseError::UnexpectedEof);
                }

                let hash_data = &data[offset..offset + hash_len];
                let algo_end = hash_data.iter().position(|&b| b == 0);
                let (_algo, raw_hash) = if let Some(idx) = algo_end {
                    let algo_str = String::from_utf8_lossy(&hash_data[..idx]).into_owned();
                    (algo_str, &hash_data[idx + 1..])
                } else {
                    ("sha1".to_string(), hash_data)
                };

                let mut hash_val = [0u8; 32];
                let copy_len = raw_hash.len().min(32);
                hash_val[..copy_len].copy_from_slice(&raw_hash[..copy_len]);

                let alg = DigestAlgorithm::Sha3_256;
                file_hash = TypedDigest::new(alg, hash_val);
                offset += hash_len;

                let path_len =
                    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
                if path_len > 1024 {
                    return Err(ImaParseError::MalformedField);
                }
                offset += 4;

                if data.len() < offset + path_len {
                    return Err(ImaParseError::UnexpectedEof);
                }
                file_path = String::from_utf8_lossy(&data[offset..offset + path_len]).into_owned();
                offset += path_len;

                if template_name == "ima-sig" {
                    if data.len() < offset + 4 {
                        return Err(ImaParseError::UnexpectedEof);
                    }
                    let sig_len =
                        u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
                    if sig_len > 1024 {
                        return Err(ImaParseError::MalformedField);
                    }
                    offset += 4;

                    if data.len() < offset + sig_len {
                        return Err(ImaParseError::UnexpectedEof);
                    }
                    offset += sig_len;
                }
            } else {
                return Err(ImaParseError::UnsupportedTemplate(
                    "unknown template format",
                ));
            }

            measurements.push(ImaMeasurement {
                pcr,
                template_hash,
                template_name,
                file_hash,
                file_path,
            });

            data = &data[offset..];
        }

        Ok(Self {
            ima_enabled: true,
            appraisal_enabled: true,
            measurements,
        })
    }
}
