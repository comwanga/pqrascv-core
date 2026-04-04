//! Provenance layer — in-toto attestations and SLSA v1 predicates.
//!
//! # Design
//!
//! [`InTotoAttestation`] is an owned, CBOR-serialisable representation of
//! in-toto statement metadata.  It follows the in-toto Attestation Framework
//! v1 schema (see <https://github.com/in-toto/attestation>).
//!
//! [`SlsaPredicateBuilder`] constructs SLSA v1 build provenance predicates
//! and embeds them inside an [`InTotoAttestation`].
//!
//! # No-std considerations
//!
//! Both types require `alloc` (they contain `Vec`/`String` fields) but are
//! otherwise `no_std`-compatible.  On bare-metal targets that supply an
//! allocator (e.g. `embedded-alloc`) this module works unchanged.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "alloc")]
use crate::error::PqRascvError;

// ────────────────────────────────────────────────────────────────────────────
// Subject
// ────────────────────────────────────────────────────────────────────────────

/// A subject in an in-toto statement — identifies the artefact being attested.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Subject {
    /// Human-readable name (e.g. `"firmware-v1.2.3.bin"`).
    pub name: String,
    /// SHA3-256 digest of the artefact (hex-encoded, lowercase).
    pub digest_sha3_256: String,
}

#[cfg(feature = "alloc")]
impl Subject {
    /// Creates a new [`Subject`] from a name and raw digest bytes.
    pub fn new(name: impl Into<String>, digest: &[u8; 32]) -> Self {
        use core::fmt::Write as _;
        let mut hex = String::with_capacity(64);
        for byte in digest {
            write!(hex, "{byte:02x}").expect("write to String never fails");
        }
        Self {
            name: name.into(),
            digest_sha3_256: hex,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Build metadata
// ────────────────────────────────────────────────────────────────────────────

/// SLSA v1 build metadata embedded in a provenance predicate.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BuildMetadata {
    /// URI of the builder (e.g. `"https://github.com/actions/runner"`).
    pub builder_id: String,
    /// Build config reference (e.g. git commit SHA of the build script).
    pub build_config_ref: String,
    /// Unix timestamp (seconds since epoch) when the build started.
    pub build_started_on: u64,
    /// Unix timestamp (seconds since epoch) when the build finished.
    pub build_finished_on: u64,
    /// SHA3-256 of the SBOM document (or all-zero if not present).
    pub sbom_hash: [u8; 32],
    /// SLSA level achieved (1–4).
    pub slsa_level: u8,
}

// ────────────────────────────────────────────────────────────────────────────
// InTotoAttestation
// ────────────────────────────────────────────────────────────────────────────

/// Serialisable in-toto v1 attestation statement.
///
/// Wire format: CBOR via serde.
///
/// ```text
/// {
///   "predicateType": "https://slsa.dev/provenance/v1",
///   "subject": [ { "name": "...", "digestSha3_256": "..." } ],
///   "build": { ... }
/// }
/// ```
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InTotoAttestation {
    /// Must be `"https://slsa.dev/provenance/v1"` for SLSA v1.
    pub predicate_type: String,
    /// List of attested subjects.
    pub subjects: Vec<Subject>,
    /// SLSA build provenance predicate.
    pub build: BuildMetadata,
}

#[cfg(feature = "alloc")]
impl InTotoAttestation {
    /// Returns the SLSA level from the embedded build metadata.
    #[must_use]
    pub fn slsa_level(&self) -> u8 {
        self.build.slsa_level
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SlsaPredicateBuilder
// ────────────────────────────────────────────────────────────────────────────

/// Builder for SLSA v1 provenance predicates.
///
/// # Example
///
/// ```
/// use pqrascv_core::provenance::SlsaPredicateBuilder;
///
/// let attestation = SlsaPredicateBuilder::new("https://github.com/actions/runner")
///     .with_build_config_ref("abc123def456")
///     .with_timestamps(1_700_000_000, 1_700_001_000)
///     .with_slsa_level(2)
///     .add_subject("firmware.bin", &[0xde; 32])
///     .build()
///     .expect("build failed");
/// ```
#[cfg(feature = "alloc")]
pub struct SlsaPredicateBuilder {
    builder_id: String,
    build_config_ref: String,
    started_on: u64,
    finished_on: u64,
    sbom_hash: [u8; 32],
    slsa_level: u8,
    subjects: Vec<Subject>,
}

#[cfg(feature = "alloc")]
impl SlsaPredicateBuilder {
    /// Creates a new builder with the given `builder_id` URI.
    pub fn new(builder_id: impl Into<String>) -> Self {
        Self {
            builder_id: builder_id.into(),
            build_config_ref: String::new(),
            started_on: 0,
            finished_on: 0,
            sbom_hash: [0u8; 32],
            slsa_level: 1,
            subjects: Vec::new(),
        }
    }

    /// Sets the build configuration reference (e.g. git commit SHA).
    #[must_use]
    pub fn with_build_config_ref(mut self, r#ref: impl Into<String>) -> Self {
        self.build_config_ref = r#ref.into();
        self
    }

    /// Sets build start and finish timestamps (Unix seconds).
    #[must_use]
    pub fn with_timestamps(mut self, started_on: u64, finished_on: u64) -> Self {
        self.started_on = started_on;
        self.finished_on = finished_on;
        self
    }

    /// Sets the SHA3-256 hash of the SBOM document.
    #[must_use]
    pub fn with_sbom_hash(mut self, hash: [u8; 32]) -> Self {
        self.sbom_hash = hash;
        self
    }

    /// Sets the SLSA level (1–4).  Silently clamps to `[1, 4]`.
    #[must_use]
    pub fn with_slsa_level(mut self, level: u8) -> Self {
        self.slsa_level = level.clamp(1, 4);
        self
    }

    /// Adds an attested subject.
    #[must_use]
    pub fn add_subject(mut self, name: impl Into<String>, digest: &[u8; 32]) -> Self {
        self.subjects.push(Subject::new(name, digest));
        self
    }

    /// Consumes the builder and returns a complete [`InTotoAttestation`].
    ///
    /// # Errors
    ///
    /// Returns [`PqRascvError::InvalidProvenance`] if no subjects were added.
    pub fn build(self) -> Result<InTotoAttestation, PqRascvError> {
        if self.subjects.is_empty() {
            return Err(PqRascvError::InvalidProvenance);
        }
        Ok(InTotoAttestation {
            predicate_type: String::from("https://slsa.dev/provenance/v1"),
            subjects: self.subjects,
            build: BuildMetadata {
                builder_id: self.builder_id,
                build_config_ref: self.build_config_ref,
                build_started_on: self.started_on,
                build_finished_on: self.finished_on,
                sbom_hash: self.sbom_hash,
                slsa_level: self.slsa_level,
            },
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn builder_roundtrip() {
        let att = SlsaPredicateBuilder::new("https://ci.example.com")
            .with_build_config_ref("deadbeef")
            .with_timestamps(1_000, 2_000)
            .with_slsa_level(2)
            .add_subject("fw.bin", &[0xabu8; 32])
            .build()
            .expect("build failed");

        assert_eq!(att.slsa_level(), 2);
        assert_eq!(att.subjects.len(), 1);
        assert_eq!(att.predicate_type, "https://slsa.dev/provenance/v1");
    }

    #[test]
    fn builder_rejects_empty_subjects() {
        let result = SlsaPredicateBuilder::new("https://ci.example.com").build();
        assert_eq!(result, Err(PqRascvError::InvalidProvenance));
    }

    #[test]
    fn subject_digest_is_hex_encoded() {
        let digest = [0xffu8; 32];
        let subject = Subject::new("test", &digest);
        assert_eq!(subject.digest_sha3_256.len(), 64);
        assert!(subject
            .digest_sha3_256
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn slsa_level_clamps_to_range() {
        let att = SlsaPredicateBuilder::new("x")
            .with_slsa_level(99)
            .add_subject("fw", &[0u8; 32])
            .build()
            .unwrap();
        assert_eq!(att.slsa_level(), 4);
    }
}
