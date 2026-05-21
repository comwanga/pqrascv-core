//! Hardware backend trait and type definitions.
//!
//! # Design
//!
//! [`HardwareRootOfTrust`] is the central trait. Every hardware backend
//! implements it. The trait returns [`HardwareEvidence`] — a strongly-typed
//! envelope that carries the backend type, capabilities, and all measurements.
//!
//! # Backend Type Enforcement
//!
//! [`HardwareBackendType::TestOnly`] requires the `unsafe-test-backend`
//! feature flag. It is impossible to construct in a production build.
//! The policy engine's `hardware_production()` preset explicitly rejects it.
//!
//! # Capabilities
//!
//! [`HardwareCapabilities`] declares what a backend can provide. The verifier
//! checks capabilities before applying rules that require them (e.g.
//! `RequireHardwareMonotonicCounter` is only evaluated if the backend
//! advertises `has_monotonic_counter`).

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    counter::CounterEvidence,
    digest::TypedDigest,
    pcr::TypedPcrBank,
};

// ── HardwareBackendType ───────────────────────────────────────────────────

/// Identifies the hardware technology that produced a set of measurements.
///
/// This is a wire-stable discriminant — do not reorder variants.
/// New variants must be added at the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum HardwareBackendType {
    /// TPM 2.0 (Trusted Platform Module). Measurements rooted in TPM firmware,
    /// which executes before and outside the attested OS.
    Tpm2 = 0x01,
    /// DICE (Device Identifier Composition Engine). Measurements derived from
    /// a hardware Unique Device Secret via one-way CDI derivation.
    Dice = 0x02,
    /// Intel Trust Domain Extensions. Measurements rooted in CPU microcode,
    /// below the hypervisor.
    IntelTdx = 0x03,
    /// AMD Secure Encrypted Virtualization — Secure Nested Paging.
    /// Measurements rooted in AMD PSP firmware.
    AmdSevSnp = 0x04,
    /// AWS Nitro Enclave. Measurements rooted in the Nitro hypervisor.
    NitroEnclave = 0x05,
    /// Test-only software backend. MUST NOT appear in production evidence.
    ///
    /// This variant is only constructible when the `unsafe-test-backend`
    /// feature is enabled. The policy engine's `hardware_production()` preset
    /// rejects it unconditionally.
    #[cfg(feature = "unsafe-test-backend")]
    TestOnly = 0xFF,
}

impl HardwareBackendType {
    /// Returns `true` if this backend type provides a real hardware security
    /// boundary (i.e. measurements occur below attacker-controlled code).
    #[must_use]
    pub fn is_hardware_rooted(self) -> bool {
        match self {
            Self::Tpm2 | Self::Dice | Self::IntelTdx | Self::AmdSevSnp | Self::NitroEnclave => {
                true
            }
            #[cfg(feature = "unsafe-test-backend")]
            Self::TestOnly => false,
        }
    }

    /// Returns a human-readable name for logging and error messages.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tpm2 => "TPM 2.0",
            Self::Dice => "DICE",
            Self::IntelTdx => "Intel TDX",
            Self::AmdSevSnp => "AMD SEV-SNP",
            Self::NitroEnclave => "AWS Nitro Enclave",
            #[cfg(feature = "unsafe-test-backend")]
            Self::TestOnly => "TestOnly (UNSAFE — not for production)",
        }
    }
}

// ── HardwareCapabilities ──────────────────────────────────────────────────

/// Capabilities advertised by a hardware backend.
///
/// The verifier checks these before applying rules that require specific
/// hardware features. A missing capability is not an error — it means the
/// corresponding policy rule cannot be satisfied by this backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HardwareCapabilities {
    /// Backend provides a hardware-backed monotonic counter.
    /// If `false`, `CounterEvidence` will be `Unsupported`.
    pub has_monotonic_counter: bool,
    /// Backend provides an Endorsement Key (EK) certificate chain.
    pub has_ek_certificate: bool,
    /// Backend supports measured boot (PCR extend chain from firmware).
    pub supports_measured_boot: bool,
    /// Backend provides a nonce-bound quote (TPM2_Quote or equivalent).
    pub supports_nonce_binding: bool,
    /// Backend provides a hardware-signed quote (not just measurements).
    pub provides_signed_quote: bool,
}

impl HardwareCapabilities {
    /// Capabilities for a full TPM 2.0 implementation.
    #[must_use]
    pub const fn tpm2_full() -> Self {
        Self {
            has_monotonic_counter: true,
            has_ek_certificate: true,
            supports_measured_boot: true,
            supports_nonce_binding: true,
            provides_signed_quote: true,
        }
    }

    /// Capabilities for a DICE implementation (no EK, no signed quote).
    #[must_use]
    pub const fn dice() -> Self {
        Self {
            has_monotonic_counter: false,
            has_ek_certificate: false,
            supports_measured_boot: true,
            supports_nonce_binding: false,
            provides_signed_quote: false,
        }
    }

    /// Minimal capabilities for test backends.
    #[cfg(feature = "unsafe-test-backend")]
    #[must_use]
    pub const fn test_only() -> Self {
        Self {
            has_monotonic_counter: false,
            has_ek_certificate: false,
            supports_measured_boot: false,
            supports_nonce_binding: false,
            provides_signed_quote: false,
        }
    }
}

// ── HardwareEvidence ──────────────────────────────────────────────────────

/// All evidence collected from a hardware backend in a single attestation.
///
/// This is the output of [`HardwareRootOfTrust::collect_evidence`]. It is
/// a strongly-typed envelope: the backend type is explicit, the PCR bank
/// carries semantic labels, and all digests are algorithm-tagged.
///
/// The verifier consumes `HardwareEvidence` and maps it into a
/// `PolicyContext` for rule evaluation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HardwareEvidence {
    /// The backend that produced this evidence.
    pub backend_type: HardwareBackendType,
    /// Capabilities of the backend that produced this evidence.
    pub capabilities: HardwareCapabilities,
    /// Typed PCR bank (semantic-labeled, algorithm-tagged).
    pub pcr_bank: TypedPcrBank,
    /// SHA3-256 digest of the firmware image being attested.
    pub firmware_digest: TypedDigest,
    /// Optional SHA3-256 digest of an AI model or secondary payload.
    pub secondary_digest: Option<TypedDigest>,
    /// Monotonic counter evidence (hardware-backed or software-observed).
    pub counter: CounterEvidence,
    /// Backend-specific evidence (TPM quote, DICE CDI, TDX report, etc.).
    pub backend_evidence: BackendSpecificEvidence,
}

impl HardwareEvidence {
    /// Returns `true` if all PCR digests use the canonical SHA3-256 algorithm.
    ///
    /// The verifier MUST call this before evaluating PCR-based policy rules.
    #[must_use]
    pub fn pcrs_are_normalized(&self) -> bool {
        self.pcr_bank.all_normalized()
    }

    /// Returns `true` if this evidence came from a hardware-rooted backend.
    #[must_use]
    pub fn is_hardware_rooted(&self) -> bool {
        self.backend_type.is_hardware_rooted()
    }
}

// ── BackendSpecificEvidence ───────────────────────────────────────────────

/// Backend-specific evidence that cannot be expressed in the common model.
///
/// The verifier uses this for backend-specific validation steps (e.g. TPM
/// quote signature verification, DICE CDI chain validation).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum BackendSpecificEvidence {
    /// TPM 2.0 quote evidence.
    Tpm2(TpmQuoteEvidence),
    /// DICE CDI derivation evidence.
    Dice(DiceEvidence),
    /// Intel TDX attestation report (placeholder — full impl in Phase 4).
    IntelTdx(TdxEvidence),
    /// AMD SEV-SNP attestation report (placeholder — full impl in Phase 4).
    AmdSevSnp(SevSnpEvidence),
    /// AWS Nitro Enclave attestation document (placeholder).
    NitroEnclave(NitroEnclaveEvidence),
    /// Test-only evidence. Rejected by production policy.
    #[cfg(feature = "unsafe-test-backend")]
    TestOnly,
}

// ── TpmQuoteEvidence ──────────────────────────────────────────────────────

/// TPM 2.0 quote evidence — the output of `TPM2_Quote`.
///
/// Contains the raw quote blob, its signature, the PCR selection that was
/// quoted, and the AK/EK identity information.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TpmQuoteEvidence {
    /// Raw `TPMS_ATTEST` structure from `TPM2_Quote` (CBOR byte string).
    #[serde(with = "serde_bytes")]
    pub quote_blob: Vec<u8>,
    /// Signature over `quote_blob` by the Attestation Key.
    #[serde(with = "serde_bytes")]
    pub quote_signature: Vec<u8>,
    /// TPM identity (AK public key + optional EK).
    pub identity: TpmIdentity,
    /// Clock information from the TPM (for freshness evidence).
    pub clock_info: TpmClockInfo,
    /// The nonce that was bound into this quote (must match the challenge).
    pub qualifying_data: [u8; 32],
}

/// TPM identity — Attestation Key and optional Endorsement Key.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TpmIdentity {
    /// TPM Attestation Key public area (CBOR byte string).
    ///
    /// This is the key that signed the quote. The verifier must confirm
    /// it is certified by the EK certificate chain.
    #[serde(with = "serde_bytes")]
    pub ak_pub: Vec<u8>,
    /// TPM Endorsement Key public area (optional, CBOR byte string).
    ///
    /// When present, the verifier can validate the AK against the EK
    /// certificate chain to confirm the TPM is genuine hardware.
    #[serde(with = "serde_bytes")]
    pub ek_pub: Option<Vec<u8>>,
    /// TPM manufacturer identifier (e.g. `"IFX"` for Infineon).
    pub manufacturer: Option<alloc::string::String>,
    /// TPM firmware version string.
    pub firmware_version: Option<alloc::string::String>,
}

/// TPM clock information embedded in every `TPM2_Quote`.
///
/// Provides a hardware-backed time reference. The `clock` field is a
/// monotonically increasing millisecond counter that resets only on TPM
/// clear. The `reset_count` and `restart_count` track power cycles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TpmClockInfo {
    /// Milliseconds since the last TPM clear (monotonic within a TPM lifetime).
    pub clock_ms: u64,
    /// Number of times the TPM has been reset (power cycle counter).
    pub reset_count: u32,
    /// Number of times the TPM has been restarted without a full reset.
    pub restart_count: u32,
    /// `true` if the TPM clock has been set since the last clear.
    pub safe: bool,
}

// ── DiceEvidence ──────────────────────────────────────────────────────────

/// DICE CDI derivation evidence.
///
/// Contains the attestation CDI (safe to include in quotes — it is a
/// one-way derivation of the hardware UDS) and the layered measurements
/// that produced it.
///
/// The `cdi_seal` is NOT included in quotes — it is a device secret used
/// for sealing operations and must never leave the device.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DiceEvidence {
    /// Attestation CDI: `SHA3-256(UDS ‖ "DICE-attest" ‖ FWID)`.
    ///
    /// Safe to include in attestation quotes. One-way derivation of the UDS.
    pub cdi_attest: TypedDigest,
    /// Layered firmware measurements that produced the CDI chain.
    ///
    /// Index 0 is the first layer (bootloader), subsequent entries are
    /// higher layers. Each entry is the FWID used in that layer's CDI
    /// derivation.
    pub layered_measurements: Vec<TypedDigest>,
}

// ── Confidential Computing Placeholders ──────────────────────────────────
//
// These types define the evidence envelope for future backends.
// They do NOT implement fake verification logic — they are extensible
// containers for the raw attestation reports that Phase 4 will verify.

/// Intel TDX attestation evidence (Phase 4 placeholder).
///
/// In a full implementation, this would contain the TDX Quote (TD Report
/// + QE Report + QE Cert Chain) as produced by the Intel DCAP library.
/// The verifier would validate it against Intel's PCK certificate hierarchy.
///
/// # Security Note
///
/// Do NOT implement fake TDX verification. The raw report bytes must be
/// validated by a proper DCAP verifier (Intel's `tdx-attest` library or
/// an equivalent). This placeholder exists to define the wire format.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TdxEvidence {
    /// Raw TDX Quote bytes (TD Report + QE Report + cert chain).
    #[serde(with = "serde_bytes")]
    pub raw_quote: Vec<u8>,
    /// TD measurement register 0 (MRTD) — SHA-384 of the initial TD image.
    #[serde(with = "serde_bytes")]
    pub mrtd: Vec<u8>,
    /// Runtime measurement registers RTMR[0..3] — each 48 bytes, stored as Vec.
    pub rtmr: [alloc::vec::Vec<u8>; 4],
}

/// AMD SEV-SNP attestation evidence (Phase 4 placeholder).
///
/// In a full implementation, this would contain the SNP Attestation Report
/// as produced by the `sev-snp-measure` tool or the AMD PSP firmware.
/// The verifier would validate it against AMD's ARK/ASK certificate chain.
///
/// # Security Note
///
/// Do NOT implement fake SEV-SNP verification. The raw report must be
/// validated by AMD's `snpguest` tool or equivalent. This placeholder
/// defines the wire format only.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SevSnpEvidence {
    /// Raw SNP Attestation Report (1184 bytes from AMD PSP).
    #[serde(with = "serde_bytes")]
    pub raw_report: Vec<u8>,
    /// MEASUREMENT field from the report (SHA-384 of the initial memory).
    #[serde(with = "serde_bytes")]
    pub measurement: Vec<u8>,
}

/// AWS Nitro Enclave attestation evidence (Phase 4 placeholder).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NitroEnclaveEvidence {
    /// CBOR-encoded attestation document from the Nitro hypervisor.
    #[serde(with = "serde_bytes")]
    pub attestation_doc: Vec<u8>,
    /// PCR0: SHA-384 of the enclave image file (EIF).
    #[serde(with = "serde_bytes")]
    pub pcr0: Vec<u8>,
}

// ── HardwareRootOfTrust trait ─────────────────────────────────────────────

/// The central hardware backend abstraction.
///
/// Every hardware backend implements this trait. The trait is object-safe
/// so backends can be used as `Box<dyn HardwareRootOfTrust>` in the verifier.
///
/// # Contract
///
/// - `collect_evidence` MUST be deterministic for the same platform state.
/// - `collect_evidence` MUST bind `nonce` into the evidence (for replay protection).
/// - `backend_type` MUST return the correct discriminant — no spoofing.
/// - `capabilities` MUST accurately reflect what the backend can provide.
pub trait HardwareRootOfTrust {
    /// Collects all hardware evidence for an attestation.
    ///
    /// The `nonce` is bound into the evidence (e.g. as `qualifying_data`
    /// in a TPM quote) to prevent replay attacks.
    ///
    /// # Errors
    ///
    /// Returns `HardwareError` if any measurement step fails.
    fn collect_evidence(&self, nonce: &[u8; 32]) -> Result<HardwareEvidence, HardwareError>;

    /// Returns the backend type discriminant.
    fn backend_type(&self) -> HardwareBackendType;

    /// Returns the capabilities of this backend.
    fn capabilities(&self) -> HardwareCapabilities;
}

// ── HardwareError ─────────────────────────────────────────────────────────

/// Errors from hardware evidence collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareError {
    /// The hardware device is not accessible (not present, permission denied).
    DeviceUnavailable,
    /// A PCR read operation failed.
    PcrReadFailed,
    /// The TPM quote operation failed.
    QuoteFailed,
    /// The nonce could not be bound into the evidence.
    NonceBidingFailed,
    /// The backend returned an unsupported algorithm.
    UnsupportedAlgorithm,
    /// The evidence structure is internally inconsistent.
    InconsistentEvidence,
    /// The backend feature is not compiled in.
    BackendNotCompiled,
}

impl core::fmt::Display for HardwareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DeviceUnavailable => f.write_str("hardware device unavailable"),
            Self::PcrReadFailed => f.write_str("PCR read failed"),
            Self::QuoteFailed => f.write_str("TPM quote operation failed"),
            Self::NonceBidingFailed => f.write_str("nonce binding failed"),
            Self::UnsupportedAlgorithm => f.write_str("unsupported hash algorithm"),
            Self::InconsistentEvidence => f.write_str("evidence is internally inconsistent"),
            Self::BackendNotCompiled => f.write_str("backend not compiled in"),
        }
    }
}
