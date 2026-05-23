//! Delta Attestation Serialization & Hash Chaining
//!
//! Provides cryptographically strict canonicalization for runtime state deltas.
//! Ensures identical evidence always computes to the identical rolling hash,
//! preventing consensus fractures across the verifier federation.

use crate::digest::{DigestAlgorithm, TypedDigest};
use crate::runtime_attestation::{RuntimeMeasurement, RuntimeMeasurementDomain};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

/// A strict, canonical representation of incremental changes in runtime state.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeltaAttestation {
    /// The sequence number of the state immediately preceding this delta.
    pub previous_sequence: u64,
    /// The sequence number of the new state resulting from this delta.
    pub current_sequence: u64,
    /// Measurements of processes/files added since the previous sequence.
    pub added_measurements: Vec<RuntimeMeasurement>,
    /// Measurements of processes/files removed since the previous sequence.
    pub removed_measurements: Vec<RuntimeMeasurement>,
    /// The cryptographically linked rolling hash `H(prev_hash || canonical_delta)`.
    pub rolling_hash: TypedDigest,
}

#[derive(serde::Serialize)]
struct CanonicalPayload<'a> {
    prev_seq: u64,
    curr_seq: u64,
    added: &'a [RuntimeMeasurement],
    removed: &'a [RuntimeMeasurement],
    prev_hash: &'a [u8],
}

impl DeltaAttestation {
    /// Constructs a new `DeltaAttestation` by strictly canonicalizing inputs
    /// and chaining against the previous rolling hash.
    pub fn new_chained(
        previous_sequence: u64,
        current_sequence: u64,
        mut added_measurements: Vec<RuntimeMeasurement>,
        mut removed_measurements: Vec<RuntimeMeasurement>,
        previous_hash: &TypedDigest,
        algo: DigestAlgorithm,
    ) -> Result<Self, &'static str> {
        if current_sequence <= previous_sequence {
            return Err("current sequence must be greater than previous sequence");
        }

        // ── Canonical Sorting (Issue 3 Fix) ──────────────────────────────
        //
        // Two verifiers receiving the same events in different orders must
        // produce identical delta roots. Sorting by domain discriminant first
        // partitions events by their trust domain (IMA, TPM, process state,
        // etc.), then sorts deterministically within each domain.
        //
        // Order: domain (by tag repr) → digest.value (lexicographic) → measurement_id
        let domain_tag = |m: &RuntimeMeasurement| -> u8 {
            match m.domain {
                RuntimeMeasurementDomain::KernelModule => 0,
                RuntimeMeasurementDomain::Executable => 1,
                RuntimeMeasurementDomain::Library => 2,
                RuntimeMeasurementDomain::Container => 3,
                RuntimeMeasurementDomain::Process => 4,
                RuntimeMeasurementDomain::Filesystem => 5,
            }
        };
        added_measurements.sort_by(|a, b| {
            domain_tag(a)
                .cmp(&domain_tag(b))
                .then_with(|| a.digest.value.cmp(&b.digest.value))
                .then_with(|| a.measurement_id.cmp(&b.measurement_id))
        });
        removed_measurements.sort_by(|a, b| {
            domain_tag(a)
                .cmp(&domain_tag(b))
                .then_with(|| a.digest.value.cmp(&b.digest.value))
                .then_with(|| a.measurement_id.cmp(&b.measurement_id))
        });

        let payload = CanonicalPayload {
            prev_seq: previous_sequence,
            curr_seq: current_sequence,
            added: &added_measurements,
            removed: &removed_measurements,
            prev_hash: &previous_hash.value,
        };

        let mut cbor_buf = Vec::new();
        ciborium::into_writer(&payload, &mut cbor_buf)
            .map_err(|_| "failed to canonicalize delta to CBOR")?;

        let rolling_hash = match algo {
            DigestAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&cbor_buf);
                TypedDigest {
                    algorithm: DigestAlgorithm::Sha256,
                    value: hasher.finalize().into(),
                }
            }
            DigestAlgorithm::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(&cbor_buf);
                TypedDigest {
                    algorithm: DigestAlgorithm::Sha3_256,
                    value: hasher.finalize().into(),
                }
            }
        };

        Ok(Self {
            previous_sequence,
            current_sequence,
            added_measurements,
            removed_measurements,
            rolling_hash,
        })
    }
}
