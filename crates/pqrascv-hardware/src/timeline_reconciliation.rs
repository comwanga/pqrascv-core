//! Cross-Verifier Timeline Reconciliation
//!
//! Detects inconsistencies between attestation timelines produced by
//! different verifiers. The reconciler is fail-closed: any detected
//! divergence sets `conflicts_detected = true` in the report, and the
//! [`crate::policy::HardwarePolicyRule::RequireTimelineConsistency`] rule
//! will reject evaluation if conflicts are present.
//!
//! # Conflict Types
//!
//! | Type | Meaning |
//! |---|---|
//! | `MissingEvent` | A sequence number present in one timeline is absent from another |
//! | `ConflictingEvent` | The same sequence number maps to different event hashes |
//! | `DivergentHistory` | Timelines agree up to a point then diverge |
//!
//! # Determinism
//!
//! `TimelineReconciler::reconcile` is a pure function: same inputs → same
//! report. No mutable state is carried between calls.

use alloc::string::String;
use alloc::vec::Vec;

use crate::verifier_timeline::{AttestationEvent, AttestationTimeline};

// ── TimelineConflictType ──────────────────────────────────────────────────

/// The kind of inconsistency detected between two verifier timelines.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TimelineConflictType {
    /// A sequence number that exists in one timeline is absent from the other.
    MissingEvent { event_sequence: u64 },
    /// Two timelines carry different content at the same sequence number.
    ConflictingEvent { sequence: u64 },
    /// Timelines agreed up to `from_sequence` then diverged.
    DivergentHistory { from_sequence: u64 },
}

// ── TimelineConflict ──────────────────────────────────────────────────────

/// A single conflict detected between two verifiers' timelines.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimelineConflict {
    /// Identifier of the first verifier.
    pub verifier_a: String,
    /// Identifier of the second verifier.
    pub verifier_b: String,
    /// The specific type of conflict.
    pub conflict_type: TimelineConflictType,
}

// ── TimelineReconciliationReport ──────────────────────────────────────────

/// The outcome of comparing two or more verifier timelines.
///
/// `conflicts_detected` is `true` if any [`TimelineConflict`] was found.
/// `missing_events` is `true` if any `MissingEvent` conflict was found.
/// Both flags are set fail-closed: any ambiguity is treated as a conflict.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimelineReconciliationReport {
    /// Unique identifier for this reconciliation run.
    pub reconciliation_id: String,
    /// Identifiers of all verifiers whose timelines were compared.
    pub verifier_timelines: Vec<String>,
    /// `true` if any conflict was detected.
    pub conflicts_detected: bool,
    /// `true` if any `MissingEvent` conflict was detected.
    pub missing_events: bool,
    /// Detailed list of detected conflicts.
    pub conflict_details: Vec<TimelineConflict>,
}

// ── TimelineReconciler ────────────────────────────────────────────────────

/// Stateless reconciler comparing two [`AttestationTimeline`]s.
pub struct TimelineReconciler;

impl TimelineReconciler {
    /// Compares two timelines and returns a reconciliation report.
    ///
    /// The reconciler examines events by sequence number:
    /// - If a sequence exists in `timeline_a` but not `timeline_b` →
    ///   `MissingEvent`.
    /// - If a sequence exists in `timeline_b` but not `timeline_a` →
    ///   `MissingEvent`.
    /// - If a sequence exists in both but the event hashes differ →
    ///   `ConflictingEvent`.
    /// - If conflicts start at a specific sequence → `DivergentHistory` is
    ///   emitted as an additional diagnostic conflict.
    ///
    /// # Panics
    ///
    /// Does not panic in practice: the inner `unwrap` is guarded by the
    /// surrounding `in_a` binding, which is `Some` whenever the arm is reached.
    #[must_use]
    pub fn reconcile(
        reconciliation_id: String,
        verifier_id_a: String,
        timeline_a: &AttestationTimeline,
        verifier_id_b: String,
        timeline_b: &AttestationTimeline,
    ) -> TimelineReconciliationReport {
        let mut conflicts: Vec<TimelineConflict> = Vec::new();
        let mut missing_events = false;
        let mut first_conflict_seq: Option<u64> = None;

        let events_a = timeline_a.events();
        let events_b = timeline_b.events();

        // Build sequence-indexed views
        let max_seq_a = events_a.iter().map(AttestationEvent::sequence_number).max();
        let max_seq_b = events_b.iter().map(AttestationEvent::sequence_number).max();
        let max_seq = match (max_seq_a, max_seq_b) {
            (Some(a), Some(b)) => core::cmp::max(a, b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => {
                return TimelineReconciliationReport {
                    reconciliation_id,
                    verifier_timelines: alloc::vec![verifier_id_a, verifier_id_b],
                    conflicts_detected: false,
                    missing_events: false,
                    conflict_details: alloc::vec![],
                };
            }
        };

        for seq in 0..=max_seq {
            let in_a = events_a.iter().find(|e| e.sequence_number() == seq);
            let in_b = events_b.iter().find(|e| e.sequence_number() == seq);

            match (in_a, in_b) {
                (Some(ea), Some(eb))
                    if ea.event_hash().value != eb.event_hash().value
                        || ea.event_hash().algorithm != eb.event_hash().algorithm =>
                {
                    if first_conflict_seq.is_none() {
                        first_conflict_seq = Some(seq);
                    }
                    conflicts.push(TimelineConflict {
                        verifier_a: verifier_id_a.clone(),
                        verifier_b: verifier_id_b.clone(),
                        conflict_type: TimelineConflictType::ConflictingEvent { sequence: seq },
                    });
                }
                (Some(_), None) | (None, Some(_)) => {
                    missing_events = true;
                    if first_conflict_seq.is_none() {
                        first_conflict_seq = Some(seq);
                    }
                    conflicts.push(TimelineConflict {
                        verifier_a: verifier_id_a.clone(),
                        verifier_b: verifier_id_b.clone(),
                        conflict_type: TimelineConflictType::MissingEvent {
                            event_sequence: seq,
                        },
                    });
                }
                _ => {} // both present and matching, or both absent — no conflict
            }
        }

        // Emit a DivergentHistory marker if any conflicts were detected
        if let Some(from_seq) = first_conflict_seq {
            conflicts.push(TimelineConflict {
                verifier_a: verifier_id_a.clone(),
                verifier_b: verifier_id_b.clone(),
                conflict_type: TimelineConflictType::DivergentHistory {
                    from_sequence: from_seq,
                },
            });
        }

        let conflicts_detected = !conflicts.is_empty();
        TimelineReconciliationReport {
            reconciliation_id,
            verifier_timelines: alloc::vec![verifier_id_a, verifier_id_b],
            conflicts_detected,
            missing_events,
            conflict_details: conflicts,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::{DigestAlgorithm, TypedDigest};
    use crate::verifier_timeline::{AttestationEvent, AttestationTimeline};

    fn make_event(seq: u64, hash_val: u8) -> AttestationEvent {
        AttestationEvent::RuntimeMeasurementReceived {
            sequence_number: seq,
            timestamp: seq * 1000,
            event_hash: TypedDigest {
                algorithm: DigestAlgorithm::Sha3_256,
                value: [hash_val; 32],
            },
        }
    }

    fn make_timeline(events: &[(u64, u8)]) -> AttestationTimeline {
        let mut t = AttestationTimeline::new("device1".into());
        for &(seq, val) in events {
            t.push(make_event(seq, val));
        }
        t
    }

    #[test]
    fn identical_timelines_no_conflict() {
        let ta = make_timeline(&[(0, 0xaa), (1, 0xbb), (2, 0xcc)]);
        let tb = make_timeline(&[(0, 0xaa), (1, 0xbb), (2, 0xcc)]);
        let report =
            TimelineReconciler::reconcile("r1".into(), "va".into(), &ta, "vb".into(), &tb);
        assert!(!report.conflicts_detected);
        assert!(!report.missing_events);
        assert!(report.conflict_details.is_empty());
    }

    #[test]
    fn missing_event_in_b() {
        let ta = make_timeline(&[(0, 0xaa), (1, 0xbb), (2, 0xcc)]);
        let tb = make_timeline(&[(0, 0xaa), (2, 0xcc)]); // seq 1 missing in b
        let report =
            TimelineReconciler::reconcile("r2".into(), "va".into(), &ta, "vb".into(), &tb);
        assert!(report.conflicts_detected);
        assert!(report.missing_events);
        let missing: Vec<_> = report
            .conflict_details
            .iter()
            .filter(|c| {
                matches!(
                    c.conflict_type,
                    TimelineConflictType::MissingEvent { event_sequence: 1 }
                )
            })
            .collect();
        assert!(!missing.is_empty());
    }

    #[test]
    fn conflicting_event_hash() {
        let ta = make_timeline(&[(0, 0xaa), (1, 0x11)]);
        let tb = make_timeline(&[(0, 0xaa), (1, 0x22)]); // seq 1 has different hash
        let report =
            TimelineReconciler::reconcile("r3".into(), "va".into(), &ta, "vb".into(), &tb);
        assert!(report.conflicts_detected);
        assert!(!report.missing_events);
        let conflicting: Vec<_> = report
            .conflict_details
            .iter()
            .filter(|c| {
                matches!(
                    c.conflict_type,
                    TimelineConflictType::ConflictingEvent { sequence: 1 }
                )
            })
            .collect();
        assert!(!conflicting.is_empty());
    }

    #[test]
    fn divergent_history_marker_emitted() {
        let ta = make_timeline(&[(0, 0xaa), (1, 0x11)]);
        let tb = make_timeline(&[(0, 0xaa), (1, 0x22)]);
        let report =
            TimelineReconciler::reconcile("r4".into(), "va".into(), &ta, "vb".into(), &tb);
        let divergent: Vec<_> = report
            .conflict_details
            .iter()
            .filter(|c| {
                matches!(
                    c.conflict_type,
                    TimelineConflictType::DivergentHistory { from_sequence: 1 }
                )
            })
            .collect();
        assert!(!divergent.is_empty(), "DivergentHistory marker should be present");
    }

    #[test]
    fn both_empty_no_conflict() {
        let ta = AttestationTimeline::new("device1".into());
        let tb = AttestationTimeline::new("device1".into());
        let report =
            TimelineReconciler::reconcile("r5".into(), "va".into(), &ta, "vb".into(), &tb);
        assert!(!report.conflicts_detected);
    }
}
