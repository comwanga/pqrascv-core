//! Hybrid Logical Clocks and Federation Time Semantics
//!
//! Provides tracking for temporal causal ordering without requiring full
//! vector clocks, scaling to large federations with bounded drift policies.

use core::cmp::Ordering;
use serde::{Deserialize, Serialize};

/// A Hybrid Logical Clock (HLC) combining logical causal progression with
/// signed physical timestamps for drift/skew tracking.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridLogicalClock {
    /// Incremented on every causal event (the Lamport component).
    pub logical_counter: u64,
    /// The physical wall-clock time observed by the node at event creation (Unix seconds).
    pub physical_timestamp: u64,
    /// Cryptographic signature of `(logical_counter || physical_timestamp)` by the issuing verifier.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl PartialOrd for HybridLogicalClock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HybridLogicalClock {
    fn cmp(&self, other: &Self) -> Ordering {
        // Causality is strictly determined by the logical counter first.
        match self.logical_counter.cmp(&other.logical_counter) {
            Ordering::Equal => self.physical_timestamp.cmp(&other.physical_timestamp),
            other_ordering => other_ordering,
        }
    }
}

impl HybridLogicalClock {
    /// Evaluates if an observed physical time from another clock exceeds
    /// the maximum allowable drift (skew limit).
    #[must_use]
    pub fn exceeds_skew(&self, other: &Self, max_skew_seconds: u64) -> bool {
        let diff = self.physical_timestamp.abs_diff(other.physical_timestamp);
        diff > max_skew_seconds
    }
}

/// Defines federation-wide temporal boundaries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedTimeSkew {
    /// Maximum allowed difference between two nodes' physical timestamps
    /// in the same causal event window.
    pub max_drift_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlc_ordering() {
        let a = HybridLogicalClock {
            logical_counter: 1,
            physical_timestamp: 1000,
            signature: vec![],
        };
        let b = HybridLogicalClock {
            logical_counter: 2,
            physical_timestamp: 900,
            signature: vec![],
        };
        // Even though b is physically older, it is logically newer.
        assert!(a < b);

        let c = HybridLogicalClock {
            logical_counter: 1,
            physical_timestamp: 1001,
            signature: vec![],
        };
        // If logical counters are equal, fallback to physical time.
        assert!(a < c);
    }

    #[test]
    fn test_skew_enforcement() {
        let a = HybridLogicalClock {
            logical_counter: 1,
            physical_timestamp: 1000,
            signature: vec![],
        };
        let b = HybridLogicalClock {
            logical_counter: 2,
            physical_timestamp: 1050,
            signature: vec![],
        };

        assert!(!a.exceeds_skew(&b, 60)); // 50 <= 60
        assert!(a.exceeds_skew(&b, 40)); // 50 > 40
    }
}
