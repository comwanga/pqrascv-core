//! Per-key usage tracking: operation counters and last-used timestamp.
//!
//! Counters are updated only on **successful** operations. The tracker is
//! thread-safe (an internal `Mutex`) so it can be shared across the daemon's
//! connection tasks, and is queryable for monitoring / quota purposes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::audit::now_unix_ms;
use crate::policy::Operation;

/// A point-in-time snapshot of usage statistics for a single key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUsage {
    /// Count of successful operations per operation kind.
    pub per_operation: BTreeMap<String, u64>,
    /// Total successful operations across all kinds.
    pub total: u64,
    /// Wall-clock time of the most recent successful operation, in milliseconds
    /// since the Unix epoch. `None` if the key has never been used successfully.
    pub last_used_unix_ms: Option<u128>,
}

impl KeyUsage {
    /// Successful-operation count for a specific operation kind.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn count(&self, op: Operation) -> u64 {
        self.per_operation.get(op.as_str()).copied().unwrap_or(0)
    }
}

/// Thread-safe per-key usage tracker.
#[derive(Debug, Default)]
pub struct UsageTracker {
    keys: Mutex<BTreeMap<String, KeyUsage>>,
}

impl UsageTracker {
    /// Creates an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one **successful** operation against `key`: increments the
    /// per-operation and total counters and updates the last-used timestamp.
    pub fn record_success(&self, key: &str, op: Operation) {
        self.record_success_at(key, op, now_unix_ms());
    }

    /// Like [`record_success`](Self::record_success) but with an explicit
    /// timestamp (used by tests for determinism).
    pub fn record_success_at(&self, key: &str, op: Operation, ts_unix_ms: u128) {
        let mut guard = self
            .keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = guard.entry(key.to_string()).or_default();
        *entry.per_operation.entry(op.as_str().to_string()).or_insert(0) += 1;
        entry.total += 1;
        entry.last_used_unix_ms = Some(ts_unix_ms);
    }

    /// Returns a snapshot of usage for `key`, or `None` if it has never been
    /// used successfully.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn usage(&self, key: &str) -> Option<KeyUsage> {
        self.keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .cloned()
    }

    /// Returns the successful-operation count for `(key, op)`, defaulting to 0.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn count(&self, key: &str, op: Operation) -> u64 {
        self.keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .map_or(0, |u| u.count(op))
    }

    /// Snapshot of usage for every tracked key.
    #[must_use]
    pub fn snapshot(&self) -> BTreeMap<String, KeyUsage> {
        self.keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unused_key_has_no_usage() {
        let tracker = UsageTracker::new();
        assert!(tracker.usage("ghost").is_none());
        assert_eq!(tracker.count("ghost", Operation::Sign), 0);
    }

    #[test]
    fn record_success_increments_counters_and_total() {
        let tracker = UsageTracker::new();
        tracker.record_success("k", Operation::Sign);
        tracker.record_success("k", Operation::Sign);
        tracker.record_success("k", Operation::Export);

        assert_eq!(tracker.count("k", Operation::Sign), 2);
        assert_eq!(tracker.count("k", Operation::Export), 1);
        let usage = tracker.usage("k").unwrap();
        assert_eq!(usage.total, 3);
        assert!(usage.last_used_unix_ms.is_some());
    }

    #[test]
    fn last_used_timestamp_advances() {
        let tracker = UsageTracker::new();
        tracker.record_success_at("k", Operation::Sign, 100);
        assert_eq!(tracker.usage("k").unwrap().last_used_unix_ms, Some(100));
        tracker.record_success_at("k", Operation::Sign, 250);
        assert_eq!(tracker.usage("k").unwrap().last_used_unix_ms, Some(250));
    }

    #[test]
    fn counters_are_isolated_per_key() {
        let tracker = UsageTracker::new();
        tracker.record_success("a", Operation::Sign);
        tracker.record_success("b", Operation::Delete);
        assert_eq!(tracker.count("a", Operation::Sign), 1);
        assert_eq!(tracker.count("a", Operation::Delete), 0);
        assert_eq!(tracker.count("b", Operation::Delete), 1);
        assert_eq!(tracker.snapshot().len(), 2);
    }
}
