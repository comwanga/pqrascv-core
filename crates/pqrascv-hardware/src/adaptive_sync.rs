use serde::{Deserialize, Serialize};

/// Role classification for topology-aware synchronization.
/// Does NOT confer any cryptographic authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerRole {
    EdgeVerifier,
    RelayHub,
    RegionalAuthority,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncPriority {
    Critical,
    High,
    Normal,
    Background,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SynchronizationHealth {
    Healthy,
    Degraded,
    Starving,
    Flooded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncBackoffState {
    pub peer_id: String,
    pub consecutive_failures: u32,
    pub next_retry_timestamp: u64,
}

impl SyncBackoffState {
    #[must_use]
    pub fn new(peer_id: String) -> Self {
        Self {
            peer_id,
            consecutive_failures: 0,
            next_retry_timestamp: 0,
        }
    }

    pub fn record_failure(&mut self, current_time: u64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        // Exponential backoff to prevent network flooding during partitions
        let backoff_seconds = 2_u64.pow(self.consecutive_failures.min(10));
        self.next_retry_timestamp = current_time.saturating_add(backoff_seconds);
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.next_retry_timestamp = 0;
    }

    #[must_use]
    pub fn can_sync(&self, current_time: u64) -> bool {
        current_time >= self.next_retry_timestamp
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AdaptiveSyncEngine {
    pub backoff_states: alloc::collections::BTreeMap<String, SyncBackoffState>,
}

impl AdaptiveSyncEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_create_backoff(&mut self, peer_id: &str) -> &mut SyncBackoffState {
        self.backoff_states
            .entry(peer_id.to_string())
            .or_insert_with(|| SyncBackoffState::new(peer_id.to_string()))
    }

    #[must_use]
    pub fn evaluate_health(&self) -> SynchronizationHealth {
        if self.backoff_states.is_empty() {
            return SynchronizationHealth::Healthy;
        }

        let failing_peers = self
            .backoff_states
            .values()
            .filter(|s| s.consecutive_failures > 5)
            .count();
        let total_peers = self.backoff_states.len();

        // Fail-closed: Ensure synchronization health does not mask severe network degradation
        if failing_peers == total_peers {
            SynchronizationHealth::Starving
        } else if failing_peers > total_peers / 2 {
            SynchronizationHealth::Degraded
        } else {
            SynchronizationHealth::Healthy
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_backoff_scales_correctly() {
        let mut state = SyncBackoffState::new("peer1".into());
        state.record_failure(100);
        assert_eq!(state.next_retry_timestamp, 102); // 100 + 2^1

        state.record_failure(102);
        assert_eq!(state.next_retry_timestamp, 106); // 102 + 2^2
    }

    #[test]
    fn synchronization_health_degrades_under_failure() {
        let mut engine = AdaptiveSyncEngine::new();
        engine.get_or_create_backoff("peer1").consecutive_failures = 6;
        engine.get_or_create_backoff("peer2").consecutive_failures = 6;
        engine.get_or_create_backoff("peer3").consecutive_failures = 0;

        // 2 out of 3 failing > 50%
        assert_eq!(engine.evaluate_health(), SynchronizationHealth::Degraded);
    }
}
