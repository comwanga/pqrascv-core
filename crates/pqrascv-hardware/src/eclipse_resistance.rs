use alloc::collections::BTreeSet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerDiversityConstraints {
    pub min_active_peers: usize,
    pub min_regional_spread: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SynchronizationSpread {
    pub active_regions: BTreeSet<String>,
    pub unique_peer_sources: usize,
}

/// Tracks connectivity to detect and prevent eclipse attacks.
/// Fails closed if synchronization becomes overly concentrated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationConnectivityReport {
    pub total_known_peers: usize,
    pub reachable_peers: usize,
    pub spread: SynchronizationSpread,
    pub is_eclipsed: bool,
}

impl FederationConnectivityReport {
    #[must_use]
    pub fn evaluate(
        known_peers: usize,
        reachable_peers: usize,
        spread: SynchronizationSpread,
        constraints: &PeerDiversityConstraints,
    ) -> Self {
        // Fail closed if synchronization spread is dangerously low
        let is_eclipsed = reachable_peers < constraints.min_active_peers
            || spread.active_regions.len() < constraints.min_regional_spread
            || spread.unique_peer_sources < (constraints.min_active_peers / 2).max(1);

        Self {
            total_known_peers: known_peers,
            reachable_peers,
            spread,
            is_eclipsed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_eclipse_when_spread_is_insufficient() {
        let mut regions = BTreeSet::new();
        regions.insert("us-east".to_string());

        let spread = SynchronizationSpread {
            active_regions: regions,
            unique_peer_sources: 1,
        };

        let constraints = PeerDiversityConstraints {
            min_active_peers: 3,
            min_regional_spread: 2,
        };

        let report = FederationConnectivityReport::evaluate(10, 1, spread, &constraints);
        assert!(report.is_eclipsed);
    }
}
