use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerPenalty {
    MalformedMessage,
    ReplayAttempt,
    ExcessiveSkew,
    SyncFailure,
    Flooding,
}

impl PeerPenalty {
    #[must_use]
    pub fn severity_score(&self) -> u32 {
        match self {
            Self::SyncFailure => 5,
            Self::ExcessiveSkew => 10,
            Self::MalformedMessage => 25,
            Self::Flooding => 50,
            Self::ReplayAttempt => 100, // Instant isolation
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerIsolationState {
    Active,
    Throttled,
    Isolated,
}

/// Operational peer scoring.
/// This does NOT influence cryptographic trust decisions or consensus validity.
/// It is strictly for synchronization, availability, and protocol compliance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerOperationalScore {
    pub peer_id: String,
    pub penalty_score: u32,
    pub isolation_state: PeerIsolationState,
}

impl PeerOperationalScore {
    #[must_use]
    pub fn new(peer_id: String) -> Self {
        Self {
            peer_id,
            penalty_score: 0,
            isolation_state: PeerIsolationState::Active,
        }
    }

    pub fn apply_penalty(&mut self, penalty: &PeerPenalty) {
        self.penalty_score = self.penalty_score.saturating_add(penalty.severity_score());
        self.evaluate_isolation();
    }

    fn evaluate_isolation(&mut self) {
        if self.penalty_score >= 100 {
            self.isolation_state = PeerIsolationState::Isolated;
        } else if self.penalty_score >= 50 {
            self.isolation_state = PeerIsolationState::Throttled;
        } else {
            self.isolation_state = PeerIsolationState::Active;
        }
    }

    pub fn decay_penalties(&mut self, decay_amount: u32) {
        self.penalty_score = self.penalty_score.saturating_sub(decay_amount);
        self.evaluate_isolation();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn penalties_accumulate_and_isolate() {
        let mut score = PeerOperationalScore::new("peer1".into());
        score.apply_penalty(&PeerPenalty::Flooding);
        assert_eq!(score.isolation_state, PeerIsolationState::Throttled);

        score.apply_penalty(&PeerPenalty::Flooding);
        assert_eq!(score.isolation_state, PeerIsolationState::Isolated);
    }

    #[test]
    fn replay_attempt_causes_instant_isolation() {
        let mut score = PeerOperationalScore::new("peer1".into());
        score.apply_penalty(&PeerPenalty::ReplayAttempt);
        assert_eq!(score.isolation_state, PeerIsolationState::Isolated);
    }
}
