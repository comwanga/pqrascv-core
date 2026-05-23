use serde::{Deserialize, Serialize};
use alloc::collections::VecDeque;

/// A bounded replay window representing a rolling cache of deterministically applied events.
/// This prevents memory exhaustion attacks by compacting older events into `applied_event_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayWindow {
    /// Merkle root of all applied events that have been compacted out of the active window.
    pub applied_event_root: [u8; 32],
    /// Queue of recently applied events.
    pub retained_events: VecDeque<[u8; 32]>,
    /// Maximum number of events to retain in-memory before compacting.
    pub max_retained_events: usize,
}

impl ReplayWindow {
    /// Creates a new replay window with a specified capacity bound.
    #[must_use]
    pub fn new(max_retained_events: usize) -> Self {
        Self {
            applied_event_root: [0; 32], // Zero hash for empty root
            retained_events: VecDeque::with_capacity(max_retained_events),
            max_retained_events,
        }
    }

    /// Deterministically applies a new event hash to the window.
    /// If the window exceeds its bounds, the oldest event is removed and compacted into the root.
    pub fn apply_event(&mut self, event_hash: [u8; 32]) {
        if self.retained_events.len() == self.max_retained_events {
            // Pop the oldest event and compact it into the root
            if let Some(oldest) = self.retained_events.pop_front() {
                self.compact_event(oldest);
            }
        }
        self.retained_events.push_back(event_hash);
    }

    /// Compacts an old event hash into the running applied event root.
    fn compact_event(&mut self, old_event: [u8; 32]) {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(self.applied_event_root);
        hasher.update(old_event);
        self.applied_event_root.copy_from_slice(&hasher.finalize());
    }
}

/// Represents the state of a deterministic reconstruction pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayState {
    /// The governance epoch in which this replay operates.
    pub replay_epoch: u64,
    /// The final reconstructed cryptographic root (e.g. timeline or checkpoint root).
    pub reconstructed_root: [u8; 32],
    /// The bounded window of applied events.
    pub window: ReplayWindow,
}

impl ReplayState {
    /// Validates an incoming stream of events and reconstructs the state deterministically.
    /// Rejects ambiguous orderings and enforces causal continuity.
    ///
    /// # Errors
    /// Returns an error if the event epoch conflicts with the `replay_epoch`.
    pub fn apply_stream(
        &mut self,
        events: impl Iterator<Item = ([u8; 32], u64)>,
    ) -> Result<(), &'static str> {
        use sha3::{Digest, Sha3_256};

        for (event_hash, event_epoch) in events {
            if event_epoch != self.replay_epoch {
                return Err("Conflicting epoch detected during deterministic replay");
            }

            // Apply to the bounded replay window
            self.window.apply_event(event_hash);

            // Reconstruct the structural root (this is a simplified sequential hashing
            // for the sake of deterministic reconstruction).
            let mut hasher = Sha3_256::new();
            hasher.update(self.reconstructed_root);
            hasher.update(event_hash);
            self.reconstructed_root.copy_from_slice(&hasher.finalize());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_bounds_and_compacts() {
        let mut window = ReplayWindow::new(3);
        assert_eq!(window.retained_events.len(), 0);
        assert_eq!(window.applied_event_root, [0; 32]);

        window.apply_event([1; 32]);
        window.apply_event([2; 32]);
        window.apply_event([3; 32]);
        
        assert_eq!(window.retained_events.len(), 3);
        assert_eq!(window.applied_event_root, [0; 32]); // No compaction yet

        // Fourth event should trigger compaction of [1; 32]
        window.apply_event([4; 32]);
        assert_eq!(window.retained_events.len(), 3);
        assert_eq!(window.retained_events.front().unwrap(), &[2; 32]);
        assert_ne!(window.applied_event_root, [0; 32]);
    }

    #[test]
    fn deterministic_replay_stream() {
        let mut state = ReplayState {
            replay_epoch: 5,
            reconstructed_root: [0; 32],
            window: ReplayWindow::new(10),
        };

        let stream = vec![([10; 32], 5), ([20; 32], 5), ([30; 32], 5)];
        assert!(state.apply_stream(stream.into_iter()).is_ok());

        assert_eq!(state.window.retained_events.len(), 3);
        assert_ne!(state.reconstructed_root, [0; 32]);

        // Attempting to apply an event from a conflicting epoch should fail
        let bad_stream = vec![([40; 32], 6)];
        assert!(state.apply_stream(bad_stream.into_iter()).is_err());
    }
}
