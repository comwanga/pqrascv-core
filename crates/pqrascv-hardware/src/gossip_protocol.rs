use crate::canonicalization::Canonicalizable;
use alloc::collections::VecDeque;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipEnvelope {
    pub source_peer_id: String,
    pub federation_epoch: u64,
    pub hlc_timestamp: u64,
    pub payload_hash: [u8; 32],
    pub payload: alloc::vec::Vec<u8>,
    pub signature: alloc::vec::Vec<u8>,
}

impl Canonicalizable for GossipEnvelope {
    fn canonical_hash(&self) -> Result<[u8; 32], ()> {
        let mut hasher = crate::hashing::Hasher::new();
        hasher.update(self.source_peer_id.as_bytes());
        hasher.update(&self.federation_epoch.to_be_bytes());
        hasher.update(&self.hlc_timestamp.to_be_bytes());
        hasher.update(&self.payload_hash);
        Ok(hasher.finalize())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipPeerState {
    pub peer_id: String,
    pub last_seen_hlc: u64,
    pub known_epochs: alloc::vec::Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct GossipDeduplication {
    seen_messages: VecDeque<[u8; 32]>,
    max_capacity: usize,
}

impl GossipDeduplication {
    #[must_use]
    pub fn new(max_capacity: usize) -> Self {
        Self {
            seen_messages: VecDeque::with_capacity(max_capacity),
            max_capacity,
        }
    }

    /// Checks if a message has been seen. If not, it records it and returns false.
    /// Used to prevent replay loops in standard gossip propagation.
    pub fn is_duplicate_or_record(&mut self, envelope_hash: [u8; 32]) -> bool {
        if self.seen_messages.contains(&envelope_hash) {
            return true;
        }

        if self.seen_messages.len() >= self.max_capacity {
            self.seen_messages.pop_front();
        }
        self.seen_messages.push_back(envelope_hash);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gossip_deduplication_respects_capacity() {
        let mut dedup = GossipDeduplication::new(2);

        assert!(!dedup.is_duplicate_or_record([1; 32]));
        assert!(!dedup.is_duplicate_or_record([2; 32]));

        // Pushes [1; 32] out
        assert!(!dedup.is_duplicate_or_record([3; 32]));

        // [1; 32] should not be seen anymore
        assert!(!dedup.is_duplicate_or_record([1; 32]));

        // [3; 32] should be seen
        assert!(dedup.is_duplicate_or_record([3; 32]));
    }
}
