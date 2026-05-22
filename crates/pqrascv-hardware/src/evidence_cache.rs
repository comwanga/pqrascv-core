//! Verifier-side Bounded Evidence Cache
//!
//! Provides an append-only, strictly bounded cache for deduplication and
//! sequence alignment of incoming live evidence. Crucial for detecting
//! replay attacks, attestation flooding, and rollback attempts without
//! risking verifier memory exhaustion.

#![cfg(feature = "live-evidence")]

use crate::digest::TypedDigest;
use alloc::collections::VecDeque;
use alloc::string::String;

pub const MAX_CACHE_ENTRIES: usize = 1000;

/// Represents a cached entry of an observed node's evidence state.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub node_id: String,
    pub timestamp: u64,
    pub evidence_hash: TypedDigest,
}

/// A deterministic, bounded evidence cache.
#[derive(Debug, Default)]
pub struct EvidenceCache {
    entries: VecDeque<CacheEntry>,
}

impl EvidenceCache {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_CACHE_ENTRIES),
        }
    }

    /// Appends a new entry to the cache. If the cache is full, deterministically
    /// evicts the oldest entry to prevent memory exhaustion.
    pub fn push(&mut self, entry: CacheEntry) {
        if self.entries.len() >= MAX_CACHE_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Checks if the exact evidence hash has already been seen (exact replay).
    #[must_use]
    pub fn contains_hash(&self, hash: &TypedDigest) -> bool {
        self.entries
            .iter()
            .any(|e| e.evidence_hash.value == hash.value)
    }

    /// Retrieves the most recent timestamp seen for a specific node identity.
    /// Used for strictly enforcing monotonic timeline progression.
    #[must_use]
    pub fn last_seen_timestamp(&self, node_id: &str) -> Option<u64> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.node_id == node_id)
            .map(|e| e.timestamp)
    }

    /// Evicts all entries older than the provided timestamp cutoff.
    pub fn evict_expired(&mut self, cutoff_timestamp: u64) {
        self.entries.retain(|e| e.timestamp > cutoff_timestamp);
    }
}
