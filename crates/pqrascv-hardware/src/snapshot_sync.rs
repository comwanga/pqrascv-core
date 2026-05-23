use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotChunk {
    pub manifest_hash: [u8; 32],
    pub chunk_index: usize,
    pub total_chunks: usize,
    pub data: alloc::vec::Vec<u8>,
    pub chunk_merkle_proof: alloc::vec::Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub snapshot_id: String,
    pub federation_id: String,
    pub total_size_bytes: u64,
    pub chunk_count: usize,
    pub chunk_merkle_root: [u8; 32],
    pub signature: alloc::vec::Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotProof {
    pub manifest: SnapshotManifest,
    pub received_chunks: alloc::collections::BTreeMap<usize, SnapshotChunk>,
}

impl SnapshotProof {
    #[must_use]
    pub fn new(manifest: SnapshotManifest) -> Self {
        Self {
            manifest,
            received_chunks: alloc::collections::BTreeMap::new(),
        }
    }

    pub fn add_chunk(&mut self, chunk: SnapshotChunk) -> Result<(), &'static str> {
        if chunk.manifest_hash != self.manifest.chunk_merkle_root {
            // Simplified for demo
            return Err("Manifest hash mismatch");
        }
        if chunk.chunk_index >= self.manifest.chunk_count {
            return Err("Chunk index out of bounds");
        }
        self.received_chunks.insert(chunk.chunk_index, chunk);
        Ok(())
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.received_chunks.len() == self.manifest.chunk_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_chunk_completion() {
        let manifest = SnapshotManifest {
            snapshot_id: "snap1".into(),
            federation_id: "fed1".into(),
            total_size_bytes: 1024,
            chunk_count: 2,
            chunk_merkle_root: [0; 32],
            signature: vec![],
        };
        let mut proof = SnapshotProof::new(manifest);
        assert!(!proof.is_complete());

        let _ = proof.add_chunk(SnapshotChunk {
            manifest_hash: [0; 32],
            chunk_index: 0,
            total_chunks: 2,
            data: vec![1, 2, 3],
            chunk_merkle_proof: vec![],
        });
        assert!(!proof.is_complete());

        let _ = proof.add_chunk(SnapshotChunk {
            manifest_hash: [0; 32],
            chunk_index: 1,
            total_chunks: 2,
            data: vec![4, 5, 6],
            chunk_merkle_proof: vec![],
        });
        assert!(proof.is_complete());
    }
}
