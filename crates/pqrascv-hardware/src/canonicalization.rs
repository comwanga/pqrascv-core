/// Centralized canonicalization trait for deterministic hashing.
pub trait Canonicalizable {
    /// Produces a deterministic 32-byte hash representing the canonical state.
    #[allow(clippy::result_unit_err)]
    fn canonical_hash(&self) -> Result<[u8; 32], ()>;
}
