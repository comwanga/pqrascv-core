//! Block-header synchronization with local validation (Phase 7C).
//!
//! A [`HeaderOracle`] supplies block headers, and [`validate_chain`] checks them
//! *locally* so anchor verification no longer has to trust caller-supplied
//! headers (the gap in the no_std core's `SpvVerifier`, which validates a proof
//! against whatever `block_header` the caller hands it). All header/PoW math is
//! delegated to rust-bitcoin.
//!
//! # What `validate_chain` enforces
//!
//! 1. **Proof-of-work** — every header's block hash is ≤ the target encoded in
//!    its own `nBits` (`Header::validate_pow`).
//! 2. **Continuity** — each header's `prev_blockhash` equals the previous
//!    header's block hash, so the slice is a single connected chain.
//! 3. **Difficulty stability** — `nBits` is constant within a 2016-block retarget
//!    period and may change only at a period boundary (`height % 2016 == 0`).
//!
//! # What it does NOT (yet) enforce
//!
//! Full difficulty-*retarget* recomputation (deriving the exact next-period
//! target from the previous period's timespan, BIP-9 rules, median-time-past,
//! and the testnet 20-minute exception) is a documented stretch goal. We enforce
//! that difficulty is *stable within a period* and meets each header's claimed
//! target — which already defeats a forged low-work chain — but we do not yet
//! recompute that the boundary target is the arithmetically correct one.

use bitcoin::block::Header;
use bitcoin::CompactTarget;

/// Bitcoin difficulty retarget interval, in blocks.
pub const RETARGET_INTERVAL: u32 = 2016;

/// Errors from header synchronization and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OracleError {
    /// The underlying source could not be reached or returned an error.
    SourceUnavailable(String),
    /// The requested height is beyond the source's tip (or `from > to`).
    OutOfRange,
    /// A header's proof-of-work does not meet its claimed target.
    PowInvalid { height: u32 },
    /// A header does not link to its predecessor (`prev_blockhash` mismatch).
    ContinuityBroken { height: u32 },
    /// Difficulty (`nBits`) changed inside a retarget period.
    DifficultyUnstable { height: u32 },
    /// Sources disagreed beyond the configured quorum (see [`crate::multi_source`]).
    NoQuorum,
}

impl core::fmt::Display for OracleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SourceUnavailable(s) => write!(f, "header source unavailable: {s}"),
            Self::OutOfRange => f.write_str("requested header height is out of range"),
            Self::PowInvalid { height } => {
                write!(f, "header at height {height} fails proof-of-work")
            }
            Self::ContinuityBroken { height } => {
                write!(
                    f,
                    "header at height {height} does not link to its predecessor"
                )
            }
            Self::DifficultyUnstable { height } => {
                write!(f, "difficulty changed mid-period at height {height}")
            }
            Self::NoQuorum => f.write_str("header sources did not reach quorum agreement"),
        }
    }
}

impl std::error::Error for OracleError {}

/// Validates a contiguous slice of headers starting at `start_height`, without
/// trusting the caller: every header must satisfy its own proof-of-work, link to
/// its predecessor, and keep difficulty stable within each retarget period.
///
/// # Errors
///
/// Returns the first [`OracleError`] encountered (PoW, continuity, or difficulty).
pub fn validate_chain(headers: &[Header], start_height: u32) -> Result<(), OracleError> {
    for (i, header) in headers.iter().enumerate() {
        let height = start_height + i as u32;

        // 1. Proof-of-work against the header's own claimed target.
        header
            .validate_pow(header.target())
            .map_err(|_| OracleError::PowInvalid { height })?;

        if i > 0 {
            let prev = &headers[i - 1];

            // 2. Continuity: this header extends the previous one.
            if header.prev_blockhash != prev.block_hash() {
                return Err(OracleError::ContinuityBroken { height });
            }

            // 3. Difficulty stability: nBits may change only at a period boundary.
            if height % RETARGET_INTERVAL != 0 && header.bits != prev.bits {
                return Err(OracleError::DifficultyUnstable { height });
            }
        }
    }
    Ok(())
}

/// A source of Bitcoin block headers.
///
/// Implementations may be local (a fixture / synced store) or remote (Bitcoin
/// Core RPC, Esplora, Electrum). Headers returned by [`Self::headers`] are
/// expected to pass [`validate_chain`]; callers should validate rather than
/// trust, which is exactly what [`crate::multi_source::MultiSourceHeaderOracle`]
/// does across several oracles.
pub trait HeaderOracle {
    /// The height of the current chain tip.
    ///
    /// # Errors
    /// [`OracleError::SourceUnavailable`] if the source cannot be queried.
    fn tip_height(&self) -> Result<u32, OracleError>;

    /// The header at `height`.
    ///
    /// # Errors
    /// [`OracleError::OutOfRange`] if `height` exceeds the tip; otherwise
    /// [`OracleError::SourceUnavailable`].
    fn header_at(&self, height: u32) -> Result<Header, OracleError>;

    /// The contiguous headers in `[from, to]` (inclusive).
    ///
    /// The default implementation calls [`Self::header_at`] for each height.
    ///
    /// # Errors
    /// [`OracleError::OutOfRange`] if `from > to` or `to` exceeds the tip.
    fn headers(&self, from: u32, to: u32) -> Result<Vec<Header>, OracleError> {
        if from > to {
            return Err(OracleError::OutOfRange);
        }
        let mut out = Vec::with_capacity((to - from + 1) as usize);
        for h in from..=to {
            out.push(self.header_at(h)?);
        }
        Ok(out)
    }
}

/// An in-memory [`HeaderOracle`] over a fixed chain, for tests and for callers
/// that have already synced and validated headers out of band.
///
/// The chain starts at `base_height`; `headers[i]` is the header at
/// `base_height + i`.
#[derive(Debug, Clone)]
pub struct FixtureHeaderOracle {
    base_height: u32,
    headers: Vec<Header>,
}

impl FixtureHeaderOracle {
    /// Builds an oracle over `headers` beginning at `base_height`, validating the
    /// chain first.
    ///
    /// # Errors
    /// Propagates any [`OracleError`] from [`validate_chain`].
    pub fn new(base_height: u32, headers: Vec<Header>) -> Result<Self, OracleError> {
        validate_chain(&headers, base_height)?;
        Ok(Self {
            base_height,
            headers,
        })
    }

    /// Builds an oracle without validating (e.g. to model a malicious source that
    /// serves an invalid chain). Used by tests and by the multi-source oracle's
    /// adversarial scenarios.
    #[must_use]
    pub fn new_unchecked(base_height: u32, headers: Vec<Header>) -> Self {
        Self {
            base_height,
            headers,
        }
    }

    fn index_of(&self, height: u32) -> Result<usize, OracleError> {
        height
            .checked_sub(self.base_height)
            .map(|i| i as usize)
            .filter(|&i| i < self.headers.len())
            .ok_or(OracleError::OutOfRange)
    }
}

impl HeaderOracle for FixtureHeaderOracle {
    fn tip_height(&self) -> Result<u32, OracleError> {
        if self.headers.is_empty() {
            return Err(OracleError::OutOfRange);
        }
        Ok(self.base_height + (self.headers.len() as u32 - 1))
    }

    fn header_at(&self, height: u32) -> Result<Header, OracleError> {
        let i = self.index_of(height)?;
        Ok(self.headers[i])
    }
}

/// Regtest-style maximum-difficulty `nBits` (`0x207fffff`): the target is so
/// large that essentially any block hash satisfies it, so synthetic headers pass
/// `validate_pow` without real mining.
#[must_use]
pub fn regtest_max_bits() -> CompactTarget {
    CompactTarget::from_consensus(0x207f_ffff)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use bitcoin::block::Version;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, TxMerkleNode};

    /// Builds one (un-mined) header linking to `prev` with the given bits.
    #[must_use]
    pub(crate) fn header(prev: BlockHash, bits: CompactTarget, nonce: u32) -> Header {
        Header {
            version: Version::from_consensus(2),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000,
            bits,
            nonce,
        }
    }

    /// Searches `nonce` until the header satisfies its own target. At the
    /// regtest-style difficulty used in tests roughly half of nonces work, so
    /// this returns within a handful of iterations.
    pub(crate) fn remine(h: &mut Header) {
        h.nonce = 0;
        while h.validate_pow(h.target()).is_err() {
            h.nonce = h.nonce.wrapping_add(1);
        }
    }

    /// Builds a mined header linking to `prev` at the given difficulty.
    #[must_use]
    pub(crate) fn mine(prev: BlockHash, bits: CompactTarget) -> Header {
        let mut h = header(prev, bits, 0);
        remine(&mut h);
        h
    }

    /// Builds a connected, valid-PoW chain of `n` headers at the given difficulty.
    #[must_use]
    pub(crate) fn build_chain(n: u32, bits: CompactTarget) -> Vec<Header> {
        build_chain_with_time(n, bits, 1_700_000_000)
    }

    /// Like [`build_chain`] but stamps every header with `time`, so two chains
    /// built with different `time` values diverge from height 0 — used to model
    /// independent / forked sources in the multi-source tests.
    #[must_use]
    pub(crate) fn build_chain_with_time(n: u32, bits: CompactTarget, time: u32) -> Vec<Header> {
        let mut chain = Vec::new();
        let mut prev = BlockHash::all_zeros();
        for _ in 0..n {
            let mut h = header(prev, bits, 0);
            h.time = time;
            remine(&mut h);
            prev = h.block_hash();
            chain.push(h);
        }
        chain
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{build_chain, header, mine, remine};
    use super::*;
    use bitcoin::hashes::Hash as _;
    use bitcoin::BlockHash;

    /// Mainnet genesis-era difficulty — far too hard for an un-mined synthetic
    /// header, so `validate_pow` fails (used for the insufficient-PoW test).
    fn hard_bits() -> CompactTarget {
        CompactTarget::from_consensus(0x1d00_ffff)
    }

    #[test]
    fn valid_chain_passes() {
        let chain = build_chain(5, regtest_max_bits());
        assert!(validate_chain(&chain, 0).is_ok());
    }

    #[test]
    fn broken_continuity_is_rejected() {
        let mut chain = build_chain(4, regtest_max_bits());
        // Sever the link at index 2 by pointing it at the wrong predecessor, then
        // re-mine so its PoW is valid and the *continuity* check is what fails.
        chain[2].prev_blockhash = BlockHash::all_zeros();
        remine(&mut chain[2]);
        assert_eq!(
            validate_chain(&chain, 0),
            Err(OracleError::ContinuityBroken { height: 2 })
        );
    }

    #[test]
    fn insufficient_pow_is_rejected() {
        // A single un-mined header at mainnet difficulty: its hash will not be
        // below the (small) target, so PoW validation fails.
        let h = header(BlockHash::all_zeros(), hard_bits(), 0);
        assert_eq!(
            validate_chain(&[h], 0),
            Err(OracleError::PowInvalid { height: 0 })
        );
    }

    #[test]
    fn mid_period_difficulty_change_is_rejected() {
        // Two valid-PoW headers, but the second changes nBits at height 1, which
        // is not a retarget boundary.
        let h0 = mine(BlockHash::all_zeros(), regtest_max_bits());
        // A different but still-easy target so PoW still passes.
        let easier = CompactTarget::from_consensus(0x207f_fffe);
        let h1 = mine(h0.block_hash(), easier);
        assert_eq!(
            validate_chain(&[h0, h1], 0),
            Err(OracleError::DifficultyUnstable { height: 1 })
        );
    }

    #[test]
    fn fixture_oracle_serves_validated_headers() {
        let chain = build_chain(3, regtest_max_bits());
        let oracle = FixtureHeaderOracle::new(100, chain.clone()).unwrap();
        assert_eq!(oracle.tip_height().unwrap(), 102);
        assert_eq!(oracle.header_at(101).unwrap(), chain[1]);
        assert_eq!(oracle.headers(100, 102).unwrap(), chain);
        assert_eq!(oracle.header_at(200), Err(OracleError::OutOfRange));
    }

    #[test]
    fn fixture_oracle_rejects_invalid_chain_on_construction() {
        let mut chain = build_chain(3, regtest_max_bits());
        chain[1].prev_blockhash = BlockHash::all_zeros();
        remine(&mut chain[1]);
        assert!(matches!(
            FixtureHeaderOracle::new(0, chain),
            Err(OracleError::ContinuityBroken { height: 1 })
        ));
    }
}
