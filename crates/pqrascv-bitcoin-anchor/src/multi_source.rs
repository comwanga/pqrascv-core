//! Independent chain trust across multiple header sources (Phase 7D).
//!
//! A single [`HeaderOracle`] can be eclipsed: an attacker who controls a node's
//! network view can feed it a fabricated chain. [`MultiSourceHeaderOracle`]
//! defends against this by querying several independent sources and requiring a
//! **quorum** of them to agree on the header at a given height. It:
//!
//! - returns the header only when ≥ `quorum` sources report the same block hash
//!   ([`Self::agreed_header_at`]); otherwise it **fails closed** with
//!   [`OracleError::NoQuorum`] rather than silently picking a chain;
//! - reports which sources diverge from the agreed view
//!   ([`Self::divergent_sources_at`]) — a divergence at the tip is an eclipse
//!   indicator for that source.

use bitcoin::block::Header;
use bitcoin::BlockHash;

use crate::oracle::{HeaderOracle, OracleError};

/// Cross-checks several [`HeaderOracle`]s and requires quorum agreement.
pub struct MultiSourceHeaderOracle {
    sources: Vec<Box<dyn HeaderOracle>>,
    quorum: usize,
}

impl MultiSourceHeaderOracle {
    /// Builds a multi-source oracle requiring `quorum` sources to agree.
    ///
    /// `quorum` is clamped to at least 1; configure it above half the source
    /// count (e.g. 2-of-3) so a minority of malicious/eclipsed sources cannot
    /// carry a decision.
    #[must_use]
    pub fn new(sources: Vec<Box<dyn HeaderOracle>>, quorum: usize) -> Self {
        Self {
            sources,
            quorum: quorum.max(1),
        }
    }

    /// Number of configured sources.
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// The header at `height` agreed by at least `quorum` sources.
    ///
    /// Sources are grouped by block hash; the first group reaching quorum wins.
    /// Sources that error are simply absent from the tally.
    ///
    /// # Errors
    /// [`OracleError::NoQuorum`] if no block hash is reported by `quorum` sources.
    pub fn agreed_header_at(&self, height: u32) -> Result<Header, OracleError> {
        let mut groups: Vec<(BlockHash, Header, usize)> = Vec::new();
        for source in &self.sources {
            if let Ok(header) = source.header_at(height) {
                let hash = header.block_hash();
                if let Some(group) = groups.iter_mut().find(|g| g.0 == hash) {
                    group.2 += 1;
                } else {
                    groups.push((hash, header, 1));
                }
            }
        }
        groups
            .into_iter()
            .find(|g| g.2 >= self.quorum)
            .map(|g| g.1)
            .ok_or(OracleError::NoQuorum)
    }

    /// The agreed tip height: the highest height that at least `quorum` sources
    /// claim to have reached.
    ///
    /// # Errors
    /// [`OracleError::NoQuorum`] if fewer than `quorum` sources are reachable.
    pub fn agreed_tip_height(&self) -> Result<u32, OracleError> {
        let mut tips: Vec<u32> = self
            .sources
            .iter()
            .filter_map(|s| s.tip_height().ok())
            .collect();
        if tips.len() < self.quorum {
            return Err(OracleError::NoQuorum);
        }
        tips.sort_unstable_by(|a, b| b.cmp(a)); // descending
        Ok(tips[self.quorum - 1])
    }

    /// Indices of sources that diverge from (or cannot serve) the agreed header
    /// at `height`. A non-empty result — especially at the tip — is an eclipse
    /// indicator for those sources.
    ///
    /// # Errors
    /// [`OracleError::NoQuorum`] if there is no agreed header to compare against.
    pub fn divergent_sources_at(&self, height: u32) -> Result<Vec<usize>, OracleError> {
        let agreed = self.agreed_header_at(height)?.block_hash();
        let mut diverged = Vec::new();
        for (i, source) in self.sources.iter().enumerate() {
            match source.header_at(height) {
                Ok(h) if h.block_hash() == agreed => {}
                _ => diverged.push(i),
            }
        }
        Ok(diverged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::test_support::{build_chain, build_chain_with_time};
    use crate::oracle::{regtest_max_bits, FixtureHeaderOracle};

    fn oracle_over(chain: Vec<Header>) -> Box<dyn HeaderOracle> {
        Box::new(FixtureHeaderOracle::new(0, chain).unwrap())
    }

    #[test]
    fn unanimous_sources_agree() {
        let chain = build_chain(4, regtest_max_bits());
        let multi = MultiSourceHeaderOracle::new(
            vec![
                oracle_over(chain.clone()),
                oracle_over(chain.clone()),
                oracle_over(chain.clone()),
            ],
            2,
        );
        assert_eq!(multi.agreed_header_at(2).unwrap(), chain[2]);
        assert_eq!(multi.agreed_tip_height().unwrap(), 3);
        assert!(multi.divergent_sources_at(3).unwrap().is_empty());
    }

    #[test]
    fn minority_fork_is_outvoted_and_flagged() {
        // Two sources on chain A, one eclipsed source on a divergent chain B.
        let chain_a = build_chain_with_time(4, regtest_max_bits(), 1_700_000_000);
        let chain_b = build_chain_with_time(4, regtest_max_bits(), 1_700_009_999);
        assert_ne!(chain_a[2].block_hash(), chain_b[2].block_hash());

        let multi = MultiSourceHeaderOracle::new(
            vec![
                oracle_over(chain_a.clone()),
                oracle_over(chain_a.clone()),
                oracle_over(chain_b),
            ],
            2,
        );
        // Majority (chain A) wins.
        assert_eq!(multi.agreed_header_at(2).unwrap(), chain_a[2]);
        // The eclipsed source (index 2) is flagged as divergent at the tip.
        assert_eq!(multi.divergent_sources_at(3).unwrap(), vec![2]);
    }

    #[test]
    fn split_with_no_quorum_fails_closed() {
        // Three sources, three different chains: no block hash reaches quorum 2.
        let a = build_chain_with_time(3, regtest_max_bits(), 1_700_000_001);
        let b = build_chain_with_time(3, regtest_max_bits(), 1_700_000_002);
        let c = build_chain_with_time(3, regtest_max_bits(), 1_700_000_003);
        let multi =
            MultiSourceHeaderOracle::new(vec![oracle_over(a), oracle_over(b), oracle_over(c)], 2);
        assert_eq!(multi.agreed_header_at(1), Err(OracleError::NoQuorum));
        assert_eq!(multi.divergent_sources_at(1), Err(OracleError::NoQuorum));
    }

    #[test]
    fn tip_height_is_the_quorum_th_highest() {
        // Tips: 3, 3, 1. With quorum 2 the agreed tip is 3 (two sources reach it).
        let long = build_chain(4, regtest_max_bits()); // tip height 3
        let short = build_chain(2, regtest_max_bits()); // tip height 1
        let multi = MultiSourceHeaderOracle::new(
            vec![
                oracle_over(long.clone()),
                oracle_over(long),
                oracle_over(short),
            ],
            2,
        );
        assert_eq!(multi.agreed_tip_height().unwrap(), 3);
    }

    #[test]
    fn too_few_reachable_sources_fails_closed() {
        let chain = build_chain(3, regtest_max_bits());
        let multi = MultiSourceHeaderOracle::new(vec![oracle_over(chain)], 2);
        assert_eq!(multi.agreed_tip_height(), Err(OracleError::NoQuorum));
    }
}
