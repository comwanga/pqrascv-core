//! Bitcoin Node Event Timeline
//!
//! Captures sequence-ordered, cryptographically hashable events in the lifecycle
//! of a sovereign Bitcoin node for timeline reconciliation and forensic audit.

use crate::digest::{DigestAlgorithm, TypedDigest};
use alloc::vec::Vec;

/// Specific lifecycle events for a Bitcoin node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BitcoinNodeEvent {
    /// The node's secure boot and measured boot sequence was verified.
    BootVerified {
        sequence_number: u64,
        firmware_digest: TypedDigest,
    },
    /// The runtime integrity of the node's bitcoind workload was verified.
    RuntimeIntegrityVerified {
        sequence_number: u64,
        executable_hash: TypedDigest,
        config_hash: TypedDigest,
    },
    /// The bitcoind executable was updated to a new version.
    BinaryUpdated {
        sequence_number: u64,
        old_hash: TypedDigest,
        new_hash: TypedDigest,
    },
    /// The bitcoin.conf configuration file was modified.
    ConfigChanged {
        sequence_number: u64,
        old_hash: TypedDigest,
        new_hash: TypedDigest,
    },
    /// A distributed verifier consensus decision was reached for this node.
    VerifierConsensusReached {
        sequence_number: u64,
        consensus_hash: TypedDigest,
    },
    /// The governance policy applied to this node was updated.
    GovernancePolicyUpdated { sequence_number: u64, epoch_id: u64 },
    /// The node's trust state was successfully anchored to a transparency log or Bitcoin.
    TransparencyAnchored {
        sequence_number: u64,
        anchor_hash: TypedDigest,
    },
}

impl BitcoinNodeEvent {
    /// Gets the monotonic sequence number of the event.
    #[must_use]
    pub fn sequence_number(&self) -> u64 {
        match *self {
            Self::BootVerified {
                sequence_number, ..
            }
            | Self::RuntimeIntegrityVerified {
                sequence_number, ..
            }
            | Self::BinaryUpdated {
                sequence_number, ..
            }
            | Self::ConfigChanged {
                sequence_number, ..
            }
            | Self::VerifierConsensusReached {
                sequence_number, ..
            }
            | Self::GovernancePolicyUpdated {
                sequence_number, ..
            }
            | Self::TransparencyAnchored {
                sequence_number, ..
            } => sequence_number,
        }
    }

    /// Computes the cryptographic hash of the event for timeline anchoring.
    #[must_use]
    pub fn event_hash(&self) -> TypedDigest {
        use sha2::{Digest, Sha256};
        // In a real implementation, this would serialize the variant and hash it.
        // For demonstration, we just create a dummy hash based on the sequence number.
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.sequence_number().to_be_bytes());
        match self {
            Self::BootVerified {
                firmware_digest, ..
            } => buf.extend_from_slice(&firmware_digest.value),
            Self::RuntimeIntegrityVerified {
                executable_hash, ..
            } => buf.extend_from_slice(&executable_hash.value),
            Self::BinaryUpdated { new_hash, .. } | Self::ConfigChanged { new_hash, .. } => {
                buf.extend_from_slice(&new_hash.value);
            }
            Self::VerifierConsensusReached { consensus_hash, .. } => {
                buf.extend_from_slice(&consensus_hash.value);
            }
            Self::GovernancePolicyUpdated { epoch_id, .. } => {
                buf.extend_from_slice(&epoch_id.to_be_bytes());
            }
            Self::TransparencyAnchored { anchor_hash, .. } => {
                buf.extend_from_slice(&anchor_hash.value);
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(&buf);
        let result = hasher.finalize();

        TypedDigest {
            algorithm: DigestAlgorithm::Sha256,
            value: result.into(),
        }
    }
}
