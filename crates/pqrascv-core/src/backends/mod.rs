//! Optional hardware-specific Root-of-Trust backends.
//!
//! Each backend is gated behind a feature flag to keep the default build
//! dependency-free for embedded targets.
//!
//! | Module | Feature | Description |
//! |--------|---------|-------------|
//! | [`software`] | *(always available)* | SHA3-256 hash-based software RoT |
//! | [`tpm`] | `hardware-tpm` | TPM 2.0 backend |
//! | [`dice`] | `dice` | DICE RoT backend |

pub mod software;

#[cfg(feature = "hardware-tpm")]
pub mod tpm;

#[cfg(feature = "dice")]
pub mod dice;
