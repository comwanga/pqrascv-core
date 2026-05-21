//! Software Root-of-Trust backend.
//!
//! Re-exports [`crate::measurement::SoftwareRoT`] so backends can be
//! addressed uniformly via `pqrascv_core::backends::software::SoftwareRoT`.
//!
//! # ⚠ SECURITY WARNING
//!
//! `SoftwareRoT` is **not a real security boundary**. It is gated behind the
//! `software-rot-unsafe` feature flag and must only be used for testing.
//! See [`crate::measurement::SoftwareRoT`] for details.

#[cfg(feature = "software-rot-unsafe")]
pub use crate::measurement::SoftwareRoT;
