//! Software Root-of-Trust backend.
//!
//! Re-exports [`crate::measurement::SoftwareRoT`] so backends can be
//! addressed uniformly via `pqrascv_core::backends::software::SoftwareRoT`.

pub use crate::measurement::SoftwareRoT;
