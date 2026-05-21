//! Secure Boot Policy Semantics
//!
//! Explicitly models Secure Boot states to allow the verifier to
//! detect when it is Disabled, in Setup Mode, or Enforcing.

use crate::digest::TypedDigest;

/// Represents the state of Secure Boot on the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecureBootState {
    /// Secure Boot is actively enforcing signatures.
    Enabled,
    /// Secure Boot is disabled.
    Disabled,
    /// Secure Boot is in setup mode (custom keys can be enrolled).
    SetupMode,
    /// Secure Boot state could not be determined.
    Unknown,
}

/// Contains evidence regarding the Secure Boot state and key databases.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecureBootEvidence {
    /// The state of Secure Boot on the device.
    pub state: SecureBootState,
    /// Hash of the signature database (db).
    pub db_hash: Option<TypedDigest>,
    /// Hash of the forbidden signature database (dbx).
    pub dbx_hash: Option<TypedDigest>,
    /// Hash of the Machine Owner Key database (MOK).
    pub mok_hash: Option<TypedDigest>,
}
