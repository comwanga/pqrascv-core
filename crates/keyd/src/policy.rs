//! Per-key authorization policy (ACLs) for keyd.
//!
//! The *principal* is the peer UID obtained from `SO_PEERCRED` at the socket
//! layer (see [`crate::server`]). This module makes no socket calls itself: it
//! is a pure, in-memory decision engine so the authorization path is unit
//! testable without a live `UnixListener`.
//!
//! # Default-deny
//!
//! The policy is **default-deny**. A `(principal, key, operation)` triple is
//! permitted only if an explicit grant matches it. Unknown principals, unknown
//! keys, and operations without an explicit grant are all denied. There is an
//! optional wildcard key (`"*"`) so an operator can grant a principal rights
//! across every key without enumerating each label, but even that must be
//! configured explicitly — absence of configuration denies everything.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A key operation that can be authorized independently.
///
/// These map 1:1 onto the wire-protocol request types in [`crate::protocol`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Create a new keypair for a label (protocol `GenerateKeypair = 1`).
    Generate,
    /// Export the public/verifying key for a label (protocol `ExportPublicKey = 2`).
    Export,
    /// Produce a signature with a label's secret key (protocol `Sign = 3`).
    Sign,
    /// Replace a label's keypair with a fresh one (protocol `Rotate = 4`).
    Rotate,
    /// Remove a label's keypair (protocol `Delete = 5`).
    Delete,
}

impl Operation {
    /// Maps a raw wire `request_type` byte to an [`Operation`].
    ///
    /// Returns `None` for unrecognised request types; callers should treat an
    /// unknown request type as a hard error (and the audit log records it).
    #[must_use]
    pub fn from_request_type(request_type: u8) -> Option<Self> {
        match request_type {
            1 => Some(Self::Generate),
            2 => Some(Self::Export),
            3 => Some(Self::Sign),
            4 => Some(Self::Rotate),
            5 => Some(Self::Delete),
            _ => None,
        }
    }

    /// Stable lowercase name for audit logging.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generate => "generate",
            Self::Export => "export",
            Self::Sign => "sign",
            Self::Rotate => "rotate",
            Self::Delete => "delete",
        }
    }
}

/// Wildcard key label that, when present in a principal's grants, matches every
/// key. Use sparingly; default-deny still applies if the wildcard is absent.
pub const WILDCARD_KEY: &str = "*";

/// The set of operations a principal may perform on a particular key (or on the
/// wildcard key).
///
/// Stored as a sorted set of [`Operation`] for deterministic serialization.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSet {
    ops: Vec<Operation>,
}

impl OperationSet {
    /// Builds an [`OperationSet`] from an iterator of operations, de-duplicating
    /// and sorting for a canonical representation.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(ops: impl IntoIterator<Item = Operation>) -> Self {
        let mut ops: Vec<Operation> = ops.into_iter().collect();
        ops.sort_unstable();
        ops.dedup();
        Self { ops }
    }

    /// Returns `true` if `op` is in the set.
    #[must_use]
    pub fn contains(&self, op: Operation) -> bool {
        self.ops.binary_search(&op).is_ok()
    }

    /// Returns `true` if no operations are granted.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Grants for a single principal: a map from key label (or [`WILDCARD_KEY`]) to
/// the operations allowed on that key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalGrants {
    #[serde(default)]
    keys: BTreeMap<String, OperationSet>,
}

impl PrincipalGrants {
    /// Returns `true` if this principal may perform `op` on `key`.
    ///
    /// An exact-key grant or a [`WILDCARD_KEY`] grant suffices.
    #[must_use]
    fn allows(&self, key: &str, op: Operation) -> bool {
        if let Some(set) = self.keys.get(key) {
            if set.contains(op) {
                return true;
            }
        }
        self.keys
            .get(WILDCARD_KEY)
            .is_some_and(|set| set.contains(op))
    }
}

/// The full authorization policy: a map from principal UID to that principal's
/// per-key grants.
///
/// This is the operator-facing, serializable configuration. It can be loaded
/// from JSON (`Policy::from_json`) — chosen because it needs no extra
/// dependency given `serde` is already present and keeps the config trivially
/// hand-editable — or constructed programmatically with [`PolicyBuilder`] for
/// tests and embedding.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Map of principal UID -> grants. Keyed by `u32` UID.
    #[serde(default)]
    principals: BTreeMap<u32, PrincipalGrants>,
}

impl Policy {
    /// Core decision function: may `principal` perform `op` on `key`?
    ///
    /// Default-deny: returns `false` unless an explicit grant matches.
    #[must_use]
    pub fn is_allowed(&self, principal: u32, key: &str, op: Operation) -> bool {
        self.principals
            .get(&principal)
            .is_some_and(|grants| grants.allows(key, op))
    }

    /// Parses a [`Policy`] from a JSON string.
    ///
    /// # Errors
    /// Returns [`PolicyError::Parse`] if the JSON is malformed or does not match
    /// the expected schema.
    pub fn from_json(s: &str) -> Result<Self, PolicyError> {
        serde_json::from_str(s).map_err(|e| PolicyError::Parse(e.to_string()))
    }

    /// Loads a [`Policy`] from a JSON file path.
    ///
    /// # Errors
    /// Returns [`PolicyError::Io`] if the file cannot be read, or
    /// [`PolicyError::Parse`] if its contents are not valid policy JSON.
    pub fn from_json_file(path: impl AsRef<std::path::Path>) -> Result<Self, PolicyError> {
        let raw =
            std::fs::read_to_string(path.as_ref()).map_err(|e| PolicyError::Io(e.to_string()))?;
        Self::from_json(&raw)
    }

    /// Serializes this policy to pretty JSON (useful for emitting a template).
    ///
    /// # Errors
    /// Returns [`PolicyError::Parse`] if serialization fails (practically never
    /// for this data shape).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn to_json(&self) -> Result<String, PolicyError> {
        serde_json::to_string_pretty(self).map_err(|e| PolicyError::Parse(e.to_string()))
    }
}

/// Ergonomic builder for constructing a [`Policy`] in code/tests (the
/// "injected struct" configuration path).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Default)]
pub struct PolicyBuilder {
    policy: Policy,
}

#[cfg_attr(not(test), allow(dead_code))]
impl PolicyBuilder {
    /// Starts an empty (default-deny) policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Grants `principal` the given `ops` on `key`.
    ///
    /// Repeated calls for the same `(principal, key)` union the operation sets.
    /// Use [`WILDCARD_KEY`] as `key` to grant across all keys.
    #[must_use]
    pub fn grant(
        mut self,
        principal: u32,
        key: impl Into<String>,
        ops: impl IntoIterator<Item = Operation>,
    ) -> Self {
        let key = key.into();
        let entry = self.policy.principals.entry(principal).or_default();
        let existing = entry.keys.entry(key).or_default();
        let merged = OperationSet::new(existing.ops.iter().copied().chain(ops));
        *existing = merged;
        self
    }

    /// Finalizes the [`Policy`].
    #[must_use]
    pub fn build(self) -> Policy {
        self.policy
    }
}

/// Errors that can arise loading or parsing a [`Policy`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The policy file could not be read.
    #[error("policy I/O error: {0}")]
    Io(String),
    /// The policy contents could not be parsed.
    #[error("policy parse error: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_denies_everything() {
        let policy = Policy::default();
        assert!(!policy.is_allowed(1000, "any-key", Operation::Sign));
        assert!(!policy.is_allowed(0, "any-key", Operation::Generate));
    }

    #[test]
    fn exact_grant_allows_only_that_op_and_key() {
        let policy = PolicyBuilder::new()
            .grant(1000, "app-key", [Operation::Sign])
            .build();
        assert!(policy.is_allowed(1000, "app-key", Operation::Sign));
        // Wrong op on the same key is denied.
        assert!(!policy.is_allowed(1000, "app-key", Operation::Delete));
        // Right op on a different key is denied.
        assert!(!policy.is_allowed(1000, "other-key", Operation::Sign));
        // Right op/key but different principal is denied.
        assert!(!policy.is_allowed(1001, "app-key", Operation::Sign));
    }

    #[test]
    fn wildcard_key_grants_across_all_keys() {
        let policy = PolicyBuilder::new()
            .grant(1000, WILDCARD_KEY, [Operation::Export])
            .build();
        assert!(policy.is_allowed(1000, "key-a", Operation::Export));
        assert!(policy.is_allowed(1000, "key-b", Operation::Export));
        // Wildcard does not widen the operation set.
        assert!(!policy.is_allowed(1000, "key-a", Operation::Sign));
    }

    #[test]
    fn grant_merges_operations_for_same_key() {
        let policy = PolicyBuilder::new()
            .grant(1000, "k", [Operation::Sign])
            .grant(1000, "k", [Operation::Export])
            .build();
        assert!(policy.is_allowed(1000, "k", Operation::Sign));
        assert!(policy.is_allowed(1000, "k", Operation::Export));
    }

    #[test]
    fn operation_set_dedups_and_contains() {
        let set = OperationSet::new([Operation::Sign, Operation::Sign, Operation::Export]);
        assert!(set.contains(Operation::Sign));
        assert!(set.contains(Operation::Export));
        assert!(!set.contains(Operation::Delete));
        assert!(!set.is_empty());
    }

    #[test]
    fn operation_from_request_type_maps_protocol_bytes() {
        assert_eq!(Operation::from_request_type(1), Some(Operation::Generate));
        assert_eq!(Operation::from_request_type(2), Some(Operation::Export));
        assert_eq!(Operation::from_request_type(3), Some(Operation::Sign));
        assert_eq!(Operation::from_request_type(4), Some(Operation::Rotate));
        assert_eq!(Operation::from_request_type(5), Some(Operation::Delete));
        assert_eq!(Operation::from_request_type(0), None);
        assert_eq!(Operation::from_request_type(99), None);
    }

    #[test]
    fn json_roundtrip_preserves_decisions() {
        let policy = PolicyBuilder::new()
            .grant(1000, "app-key", [Operation::Sign, Operation::Export])
            .grant(0, WILDCARD_KEY, [Operation::Generate, Operation::Delete])
            .build();
        let json = policy.to_json().unwrap();
        let reparsed = Policy::from_json(&json).unwrap();
        assert_eq!(policy, reparsed);
        assert!(reparsed.is_allowed(1000, "app-key", Operation::Sign));
        assert!(reparsed.is_allowed(0, "anything", Operation::Delete));
        assert!(!reparsed.is_allowed(1000, "app-key", Operation::Delete));
    }

    #[test]
    fn from_json_rejects_malformed_input() {
        let err = Policy::from_json("{ not json").unwrap_err();
        assert!(matches!(err, PolicyError::Parse(_)));
    }

    #[test]
    fn from_json_parses_documented_schema() {
        // Operator-facing schema example.
        let json = r#"{
            "principals": {
                "1000": { "keys": { "app-key": { "ops": ["sign", "export"] } } },
                "0":    { "keys": { "*":       { "ops": ["generate", "delete"] } } }
            }
        }"#;
        let policy = Policy::from_json(json).unwrap();
        assert!(policy.is_allowed(1000, "app-key", Operation::Sign));
        assert!(policy.is_allowed(1000, "app-key", Operation::Export));
        assert!(!policy.is_allowed(1000, "app-key", Operation::Rotate));
        assert!(policy.is_allowed(0, "any", Operation::Generate));
    }
}
