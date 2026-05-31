//! Append-only audit logging for keyd key operations.
//!
//! Every authorization decision — allowed, denied, or errored — produces an
//! [`AuditRecord`]. The sink is the [`AuditSink`] trait so tests can capture
//! records in memory; a file-backed [`FileAuditSink`] is the production default.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::policy::Operation;

/// The outcome of an attempted key operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Authorization passed and the operation succeeded.
    Allowed,
    /// Authorization failed (default-deny or missing grant); nothing executed.
    Denied,
    /// Authorization passed but the operation itself failed (e.g. key not found,
    /// signing error). The `detail` field carries a short reason.
    Error,
}

impl Outcome {
    /// Stable lowercase name.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }
}

/// A single append-only audit record.
///
/// Field shape (also the JSON-lines schema written by [`FileAuditSink`]):
/// `timestamp_unix_ms`, `principal_uid`, `key`, `operation`, `outcome`,
/// `detail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Wall-clock time of the attempt, milliseconds since the Unix epoch.
    pub timestamp_unix_ms: u128,
    /// Peer UID (the authenticated principal).
    pub principal_uid: u32,
    /// Key label the operation targeted.
    pub key: String,
    /// Operation attempted.
    pub operation: Operation,
    /// Outcome of the attempt.
    pub outcome: Outcome,
    /// Optional short human-readable detail (error reason, deny reason).
    #[serde(default)]
    pub detail: Option<String>,
}

impl AuditRecord {
    /// Constructs a record, stamping the current wall-clock time.
    #[must_use]
    pub fn now(
        principal_uid: u32,
        key: impl Into<String>,
        operation: Operation,
        outcome: Outcome,
        detail: Option<String>,
    ) -> Self {
        Self {
            timestamp_unix_ms: now_unix_ms(),
            principal_uid,
            key: key.into(),
            operation,
            outcome,
            detail,
        }
    }
}

/// Current wall-clock time in milliseconds since the Unix epoch.
///
/// Saturates to `0` if the system clock is before the epoch (it never is in
/// practice) so this is total and panic-free.
#[must_use]
pub fn now_unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// Append-only sink for audit records.
///
/// Implementations must be `Send + Sync` so the sink can be shared across the
/// daemon's connection-handling tasks.
pub trait AuditSink: Send + Sync {
    /// Records one audit event. Implementations should be append-only and
    /// should not fail the request path: a logging failure is itself logged
    /// (via the returned error) but must not panic.
    ///
    /// # Errors
    /// Returns [`AuditError`] if the record could not be persisted.
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

/// Errors raised by an [`AuditSink`].
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The record could not be serialized or written.
    #[error("audit write error: {0}")]
    Write(String),
}

/// File-backed audit sink: appends one JSON object per line (JSON Lines).
///
/// Opens the file in append mode (creating it 0o600 on Unix) on every write so
/// the log survives rotation by an external tool and so multiple processes
/// appending stay correct under O_APPEND semantics.
pub struct FileAuditSink {
    path: std::path::PathBuf,
    /// Serializes writes within this process so concurrent tasks don't interleave
    /// partial lines.
    lock: Mutex<()>,
}

impl FileAuditSink {
    /// Creates a file-backed sink writing to `path`.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }
}

impl AuditSink for FileAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        use std::io::Write;

        let mut line = serde_json::to_string(record).map_err(|e| AuditError::Write(e.to_string()))?;
        line.push('\n');

        // Poisoned lock just means a prior writer panicked; the file is still
        // usable, so recover the guard rather than propagating the panic.
        let _guard = self.lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&self.path)
            .map_err(|e| AuditError::Write(e.to_string()))?;
        f.write_all(line.as_bytes())
            .map_err(|e| AuditError::Write(e.to_string()))
    }
}

/// In-memory audit sink for tests: captures every record in a `Vec`.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct MemoryAuditSink {
    records: Mutex<Vec<AuditRecord>>,
}

#[cfg(test)]
impl MemoryAuditSink {
    /// Creates an empty in-memory sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a snapshot copy of all captured records.
    #[must_use]
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Number of records captured so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether any records have been captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
impl AuditSink for MemoryAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(record.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn memory_sink_captures_records_in_order() {
        let sink = MemoryAuditSink::new();
        assert!(sink.is_empty());
        sink.record(&AuditRecord::now(1000, "k", Operation::Sign, Outcome::Allowed, None))
            .unwrap();
        sink.record(&AuditRecord::now(
            1001,
            "k",
            Operation::Delete,
            Outcome::Denied,
            Some("no grant".into()),
        ))
        .unwrap();
        let recs = sink.records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].outcome, Outcome::Allowed);
        assert_eq!(recs[1].outcome, Outcome::Denied);
        assert_eq!(recs[1].detail.as_deref(), Some("no grant"));
    }

    #[test]
    fn file_sink_appends_json_lines() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        let sink = FileAuditSink::new(&path);
        sink.record(&AuditRecord::now(1000, "k", Operation::Sign, Outcome::Allowed, None))
            .unwrap();
        sink.record(&AuditRecord::now(0, "k2", Operation::Generate, Outcome::Error, None))
            .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line must be a self-contained JSON object that round-trips.
        let r0: AuditRecord = serde_json::from_str(lines[0]).unwrap();
        let r1: AuditRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r0.principal_uid, 1000);
        assert_eq!(r0.operation, Operation::Sign);
        assert_eq!(r1.outcome, Outcome::Error);
    }

    #[test]
    fn outcome_and_record_serialize_with_expected_names() {
        let rec = AuditRecord::now(7, "label", Operation::Export, Outcome::Denied, None);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"outcome\":\"denied\""));
        assert!(json.contains("\"operation\":\"export\""));
        assert!(json.contains("\"principal_uid\":7"));
    }
}
