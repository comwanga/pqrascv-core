//! Authorized request handling: the pure decision + dispatch path.
//!
//! [`Authorizer`] ties together the [`Policy`](crate::policy::Policy),
//! [`AuditSink`](crate::audit::AuditSink), [`UsageTracker`](crate::usage::UsageTracker),
//! and [`KeyStore`](crate::keystore::KeyStore). It is deliberately free of any
//! socket I/O so the entire authorization path can be exercised in unit tests
//! by calling [`Authorizer::handle`] directly with a principal UID and a
//! [`Request`].
//!
//! Flow for every request:
//! 1. Map the request type to an [`Operation`]; unknown types are an error
//!    (audited, `InternalError` response).
//! 2. Consult the policy. On deny: audit `Denied`, return `Denied` status, and
//!    **do not** touch the keystore or usage counters.
//! 3. On allow: execute against the keystore. On success: bump usage counters
//!    and audit `Allowed`. On keystore error: audit `Error` and map to a status
//!    code.

use std::sync::Arc;

use crate::audit::{AuditRecord, AuditSink, Outcome};
use crate::keystore::{KeyStore, KeyStoreError};
use crate::policy::{Operation, Policy};
use crate::protocol::{Request, Response, StatusCode};
use crate::usage::UsageTracker;

/// Status byte returned to a principal that lacks authorization.
///
/// Rather than overloading `InternalError`, we use a dedicated `Denied` status
/// (additive — see [`StatusCode`]). Existing clients that only check `== 0` for
/// success are unaffected.
pub const STATUS_DENIED: u8 = StatusCode::Denied as u8;

/// The authorized request handler. Cheaply cloneable references are held behind
/// `Arc` so a single `Authorizer` can be shared across async tasks.
pub struct Authorizer {
    store: Arc<KeyStore>,
    policy: Arc<Policy>,
    audit: Arc<dyn AuditSink>,
    usage: Arc<UsageTracker>,
}

impl Authorizer {
    /// Builds an [`Authorizer`] from its collaborators.
    #[must_use]
    pub fn new(
        store: Arc<KeyStore>,
        policy: Arc<Policy>,
        audit: Arc<dyn AuditSink>,
        usage: Arc<UsageTracker>,
    ) -> Self {
        Self {
            store,
            policy,
            audit,
            usage,
        }
    }

    /// Read-only access to the usage tracker (for query endpoints / monitoring).
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn usage(&self) -> &UsageTracker {
        &self.usage
    }

    /// Authorize and (if permitted) execute one request on behalf of
    /// `principal` (the peer UID).
    ///
    /// This is the single entry point used by both the socket server and the
    /// unit tests. It never panics and always emits exactly one audit record.
    #[must_use]
    pub fn handle(&self, principal: u32, req: &Request) -> Response {
        let Some(op) = Operation::from_request_type(req.request_type) else {
            // Unknown request type: there is no Operation to attribute it to, so
            // we still emit an Error audit record (with the raw type in `detail`)
            // and reject. We use `Operation::Sign` only as a structural
            // placeholder; the `detail` field is the authoritative description.
            self.audit_event(
                principal,
                &req.label,
                Operation::Sign,
                Outcome::Error,
                Some(format!("unknown request_type {}", req.request_type)),
            );
            return Response {
                status: StatusCode::InternalError as u8,
                payload: vec![],
            };
        };

        // 1. Authorization decision (default-deny).
        if !self.policy.is_allowed(principal, &req.label, op) {
            self.audit_event(
                principal,
                &req.label,
                op,
                Outcome::Denied,
                Some("no grant for (principal, key, operation)".into()),
            );
            return Response {
                status: STATUS_DENIED,
                payload: vec![],
            };
        }

        // 2. Authorized — execute against the keystore.
        let result = self.execute(op, req);

        match result {
            Ok(payload) => {
                // 3a. Success: bump usage counters, then audit Allowed.
                self.usage.record_success(&req.label, op);
                self.audit_event(principal, &req.label, op, Outcome::Allowed, None);
                Response {
                    status: StatusCode::Ok as u8,
                    payload,
                }
            }
            Err(err) => {
                // 3b. Authorized but failed: audit Error, map status. No counter bump.
                let status = status_for_error(op, &err);
                self.audit_event(
                    principal,
                    &req.label,
                    op,
                    Outcome::Error,
                    Some(err.to_string()),
                );
                Response {
                    status: status as u8,
                    payload: vec![],
                }
            }
        }
    }

    /// Dispatches an *already-authorized* operation to the keystore.
    fn execute(&self, op: Operation, req: &Request) -> Result<Vec<u8>, KeyStoreError> {
        match op {
            Operation::Generate => self.store.generate(&req.label),
            Operation::Export => self.store.public_key(&req.label),
            Operation::Sign => self.store.sign(&req.label, &req.payload),
            Operation::Rotate => self.store.rotate(&req.label),
            Operation::Delete => self.store.delete(&req.label).map(|()| Vec::new()),
        }
    }

    /// Emits one audit record, logging (but never failing the request on) a
    /// sink error.
    fn audit_event(
        &self,
        principal: u32,
        key: &str,
        op: Operation,
        outcome: Outcome,
        detail: Option<String>,
    ) {
        let record = AuditRecord::now(principal, key, op, outcome, detail);
        if let Err(e) = self.audit.record(&record) {
            tracing::error!("audit sink write failed: {e}");
        }
    }
}

/// Maps a [`KeyStoreError`] to the wire [`StatusCode`], preserving the
/// historical `SigningError` status for failures on the sign path so existing
/// clients see the same codes they did before.
fn status_for_error(op: Operation, err: &KeyStoreError) -> StatusCode {
    match err {
        KeyStoreError::NotFound(_) => StatusCode::NotFound,
        KeyStoreError::AlreadyExists(_) => StatusCode::AlreadyExists,
        KeyStoreError::Io(_) | KeyStoreError::Internal(_) if op == Operation::Sign => {
            StatusCode::SigningError
        }
        KeyStoreError::Io(_) | KeyStoreError::Internal(_) => StatusCode::InternalError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::MemoryAuditSink;
    use crate::policy::PolicyBuilder;
    use crate::protocol::Request;
    use tempfile::TempDir;

    const ALICE: u32 = 1000;
    const MALLORY: u32 = 1001;

    struct Harness {
        _dir: TempDir,
        authz: Authorizer,
        audit: Arc<MemoryAuditSink>,
        usage: Arc<UsageTracker>,
    }

    fn harness(policy: Policy) -> Harness {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(KeyStore::new(dir.path()).unwrap());
        let audit = Arc::new(MemoryAuditSink::new());
        let usage = Arc::new(UsageTracker::new());
        let audit_sink: Arc<dyn AuditSink> = audit.clone();
        let authz = Authorizer::new(store, Arc::new(policy), audit_sink, usage.clone());
        Harness {
            _dir: dir,
            authz,
            audit,
            usage,
        }
    }

    fn req(request_type: u8, label: &str, payload: &[u8]) -> Request {
        Request {
            request_type,
            label: label.to_string(),
            payload: payload.to_vec(),
        }
    }

    // Adversarial test (a): a UID without per-key permission is denied.
    #[test]
    fn uid_without_permission_is_denied() {
        // Alice may sign "app-key"; Mallory has no grants at all.
        let policy = PolicyBuilder::new()
            .grant(ALICE, "app-key", [Operation::Generate, Operation::Sign])
            .build();
        let h = harness(policy);

        // Alice creates the key so it actually exists.
        let gen = h.authz.handle(ALICE, &req(1, "app-key", &[]));
        assert_eq!(gen.status, StatusCode::Ok as u8);

        // Mallory attempts to sign — must be denied, not "not found".
        let resp = h.authz.handle(MALLORY, &req(3, "app-key", b"msg"));
        assert_eq!(resp.status, STATUS_DENIED);
        assert!(resp.payload.is_empty());
    }

    // Adversarial test (b): denied attempts ARE recorded in the audit log.
    #[test]
    fn denied_attempts_are_audited() {
        let policy = PolicyBuilder::new()
            .grant(ALICE, "app-key", [Operation::Sign])
            .build();
        let h = harness(policy);

        let _ = h.authz.handle(MALLORY, &req(3, "app-key", b"msg"));

        let records = h.audit.records();
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.principal_uid, MALLORY);
        assert_eq!(r.key, "app-key");
        assert_eq!(r.operation, Operation::Sign);
        assert_eq!(r.outcome, Outcome::Denied);
        assert!(r.detail.is_some());
    }

    // Adversarial test (c): a permitted UID succeeds and the usage counter increments.
    #[test]
    fn permitted_uid_succeeds_and_increments_usage() {
        let policy = PolicyBuilder::new()
            .grant(ALICE, "app-key", [Operation::Generate, Operation::Sign])
            .build();
        let h = harness(policy);

        assert_eq!(
            h.authz.handle(ALICE, &req(1, "app-key", &[])).status,
            StatusCode::Ok as u8
        );
        // Generate counts as a successful op.
        assert_eq!(h.usage.count("app-key", Operation::Generate), 1);

        // Two successful signs.
        for _ in 0..2 {
            let resp = h.authz.handle(ALICE, &req(3, "app-key", b"data"));
            assert_eq!(resp.status, StatusCode::Ok as u8);
            assert!(!resp.payload.is_empty());
        }
        assert_eq!(h.usage.count("app-key", Operation::Sign), 2);

        let usage = h.usage.usage("app-key").unwrap();
        assert_eq!(usage.total, 3); // 1 generate + 2 sign
        assert!(usage.last_used_unix_ms.is_some());

        // And every successful op produced an Allowed audit record.
        let allowed = h
            .audit
            .records()
            .into_iter()
            .filter(|r| r.outcome == Outcome::Allowed)
            .count();
        assert_eq!(allowed, 3);
    }

    // Adversarial test (d): default-deny holds for an unconfigured key.
    #[test]
    fn default_deny_for_unconfigured_key() {
        // Alice is granted on "app-key" but nothing is configured for "secret-key".
        let policy = PolicyBuilder::new()
            .grant(ALICE, "app-key", [Operation::Sign, Operation::Generate])
            .build();
        let h = harness(policy);

        // Even the otherwise-privileged Alice is denied on an unconfigured key.
        let resp = h.authz.handle(ALICE, &req(1, "secret-key", &[]));
        assert_eq!(resp.status, STATUS_DENIED);

        // Nothing was created; usage stays empty; the deny was audited.
        assert!(h.usage.usage("secret-key").is_none());
        let records = h.audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Denied);
        assert_eq!(records[0].key, "secret-key");
    }

    #[test]
    fn unknown_request_type_is_internal_error_and_no_usage() {
        let h = harness(Policy::default());
        let resp = h.authz.handle(ALICE, &req(99, "k", &[]));
        assert_eq!(resp.status, StatusCode::InternalError as u8);
        assert!(h.usage.usage("k").is_none());
        // The malformed attempt is still audited as an Error.
        let records = h.audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Error);
    }

    #[test]
    fn authorized_but_missing_key_audits_error_not_allowed() {
        // Alice may sign "app-key" but never generated it.
        let policy = PolicyBuilder::new()
            .grant(ALICE, "app-key", [Operation::Sign])
            .build();
        let h = harness(policy);

        let resp = h.authz.handle(ALICE, &req(3, "app-key", b"msg"));
        assert_eq!(resp.status, StatusCode::NotFound as u8);

        // No usage increment on failure.
        assert!(h.usage.usage("app-key").is_none());
        let records = h.audit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Error);
    }
}
