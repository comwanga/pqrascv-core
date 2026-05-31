//! pqrascv-keyd: ML-DSA key management daemon.
//!
//! Usage: set KEYD_SOCKET and KEYD_KEYDIR environment variables.

#[cfg(unix)]
mod audit;
#[cfg(unix)]
mod authz;
#[cfg(unix)]
mod keystore;
#[cfg(unix)]
mod policy;
#[cfg(unix)]
mod protocol;
#[cfg(unix)]
mod server;
#[cfg(unix)]
mod usage;

use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let socket_path = std::env::var("KEYD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/pqrascv/keyd.sock"));

    let key_dir = std::env::var("KEYD_KEYDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/pqrascv/keys"));

    #[cfg(unix)]
    {
        use std::sync::Arc;

        // Authorization policy (default-deny). Loaded from KEYD_POLICY (JSON) if
        // set; otherwise an empty, deny-everything policy is used so the daemon
        // never starts up "open" by accident.
        let policy_path = std::env::var("KEYD_POLICY").map(PathBuf::from).ok();

        // Audit log destination (JSON Lines). Defaults under /var/lib/pqrascv.
        let audit_path = std::env::var("KEYD_AUDIT_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/lib/pqrascv/keyd-audit.log"));

        std::fs::create_dir_all(socket_path.parent().unwrap_or(std::path::Path::new("/tmp")))?;

        let policy = match policy_path {
            Some(ref p) => {
                let loaded = policy::Policy::from_json_file(p)
                    .map_err(|e| anyhow::anyhow!("failed to load policy {p:?}: {e}"))?;
                tracing::info!("loaded authorization policy from {:?}", p);
                loaded
            }
            None => {
                tracing::warn!(
                    "KEYD_POLICY not set — using empty default-deny policy; all requests denied"
                );
                policy::Policy::default()
            }
        };

        let store = Arc::new(keystore::KeyStore::new(&key_dir)?);
        let audit: Arc<dyn audit::AuditSink> = Arc::new(audit::FileAuditSink::new(&audit_path));
        let usage = Arc::new(usage::UsageTracker::new());
        // Keep a handle for the shutdown usage summary.
        let usage_handle = Arc::clone(&usage);
        let authz = authz::Authorizer::new(store, Arc::new(policy), audit, usage);
        let srv = server::Server::new(authz);

        tokio::select! {
            result = srv.run(&socket_path) => { result?; }
            _ = tokio::signal::ctrl_c() => { tracing::info!("keyd shutting down."); }
        }

        // Emit a per-key usage summary so operators can review key activity.
        for (label, stats) in usage_handle.snapshot() {
            tracing::info!(
                key = %label,
                total_ops = stats.total,
                last_used_unix_ms = ?stats.last_used_unix_ms,
                "key usage summary"
            );
        }
    }

    #[cfg(not(unix))]
    {
        eprintln!(
            "pqrascv-keyd only supports Unix platforms. socket={socket_path:?} keydir={key_dir:?}"
        );
    }

    Ok(())
}
