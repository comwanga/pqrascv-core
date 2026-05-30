//! pqrascv-keyd: ML-DSA key management daemon.
//!
//! Usage: set KEYD_SOCKET and KEYD_KEYDIR environment variables.

#[cfg(unix)]
mod keystore;
#[cfg(unix)]
mod protocol;
#[cfg(unix)]
mod server;

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
        std::fs::create_dir_all(socket_path.parent().unwrap_or(std::path::Path::new("/tmp")))?;
        let store = keystore::KeyStore::new(&key_dir)?;
        let srv = server::Server::new(store);

        tokio::select! {
            result = srv.run(&socket_path) => { result?; }
            _ = tokio::signal::ctrl_c() => { tracing::info!("keyd shutting down."); }
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
