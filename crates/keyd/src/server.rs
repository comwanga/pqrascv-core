//! Unix domain socket server: accepts keyd requests, dispatches to KeyStore.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::authz::Authorizer;
use crate::protocol::{encode_response, Request, Response, StatusCode};

// SAFETY: getuid(2) is always safe — no invalid states, no side effects.
// Only referenced by the smoke test now that per-key ACLs (not a server-UID
// match) make the authorization decision.
#[cfg(test)]
fn server_uid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }
}

pub struct Server {
    authz: Arc<Authorizer>,
}

impl Server {
    /// Builds a server from a fully-wired [`Authorizer`] (policy + audit +
    /// usage + keystore).
    #[must_use]
    pub fn new(authz: Authorizer) -> Self {
        Self {
            authz: Arc::new(authz),
        }
    }

    pub async fn run(self, socket_path: &Path) -> std::io::Result<()> {
        if socket_path.exists() {
            std::fs::remove_file(socket_path)?;
        }
        let listener = UnixListener::bind(socket_path)?;
        // Restrict socket to owner-only (0600) — prevents other OS users from connecting.
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        tracing::info!("keyd listening on {:?}", socket_path);

        loop {
            let (stream, _) = listener.accept().await?;
            // Coarse first gate: read the authenticated peer UID via SO_PEERCRED.
            // We no longer require it to equal the server UID — per-key ACLs in
            // the Authorizer make the fine-grained decision. A failure to read
            // peer credentials is fatal-to-the-connection (we cannot identify a
            // principal, so default-deny by refusing to serve).
            let peer_uid = match stream.peer_cred() {
                Ok(cred) => cred.uid(),
                Err(e) => {
                    tracing::warn!("failed to read peer credentials, rejecting: {e}");
                    continue;
                }
            };
            let authz = Arc::clone(&self.authz);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, peer_uid, &authz).await {
                    tracing::warn!("connection error: {e}");
                }
            });
        }
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    peer_uid: u32,
    authz: &Authorizer,
) -> std::io::Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > 65_536 {
            tracing::warn!("invalid frame length ({len} bytes), dropping connection");
            break;
        }

        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;

        let req: Request = match ciborium::from_reader(body.as_slice()) {
            Ok(r) => r,
            Err(_) => {
                let resp = Response {
                    status: StatusCode::InternalError as u8,
                    payload: vec![],
                };
                stream.write_all(&encode_response(&resp).unwrap()).await?;
                continue;
            }
        };

        // All authorization, audit logging, and usage tracking happen inside the
        // Authorizer. `peer_uid` is the principal from SO_PEERCRED.
        let resp = authz.handle(peer_uid, &req);
        stream.write_all(&encode_response(&resp).unwrap()).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_uid_returns_a_uid() {
        // Smoke-test that getuid() is callable and returns a u32.
        // In CI and normal dev we run as a non-root user.
        let uid = server_uid();
        // Root is UID 0; dev/CI users are typically > 0.
        // We just assert the call succeeds and returns consistently.
        assert_eq!(uid, server_uid());
    }
}
