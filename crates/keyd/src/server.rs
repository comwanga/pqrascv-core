//! Unix domain socket server: accepts keyd requests, dispatches to KeyStore.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::keystore::{KeyStore, KeyStoreError};
use crate::protocol::{encode_response, Request, Response, StatusCode};

// SAFETY: getuid(2) is always safe — no invalid states, no side effects.
fn server_uid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }
}

pub struct Server {
    store: Arc<KeyStore>,
}

impl Server {
    pub fn new(store: KeyStore) -> Self {
        Self {
            store: Arc::new(store),
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
            // Reject connections from any UID other than our own.
            let own_uid = server_uid();
            match stream.peer_cred() {
                Ok(cred) if cred.uid() != own_uid => {
                    tracing::warn!(
                        peer_uid = cred.uid(),
                        server_uid = own_uid,
                        "rejected connection from unexpected uid"
                    );
                    continue;
                }
                Err(e) => {
                    tracing::warn!("failed to read peer credentials, rejecting: {e}");
                    continue;
                }
                Ok(_) => {} // same UID — allow
            }
            let store = Arc::clone(&self.store);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, store).await {
                    tracing::warn!("connection error: {e}");
                }
            });
        }
    }
}

async fn handle_connection(mut stream: UnixStream, store: Arc<KeyStore>) -> std::io::Result<()> {
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

        let resp = dispatch(req, &store);
        stream.write_all(&encode_response(&resp).unwrap()).await?;
    }
    Ok(())
}

fn dispatch(req: Request, store: &KeyStore) -> Response {
    match req.request_type {
        1 => match store.generate(&req.label) {
            Ok(vk) => Response {
                status: StatusCode::Ok as u8,
                payload: vk,
            },
            Err(KeyStoreError::AlreadyExists(_)) => Response {
                status: StatusCode::AlreadyExists as u8,
                payload: vec![],
            },
            Err(e) => {
                tracing::error!("generate error: {e}");
                Response {
                    status: StatusCode::InternalError as u8,
                    payload: vec![],
                }
            }
        },
        2 => match store.public_key(&req.label) {
            Ok(vk) => Response {
                status: StatusCode::Ok as u8,
                payload: vk,
            },
            Err(KeyStoreError::NotFound(_)) => Response {
                status: StatusCode::NotFound as u8,
                payload: vec![],
            },
            Err(e) => {
                tracing::error!("export error: {e}");
                Response {
                    status: StatusCode::InternalError as u8,
                    payload: vec![],
                }
            }
        },
        3 => match store.sign(&req.label, &req.payload) {
            Ok(sig) => Response {
                status: StatusCode::Ok as u8,
                payload: sig,
            },
            Err(KeyStoreError::NotFound(_)) => Response {
                status: StatusCode::NotFound as u8,
                payload: vec![],
            },
            Err(e) => {
                tracing::error!("sign error: {e}");
                Response {
                    status: StatusCode::SigningError as u8,
                    payload: vec![],
                }
            }
        },
        4 => match store.rotate(&req.label) {
            Ok(vk) => Response {
                status: StatusCode::Ok as u8,
                payload: vk,
            },
            Err(e) => {
                tracing::error!("rotate error: {e}");
                Response {
                    status: StatusCode::InternalError as u8,
                    payload: vec![],
                }
            }
        },
        5 => match store.delete(&req.label) {
            Ok(()) => Response {
                status: StatusCode::Ok as u8,
                payload: vec![],
            },
            Err(KeyStoreError::NotFound(_)) => Response {
                status: StatusCode::NotFound as u8,
                payload: vec![],
            },
            Err(e) => {
                tracing::error!("delete error: {e}");
                Response {
                    status: StatusCode::InternalError as u8,
                    payload: vec![],
                }
            }
        },
        _ => Response {
            status: StatusCode::InternalError as u8,
            payload: vec![],
        },
    }
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
