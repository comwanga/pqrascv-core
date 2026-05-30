//! Unix domain socket server: accepts keyd requests, dispatches to KeyStore.

use std::path::Path;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::keystore::{KeyStore, KeyStoreError};
use crate::protocol::{Request, Response, StatusCode, encode_response};

pub struct Server {
    store: Arc<KeyStore>,
}

impl Server {
    pub fn new(store: KeyStore) -> Self {
        Self { store: Arc::new(store) }
    }

    pub async fn run(self, socket_path: &Path) -> std::io::Result<()> {
        if socket_path.exists() {
            std::fs::remove_file(socket_path)?;
        }
        let listener = UnixListener::bind(socket_path)?;
        tracing::info!("keyd listening on {:?}", socket_path);

        loop {
            let (stream, _) = listener.accept().await?;
            let store = Arc::clone(&self.store);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, store).await {
                    tracing::warn!("connection error: {e}");
                }
            });
        }
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    store: Arc<KeyStore>,
) -> std::io::Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 1_048_576 {
            tracing::warn!("oversized request ({len} bytes), dropping connection");
            break;
        }

        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;

        let req: Request = match ciborium::from_reader(body.as_slice()) {
            Ok(r) => r,
            Err(_) => {
                let resp = Response { status: StatusCode::InternalError as u8, payload: vec![] };
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
            Ok(vk) => Response { status: StatusCode::Ok as u8, payload: vk },
            Err(KeyStoreError::AlreadyExists(_)) => {
                Response { status: StatusCode::AlreadyExists as u8, payload: vec![] }
            }
            Err(e) => {
                tracing::error!("generate error: {e}");
                Response { status: StatusCode::InternalError as u8, payload: vec![] }
            }
        },
        2 => match store.public_key(&req.label) {
            Ok(vk) => Response { status: StatusCode::Ok as u8, payload: vk },
            Err(KeyStoreError::NotFound(_)) => {
                Response { status: StatusCode::NotFound as u8, payload: vec![] }
            }
            Err(e) => {
                tracing::error!("export error: {e}");
                Response { status: StatusCode::InternalError as u8, payload: vec![] }
            }
        },
        3 => match store.sign(&req.label, &req.payload) {
            Ok(sig) => Response { status: StatusCode::Ok as u8, payload: sig },
            Err(KeyStoreError::NotFound(_)) => {
                Response { status: StatusCode::NotFound as u8, payload: vec![] }
            }
            Err(e) => {
                tracing::error!("sign error: {e}");
                Response { status: StatusCode::SigningError as u8, payload: vec![] }
            }
        },
        4 => match store.rotate(&req.label) {
            Ok(vk) => Response { status: StatusCode::Ok as u8, payload: vk },
            Err(e) => {
                tracing::error!("rotate error: {e}");
                Response { status: StatusCode::InternalError as u8, payload: vec![] }
            }
        },
        5 => match store.delete(&req.label) {
            Ok(()) => Response { status: StatusCode::Ok as u8, payload: vec![] },
            Err(KeyStoreError::NotFound(_)) => {
                Response { status: StatusCode::NotFound as u8, payload: vec![] }
            }
            Err(e) => {
                tracing::error!("delete error: {e}");
                Response { status: StatusCode::InternalError as u8, payload: vec![] }
            }
        },
        _ => Response { status: StatusCode::InternalError as u8, payload: vec![] },
    }
}
