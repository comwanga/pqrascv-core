#[derive(Debug, thiserror::Error)]
pub enum SigstoreClientError {
    #[error("HTTP transport error: {0}")]
    Transport(String),
    #[error("HTTP {status} error: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Fulcio error: {0}")]
    Fulcio(String),
    #[error("Rekor error: {0}")]
    Rekor(String),
}
