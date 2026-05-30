#[derive(Debug, thiserror::Error)]
pub enum SigstoreClientError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Fulcio error: {0}")]
    Fulcio(String),
    #[error("Rekor error: {0}")]
    Rekor(String),
    #[error("Signing error: {0}")]
    Signing(String),
}
