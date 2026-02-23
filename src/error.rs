#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("database error: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("api error {status}: {body}")]
    Api { status: u16, body: String },
    #[error("not found: {0}")]
    NotFound(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
