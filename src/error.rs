use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProviderError {
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Quote parsing error: {0}")]
    QuoteParseError(String),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("PPID mismatch")]
    PPIDMismatch,

    #[error("Public key error: {0}")]
    PublicKeyError(String),

    #[error("Quote verification failed")]
    QuoteVerificationError,

    #[error("DCAP error")]
    DcapError,

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("restart required: permission denied {context}")]
    RestartRequired {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

impl From<serde_json::Error> for ProviderError {
    fn from(e: serde_json::Error) -> Self {
        ProviderError::SerializationError(e.to_string())
    }
}
