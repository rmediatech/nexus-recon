use thiserror::Error;

#[derive(Error, Debug)]
pub enum NexusError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Network/IP error: {0}")]
    Network(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML serialization/deserialization error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Database ledger error: {0}")]
    Database(String),

    #[error("Unauthorized action: {0}")]
    Unauthorized(String),

    #[error("Dry-Run mode blocked action: {0}")]
    DryRunBlocked(String),

    #[error("Destructive action blocked: {0}")]
    DestructiveActionBlocked(String),

    #[error("Integrity check failed: expected signature '{expected}', got '{actual}'")]
    IntegrityMismatch { expected: String, actual: String },
}

pub type Result<T> = std::result::Result<T, NexusError>;
