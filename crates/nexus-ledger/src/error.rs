use thiserror::Error;

#[derive(Error, Debug)]
pub enum LedgerError {
    #[error("SQLite database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Blockchain audit failure at block #{index}: calculated '{calculated}', expected '{expected}'")]
    BlockchainTamper {
        index: u64,
        calculated: String,
        expected: String,
    },

    #[error("Blockchain sequence error: expected block #{expected}, found #{actual}")]
    SequenceMismatch { expected: u64, actual: u64 },
}
