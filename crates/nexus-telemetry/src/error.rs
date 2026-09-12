use thiserror::Error;

#[derive(Error, Debug)]
pub enum TelemetryError {
    #[error("Cryptographic blockchain tamper detected at block #{index}: calculated '{calculated}', expected '{expected}'")]
    TamperDetected {
        index: u64,
        calculated: String,
        expected: String,
    },

    #[error("Invalid sequence in blockchain: expected index {expected}, found {actual}")]
    InvalidSequence { expected: u64, actual: u64 },

    #[error("Invalid prev_hash link at block #{index}: found '{actual}', expected '{expected}'")]
    InvalidPrevHash {
        index: u64,
        actual: String,
        expected: String,
    },

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
