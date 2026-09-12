use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Invalid CIDR network string: {0}")]
    InvalidCidr(String),

    #[error("Socket I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network parse error: {0}")]
    IpNet(#[from] ipnet::AddrParseError),
}
