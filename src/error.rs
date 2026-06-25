use thiserror::Error;

#[derive(Error, Debug)]
pub enum CrossNetError {
    #[error("io error: {0}")]
    StdIOError(#[from] std::io::Error),
    #[error("failed to parse mac address: {mac}")]
    ParseMacAddrErr { mac: String },
    #[error("regex error: {0}")]
    RegexErr(#[from] regex::Error),
    #[error("failed to parse ip address: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),
    /* n_windows */
    #[error("windows error: {0}")]
    WindowsError(#[from] windows::core::Error),
}
