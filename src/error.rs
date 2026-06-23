use thiserror::Error;

#[derive(Error, Debug)]
pub enum CrossNetError {
    #[error("io error: {0}")]
    StdIOError(#[from] std::io::Error),
    #[error("failed to parse mac address: {mac}")]
    ParseMacAddrErr { mac: String },
    #[error("regex error: {0}")]
    RegexErr(#[from] regex::Error),
}
