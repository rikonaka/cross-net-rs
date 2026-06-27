use thiserror::Error;

#[derive(Error, Debug)]
pub enum CrossNetError {
    #[error("io error: {0}")]
    StdIOError(#[from] std::io::Error),
    #[error("failed to parse mac address: {mac}")]
    ParseMacAddrErr { mac: String },
    #[error("failed to parse ip address: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),
    /* n_windows */
    #[cfg(target_os = "windows")]
    #[error("windows core error: {0}")]
    WindowsError(#[from] windows::core::Error),
    /* n_linux */
    #[cfg(target_os = "linux")]
    #[error("linux rtnetlink error: {0}")]
    LinuxError(#[from] rtnetlink::Error),
    /* r_linux */
    #[cfg(target_os = "linux")]
    #[error("linux ip pool error: {0}")]
    IpPoolError(#[from] subnetwork::SubnetworkError),
}
