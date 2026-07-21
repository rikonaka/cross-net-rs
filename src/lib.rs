pub mod error;
pub mod iface;
pub mod neigh;
pub mod route;

pub type Result<T, E = error::CrossNetError> = std::result::Result<T, E>;
