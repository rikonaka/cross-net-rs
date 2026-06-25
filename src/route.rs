use std::collections::HashMap;
use crate::error::CrossNetError;
use crate::iface::MacAddr;

#[cfg(target_os = "linux")]
pub mod r_linux;

