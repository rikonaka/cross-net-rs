use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use crate::error::CrossNetError;
use crate::iface::MacAddr;

#[cfg(target_os = "windows")]
pub mod n_windows;
#[cfg(target_os = "windows")]
use n_windows::get_net_ifs;
#[cfg(target_os = "windows")]
use n_windows::get_net_neighs;

#[cfg(target_os = "linux")]
pub mod n_linux;
#[cfg(target_os = "linux")]
use n_linux::get_net_ifs;
#[cfg(target_os = "linux")]
use n_linux::get_net_neighs;

#[cfg(target_os = "macos")]
pub mod n_macos;

#[derive(Debug, Clone)]
pub struct MacInfo {
    mac: MacAddr,
    /// The interface name associated with the MAC address, if available.
    /// On Linux and MacOS, this is usually interface name, on Windows, this is usually interface index.
    index: Option<u32>,
}

impl MacInfo {
    /// On Unix-like systems, we can get the interface name directly from the neighbor cache.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub fn interface_name(&self) -> Result<Option<String>, CrossNetError> {
        let net_ifs = get_net_ifs()?;
        if let Some(iface) = &self.index {
            for net_if in &net_ifs {
                if iface == &net_if.if_index {
                    return Ok(Some(net_if.if_name.clone()));
                }
            }
        }
        Ok(None)
    }
}

pub struct NeighborCache(HashMap<IpAddr, MacInfo>);

impl fmt::Display for NeighborCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (ip, mac_info) in &self.0 {
            let iface_str = match &mac_info.index {
                Some(iface) => iface.to_string(),
                None => "N/A".to_string(),
            };
            write!(f, "{}:{}({})", ip, mac_info.mac.to_string(), iface_str,)?;
        }
        Ok(())
    }
}

pub fn get_neighbor_cache() -> Result<HashMap<IpAddr, MacInfo>, CrossNetError> {
    let net_neighs = get_net_neighs()?;
    let mut rets = HashMap::new();
    let mut hm = HashMap::new();

    for n in net_neighs {
        let mac_info = MacInfo {
            mac: n.mac,
            index: Some(n.if_index),
        };
        rets.insert(n.ip, mac_info);
        hm.insert(n.if_index, n.ip);
    }

    Ok(rets)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_neighbor_cache() {
        let neighbor_cache = get_neighbor_cache().unwrap();
        for (ip, mac_info) in &neighbor_cache {
            println!(
                "IP: {}, MAC: {}, Interface: {}",
                ip,
                mac_info.mac.to_string(),
                mac_info
                    .index
                    .map(|i| i.to_string())
                    .as_deref()
                    .unwrap_or("N/A")
            );

            let ind = mac_info.index.clone().unwrap_or_default();
            let iface_name = mac_info.interface_name().unwrap();
            println!(
                "Interface name for ind {}: {}",
                ind,
                iface_name.as_deref().unwrap_or("N/A")
            );
        }
    }
}
