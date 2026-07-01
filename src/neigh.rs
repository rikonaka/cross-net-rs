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

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub mod n_unix;
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
use n_unix::get_net_neighs;

#[derive(Debug, Clone)]
pub struct NetIf {
    pub if_name: String,
    pub if_index: u32,
}

impl PartialEq for NetIf {
    fn eq(&self, other: &Self) -> bool {
        self.if_index == other.if_index
    }
}

#[derive(Debug, Clone)]
pub struct MacInfo {
    mac: MacAddr,
    /// The interface name associated with the MAC address, if available.
    /// On Linux and MacOS, this is usually interface name, on Windows, this is usually interface index.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    if_index: Option<u32>,
    #[cfg(target_os = "macos")]
    if_name: Option<String>,
}

impl MacInfo {
    /// On Unix-like systems, we can get the interface name directly from the neighbor cache.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub fn interface_name(&self) -> Result<Option<String>, CrossNetError> {
        let net_ifs = get_net_ifs()?;
        if let Some(iface) = &self.if_index {
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
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            let iface_str = match &mac_info.if_index {
                Some(iface) => iface.to_string(),
                None => "N/A".to_string(),
            };
            #[cfg(target_os = "macos")]
            let iface_str = match &mac_info.if_name {
                Some(iface) => iface.clone(),
                None => "N/A".to_string(),
            };
            write!(f, "{}:{}({})", ip, mac_info.mac.to_string(), iface_str,)?;
        }
        Ok(())
    }
}

impl NeighborCache {
    pub fn search_mac(&self, ip: &IpAddr) -> Option<MacAddr> {
        self.0.get(ip).map(|mac_info| mac_info.mac)
    }
}

pub fn get_neighbor_cache() -> Result<NeighborCache, CrossNetError> {
    let net_neighs = get_net_neighs()?;
    let mut rets = HashMap::new();

    for n in net_neighs {
        let mac_info = MacInfo {
            mac: n.mac,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            if_index: Some(n.if_index),
            #[cfg(target_os = "macos")]
            if_name: Some(n.if_name),
        };
        rets.insert(n.ip, mac_info);
    }

    let neighbor_cache = NeighborCache(rets);
    Ok(neighbor_cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_neighbor_cache() {
        let neighbor_cache = get_neighbor_cache().unwrap();
        for (ip, mac_info) in &neighbor_cache.0 {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            let interface = match &mac_info.if_index {
                Some(iface) => iface.to_string(),
                None => "N/A".to_string(),
            };
            #[cfg(target_os = "macos")]
            let interface = match &mac_info.if_name {
                Some(iface) => iface.clone(),
                None => "N/A".to_string(),
            };
            println!(
                "IP: {}, MAC: {}, Interface: {}",
                ip,
                mac_info.mac.to_string(),
                interface
            );

            #[cfg(any(target_os = "linux", target_os = "windows"))]
            let ind = mac_info.if_index.clone().unwrap_or_default();
            #[cfg(target_os = "macos")]
            let ind = mac_info.if_name.clone().unwrap_or_default();
            println!("Interface name for ind {}: {}", ind, interface);
        }
    }
}
