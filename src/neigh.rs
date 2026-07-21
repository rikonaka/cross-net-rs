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
#[cfg(target_os = "macos")]
use n_macos::get_net_neighs;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub mod n_bsd;
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
use n_bsd::get_net_neighs;

#[derive(Debug, Clone)]
pub struct NetIf {
    pub ifname: String,
    pub ifindex: u32,
}

impl PartialEq for NetIf {
    fn eq(&self, other: &Self) -> bool {
        self.ifindex == other.ifindex
    }
}

#[derive(Debug, Clone)]
pub struct MacInfo {
    mac: MacAddr,
    /// The interface name associated with the MAC address, if available.
    /// On Linux and MacOS, this is usually interface name, on Windows, this is usually interface index.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    ifindex: Option<u32>,
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    ifname: Option<String>,
}

impl MacInfo {
    /// On Unix-like systems, we can get the interface name directly from the neighbor cache.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub fn interface_name(&self) -> Result<Option<String>, CrossNetError> {
        let net_ifs = get_net_ifs()?;
        if let Some(iface) = &self.ifindex {
            for net_if in &net_ifs {
                if iface == &net_if.ifindex {
                    return Ok(Some(net_if.ifname.clone()));
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
            let iface_str = match &mac_info.ifindex {
                Some(iface) => iface.to_string(),
                None => "N/A".to_string(),
            };
            #[cfg(any(
                target_os = "macos",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            ))]
            let iface_str = match &mac_info.ifname {
                Some(iface) => iface.clone(),
                None => "N/A".to_string(),
            };
            write!(f, "{}:{}({})", ip, mac_info.mac.to_string(), iface_str)?;
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
            ifindex: Some(n.ifindex),
            #[cfg(any(
                target_os = "macos",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            ))]
            ifname: Some(n.ifname),
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
            let interface = match &mac_info.ifindex {
                Some(iface) => iface.to_string(),
                None => "N/A".to_string(),
            };
            #[cfg(target_os = "macos")]
            let interface = match &mac_info.ifname {
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
            let ind = mac_info.ifindex.clone().unwrap_or_default();
            #[cfg(target_os = "macos")]
            let ind = mac_info.ifname.clone().unwrap_or_default();
            println!("Interface name for ind {}: {}", ind, interface);
        }
    }
}
