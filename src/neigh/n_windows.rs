use windows::Win32::NetworkManagement::IpHelper::FreeMibTable;
use windows::Win32::NetworkManagement::IpHelper::GetIfTable2;
use windows::Win32::NetworkManagement::IpHelper::GetIpNetTable2;
use windows::Win32::Networking::WinSock::ADDRESS_FAMILY;
use windows::Win32::Networking::WinSock::AF_INET;
use windows::Win32::Networking::WinSock::AF_INET6;
use windows::Win32::Networking::WinSock::SOCKADDR_INET;

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use crate::error::CrossNetError;
use crate::iface::MacAddr;
use crate::neigh::NetIf;

/// More safe way to convert a UTF-16 array to a Rust String, handling null terminators and invalid sequences.
fn utf16_array_to_string(buf: &[u16]) -> String {
    // found the first null terminator in the buffer, or use the full length if none is found
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

pub(crate) fn get_net_ifs() -> Result<Vec<NetIf>, CrossNetError> {
    let mut rets = Vec::new();

    unsafe {
        let mut table_ptr = std::ptr::null_mut();
        GetIfTable2(&mut table_ptr).ok()?;

        let table = &*table_ptr;
        let num_entries = table.NumEntries as usize;
        let first_row_ptr = table.Table.as_ptr();
        let rows = std::slice::from_raw_parts(first_row_ptr, num_entries);
        for row in rows {
            let if_index = row.InterfaceIndex;
            let if_name = utf16_array_to_string(&row.Alias);
            let n = NetIf { if_name, if_index };
            if !rets.contains(&n) {
                rets.push(n);
            }
        }

        FreeMibTable(table_ptr as _);
    }

    Ok(rets)
}

#[derive(Debug, Clone)]
pub struct WindowsNetNeigh {
    pub if_index: u32,
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub state: i32,
}

impl PartialEq for WindowsNetNeigh {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip
    }
}

fn sockaddr_inet_to_ipaddr(addr: &SOCKADDR_INET) -> Result<Option<IpAddr>, CrossNetError> {
    unsafe {
        let family = addr.si_family;

        if family == AF_INET {
            let ipv4 = &addr.Ipv4;
            let octets = ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
            Ok(Some(IpAddr::V4(Ipv4Addr::from(octets))))
        } else if family == AF_INET6 {
            let ipv6 = &addr.Ipv6;
            let octets = ipv6.sin6_addr.u.Byte;
            Ok(Some(IpAddr::V6(Ipv6Addr::from(octets))))
        } else {
            Ok(None)
        }
    }
}

pub(crate) fn get_net_neighs() -> Result<Vec<WindowsNetNeigh>, CrossNetError> {
    let mut rets = Vec::new();
    unsafe {
        let mut table_ptr = std::ptr::null_mut();

        // AF_INET only IPv4
        // AF_INET6 only IPv6
        // 0: AF_UNSPEC all
        let family = ADDRESS_FAMILY(0);
        GetIpNetTable2(family, &mut table_ptr).ok()?;

        let table = &*table_ptr;
        let num_entries = table.NumEntries as usize;
        let rows = std::slice::from_raw_parts(table.Table.as_ptr(), num_entries);

        for row in rows {
            if row.PhysicalAddressLength == 0 {
                continue;
            }

            let state = row.State.0;
            let if_index = row.InterfaceIndex;
            let ip = sockaddr_inet_to_ipaddr(&row.Address)?;
            let mac_bytes = &row.PhysicalAddress[..row.PhysicalAddressLength as usize];
            let mac = if row.PhysicalAddressLength == 6 {
                MacAddr::new_eui48(
                    mac_bytes[0],
                    mac_bytes[1],
                    mac_bytes[2],
                    mac_bytes[3],
                    mac_bytes[4],
                    mac_bytes[5],
                )
            } else if row.PhysicalAddressLength == 8 {
                MacAddr::new_eui64(
                    mac_bytes[0],
                    mac_bytes[1],
                    mac_bytes[2],
                    mac_bytes[3],
                    mac_bytes[4],
                    mac_bytes[5],
                    mac_bytes[6],
                    mac_bytes[7],
                )
            } else {
                #[cfg(feature = "debug")]
                eprintln!("unsupported mac length: {}", row.PhysicalAddressLength);
                continue;
            };

            if let Some(ip) = ip {
                let n = WindowsNetNeigh {
                    if_index,
                    ip,
                    mac,
                    state,
                };
                if !rets.contains(&n) {
                    rets.push(n);
                }
            }
        }

        FreeMibTable(table_ptr as _);
    }
    Ok(rets)
}

#[cfg(target_os = "windows")]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_windows() {
        let rets = get_net_neighs().unwrap();
        for ret in rets {
            println!(
                "index: {}, ip: {}, mac: {}",
                ret.if_index,
                ret.ip.to_string(),
                ret.mac.to_string()
            );
        }
    }
}
