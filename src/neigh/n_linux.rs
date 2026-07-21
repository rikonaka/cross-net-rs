use futures::stream::TryStreamExt;
use rtnetlink::new_connection;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::packet_route::neighbour::NeighbourAddress;
use rtnetlink::packet_route::neighbour::NeighbourAttribute;
use rtnetlink::packet_route::neighbour::NeighbourState;
use std::net::IpAddr;
use tokio::runtime::Runtime;

use crate::error::CrossNetError;
use crate::iface::MacAddr;
use crate::neigh::NetIf;

async fn get_ifs_async() -> Result<Vec<NetIf>, CrossNetError> {
    let (connection, handle, _r) = new_connection()?;
    tokio::spawn(connection);

    let mut links = handle.link().get().execute();
    let mut rets = Vec::new();

    while let Some(msg) = links.try_next().await? {
        for la in msg.attributes {
            let if_index = msg.header.index;
            match la {
                LinkAttribute::IfName(if_name) => {
                    let n = NetIf { ifname: if_name, ifindex: if_index };
                    if !rets.contains(&n) {
                        rets.push(n);
                    }
                }
                _ => {}
            }
        }
    }

    Ok(rets)
}

pub(crate) fn get_net_ifs() -> Result<Vec<NetIf>, CrossNetError> {
    let rt = Runtime::new()?;
    rt.block_on(async { get_ifs_async().await })
}

#[derive(Debug, Clone)]
pub struct LinuxNetNeigh {
    pub ifindex: u32,
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub state: NeighbourState,
}

// for contains method, only compare ip
impl PartialEq for LinuxNetNeigh {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip
    }
}

async fn get_neighs_async() -> Result<Vec<LinuxNetNeigh>, CrossNetError> {
    let (connection, handle, _r) = new_connection()?;
    tokio::spawn(connection);

    let mut neighs = handle.neighbours().get().execute();
    let mut rets = Vec::new();

    while let Some(msg) = neighs.try_next().await? {
        let ifindex = msg.header.ifindex;
        let state = msg.header.state;

        let mut ip = None;
        let mut mac = None;

        for na in msg.attributes {
            match na {
                NeighbourAttribute::Destination(bytes) => match bytes {
                    NeighbourAddress::Inet(addr) => {
                        ip = Some(IpAddr::V4(addr));
                    }
                    NeighbourAddress::Inet6(addr) => {
                        ip = Some(IpAddr::V6(addr));
                    }
                    NeighbourAddress::Other(bytes) => {
                        ip = match bytes.len() {
                            4 => {
                                let mut arr = [0u8; 4];
                                arr.copy_from_slice(&bytes[..4]);
                                Some(IpAddr::from(arr))
                            }
                            16 => {
                                let mut arr = [0u8; 16];
                                arr.copy_from_slice(&bytes[..16]);
                                Some(IpAddr::from(arr))
                            }
                            _ => None,
                        };
                    }
                    _ => (),
                },
                NeighbourAttribute::LinkLayerAddress(bytes) => {
                    let m = if bytes.len() == 6 {
                        MacAddr::new_eui48(
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                        )
                    } else if bytes.len() == 8 {
                        MacAddr::new_eui64(
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        )
                    } else {
                        #[cfg(feature = "debug")]
                        eprintln!("unsupported mac length: {}", bytes.len());
                        continue;
                    };
                    mac = Some(m);
                }

                _ => {}
            }

            if let Some(ip) = ip {
                if let Some(mac) = mac {
                    let n = LinuxNetNeigh {
                        ifindex,
                        ip,
                        mac,
                        state,
                    };
                    if !rets.contains(&n) {
                        rets.push(n);
                    }
                }
            }
        }
    }

    Ok(rets)
}

pub(crate) fn get_net_neighs() -> Result<Vec<LinuxNetNeigh>, CrossNetError> {
    let rt = Runtime::new()?;
    rt.block_on(async { get_neighs_async().await })
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_linux() {
        let rets = get_net_neighs().unwrap();
        for ret in rets {
            println!(
                "index: {}, ip: {}, mac: {}",
                ret.ifindex,
                ret.ip.to_string(),
                ret.mac.to_string()
            );
        }
    }
}
