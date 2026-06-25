use futures::stream::TryStreamExt;
use rtnetlink::new_connection;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::route::RouteAddress;
use rtnetlink::packet_route::route::RouteAttribute;
use rtnetlink::packet_route::route::RouteMessage;
use std::net::IpAddr;
use tokio::runtime::Runtime;

use crate::error::CrossNetError;
use crate::iface::MacAddr;

#[derive(Debug, Clone)]
pub struct LinuxNetRoute {
    dst: Option<IpAddr>,
    src: Option<IpAddr>,
    gateway: Option<IpAddr>,
}

impl PartialEq for LinuxNetRoute {
    fn eq(&self, other: &Self) -> bool {
        self.dst == other.dst
    }
}

async fn get_route_async() -> Result<Vec<LinuxNetRoute>, CrossNetError> {
    let (connection, handle, _r) = new_connection()?;
    tokio::spawn(connection);

    let mut req = RouteMessage::default();
    req.header.address_family = AddressFamily::Inet;
    let mut routes = handle.route().get(req).execute();
    let mut rets = Vec::new();

    while let Some(msg) = routes.try_next().await? {
        let mut dst = None;
        let mut src = None;
        let mut gateway = None;

        // println!("header: {:?}", msg.header);
        // println!("attributes: {:?}", msg.attributes);
        // header: RouteHeader { address_family: Inet, destination_prefix_length: 0, source_prefix_length: 0, tos: 0, table: 254, protocol: Boot, scope: Universe, kind: Unicast, flags: RouteFlags(Onlink) }
        // attributes: [Table(254), Gateway(Inet(192.168.5.2)), Oif(2)]
        // header: RouteHeader { address_family: Inet, destination_prefix_length: 24, source_prefix_length: 0, tos: 0, table: 254, protocol: Kernel, scope: Link, kind: Unicast, flags: RouteFlags(0x0) }
        // attributes: [Table(254), Destination(Inet(192.168.5.0)), PrefSource(Inet(192.168.5.3)), Oif(2)]
        // header: RouteHeader { address_family: Inet, destination_prefix_length: 8, source_prefix_length: 0, tos: 0, table: 255, protocol: Kernel, scope: Host, kind: Local, flags: RouteFlags(0x0) }
        // attributes: [Table(255), Destination(Inet(127.0.0.0)), PrefSource(Inet(127.0.0.1)), Oif(1)]
        // header: RouteHeader { address_family: Inet, destination_prefix_length: 32, source_prefix_length: 0, tos: 0, table: 255, protocol: Kernel, scope: Host, kind: Local, flags: RouteFlags(0x0) }
        // attributes: [Table(255), Destination(Inet(127.0.0.1)), PrefSource(Inet(127.0.0.1)), Oif(1)]
        // header: RouteHeader { address_family: Inet, destination_prefix_length: 32, source_prefix_length: 0, tos: 0, table: 255, protocol: Kernel, scope: Link, kind: Broadcast, flags: RouteFlags(0x0) }
        // attributes: [Table(255), Destination(Inet(127.255.255.255)), PrefSource(Inet(127.0.0.1)), Oif(1)]
        // header: RouteHeader { address_family: Inet, destination_prefix_length: 32, source_prefix_length: 0, tos: 0, table: 255, protocol: Kernel, scope: Host, kind: Local, flags: RouteFlags(0x0) }
        // attributes: [Table(255), Destination(Inet(192.168.5.3)), PrefSource(Inet(192.168.5.3)), Oif(2)]
        // header: RouteHeader { address_family: Inet, destination_prefix_length: 32, source_prefix_length: 0, tos: 0, table: 255, protocol: Kernel, scope: Link, kind: Broadcast, flags: RouteFlags(0x0) }
        // attributes: [Table(255), Destination(Inet(192.168.5.255)), PrefSource(Inet(192.168.5.3)), Oif(2)]

        for ra in msg.attributes {
            match ra {
                RouteAttribute::Destination(d) => match d {
                    RouteAddress::Inet(ipv4) => {
                        dst = Some(IpAddr::V4(ipv4));
                    }
                    RouteAddress::Inet6(ipv6) => {
                        dst = Some(IpAddr::V6(ipv6));
                    }
                    _ => (),
                },
                RouteAttribute::Gateway(g) => match g {
                    RouteAddress::Inet(ipv4) => {
                        gateway = Some(IpAddr::V4(ipv4));
                    }
                    RouteAddress::Inet6(ipv6) => {
                        gateway = Some(IpAddr::V6(ipv6));
                    }
                    _ => (),
                },
                RouteAttribute::PrefSource(s) => match s {
                    RouteAddress::Inet(ipv4) => {
                        src = Some(IpAddr::V4(ipv4));
                    }
                    RouteAddress::Inet6(ipv6) => {
                        src = Some(IpAddr::V6(ipv6));
                    }
                    _ => (),
                },
                _ => {}
            }
        }
        rets.push(LinuxNetRoute { dst, src, gateway });
    }

    Ok(rets)
}

pub fn get_net_routes() -> Result<Vec<LinuxNetRoute>, CrossNetError> {
    let rt = Runtime::new()?;
    rt.block_on(async { get_route_async().await })
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_linux() {
        let rets = get_net_routes().unwrap();
        for ret in rets {
            println!(
                "dst: {:?}, src: {:?}, gateway: {:?}",
                ret.dst, ret.src, ret.gateway
            );
        }
    }
}
