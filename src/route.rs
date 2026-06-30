use std::fmt;
use std::net::IpAddr;
use subnetwork::IpPool;

use crate::error::CrossNetError;
use crate::iface::NetFamily;

#[cfg(target_os = "linux")]
pub mod r_linux;
#[cfg(target_os = "linux")]
use r_linux::get_net_routes;

#[cfg(target_os = "windows")]
pub mod r_windows;
#[cfg(target_os = "windows")]
use r_windows::get_net_routes;

#[cfg(target_os = "macos")]
pub mod r_macos;
#[cfg(target_os = "macos")]
use r_macos::get_net_routes;

#[derive(Debug, Clone, Hash)]
pub enum NetRouteAddr {
    IpPool(IpPool),
    IpAddr(IpAddr),
}

impl PartialEq for NetRouteAddr {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (NetRouteAddr::IpPool(p1), NetRouteAddr::IpPool(p2)) => p1 == p2,
            (NetRouteAddr::IpAddr(a1), NetRouteAddr::IpAddr(a2)) => a1 == a2,
            _ => false,
        }
    }
}

impl Eq for NetRouteAddr {}

impl fmt::Display for NetRouteAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetRouteAddr::IpPool(pool) => write!(f, "{}", pool),
            NetRouteAddr::IpAddr(addr) => write!(f, "{}", addr),
        }
    }
}

/// Indicates the type of network route,
/// default route or normal route.
/// Default route is the route that has no destination address,
/// and it is used when there is no other route that matches the destination address of a packet.
/// Normal route is the route that has a specific destination address,
/// and it is used when there is a matching route for the destination address of a packet.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetType {
    Normal,
    Default,
}

#[derive(Debug, Clone)]
pub struct NetRoute {
    pub dst: Option<NetRouteAddr>,
    pub src: Option<NetRouteAddr>,
    pub gateway: Option<NetRouteAddr>,
    pub ntype: NetType,
    pub family: NetFamily,
}

impl fmt::Display for NetRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(dst) = &self.dst {
            if let Some(src) = &self.src {
                write!(f, "dst: {}, src: {}", dst, src)?;
            } else {
                write!(f, "dst: {}", dst)?;
            }
        } else if let Some(gateway) = &self.gateway {
            if let Some(src) = &self.src {
                write!(f, "gateway: {}, src: {}", gateway, src)?;
            } else {
                write!(f, "gateway: {}", gateway)?;
            }
        }
        Ok(())
    }
}

impl PartialEq for NetRoute {
    fn eq(&self, other: &Self) -> bool {
        self.dst == other.dst
    }
}

pub struct RouteCache(Vec<NetRoute>);

impl fmt::Display for RouteCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for route in &self.0 {
            write!(f, "{}\n", route)?;
        }
        Ok(())
    }
}

impl RouteCache {
    pub fn search_route(&self, dst_addr: IpAddr) -> Option<NetRoute> {
        for route in &self.0 {
            match &route.dst {
                Some(NetRouteAddr::IpPool(pool)) => {
                    if pool.contains(dst_addr) {
                        return Some(route.clone());
                    }
                }
                Some(NetRouteAddr::IpAddr(addr)) => {
                    if *addr == dst_addr {
                        return Some(route.clone());
                    }
                }
                None => {}
            }
        }

        // no route found for the given destination address
        // now we use the default route if it exists
        for route in &self.0 {
            match dst_addr {
                IpAddr::V4(_) => {
                    if route.ntype == NetType::Default && route.family == NetFamily::Ipv4 {
                        return Some(route.clone());
                    }
                }
                IpAddr::V6(_) => {
                    if route.ntype == NetType::Default && route.family == NetFamily::Ipv6 {
                        return Some(route.clone());
                    }
                }
            }
        }

        None
    }
}

pub fn get_route_cache() -> Result<RouteCache, CrossNetError> {
    let ret = get_net_routes()?;
    let mut rets = Vec::new();
    for route in ret {
        rets.push(route);
    }
    let route_cache = RouteCache(rets);
    Ok(route_cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    #[test]
    fn test_route() {
        let routes = get_route_cache().unwrap();
        let mut dst_addrs = Vec::new();

        let dst_addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        dst_addrs.push(dst_addr);
        let dst_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 78));
        dst_addrs.push(dst_addr);

        for dst_addr in dst_addrs {
            let route = routes.search_route(dst_addr);
            match route {
                Some(r) => {
                    println!("found route for {}: {}", dst_addr, r);
                }
                None => {
                    println!("no route found for {}", dst_addr);
                }
            }
        }
    }
}
