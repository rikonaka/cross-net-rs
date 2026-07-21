use libc::c_int;
use libc::c_void;
use std::ffi::CStr;
use std::io;
use std::mem::size_of;
use std::mem::zeroed;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::ptr;
use subnetwork::IpPool;
use subnetwork::Ipv4Pool;
use subnetwork::Ipv6Pool;
use subnetwork::NetmaskExt;

use crate::error::CrossNetError;
use crate::iface::NetFamily;
use crate::route::NetRoute;
use crate::route::NetRouteAddr;
use crate::route::NetType;

#[derive(Debug, Clone)]
struct RouteEntry {
    destination: Option<IpAddr>,
    gateway: Option<IpAddr>,
    netmask: Option<IpAddr>,
    ifname: Option<String>,
    flags: i32,
}

const RTAX_DST: usize = 0;
const RTAX_GATEWAY: usize = 1;
const RTAX_NETMASK: usize = 2;
const RTAX_IFP: usize = 4;
const RTAX_MAX: usize = 8;

#[inline]
fn roundup_sa(len: usize) -> usize {
    let align = size_of::<usize>();
    (len + align - 1) & !(align - 1)
}

unsafe fn parse_sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    let fam = (*sa).sa_family as c_int;
    match fam {
        libc::AF_INET => {
            let sin: *const libc::sockaddr_in = sa as *const libc::sockaddr_in;
            let octets = (*sin).sin_addr.s_addr.to_be_bytes();
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        libc::AF_INET6 => {
            let sin6: *const libc::sockaddr_in6 = sa as *const libc::sockaddr_in6;
            Some(IpAddr::V6(Ipv6Addr::from((*sin6).sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

unsafe fn parse_ifname(sa: *const libc::sockaddr) -> Option<String> {
    if sa.is_null() {
        return None;
    }
    if (*sa).sa_family as c_int != libc::AF_LINK {
        return None;
    }
    let sdl = sa as *const libc::sockaddr_dl;
    let nlen = (*sdl).sdl_nlen as usize;
    if nlen == 0 {
        return None;
    }
    let base = (*sdl).sdl_data.as_ptr() as *const i8;
    let bytes = std::slice::from_raw_parts(base as *const u8, nlen);
    Some(String::from_utf8_lossy(bytes).to_string())
}

unsafe fn list_routes() -> io::Result<Vec<RouteEntry>> {
    // CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP2, 0
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_UNSPEC,
        libc::NET_RT_DUMP2,
        0,
    ];

    let mut needed: usize = 0;
    if libc::sysctl(
        mib.as_mut_ptr(),
        mib.len() as u32,
        ptr::null_mut(),
        &mut needed,
        ptr::null_mut(),
        0,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut buf = vec![0u8; needed];
    if libc::sysctl(
        mib.as_mut_ptr(),
        mib.len() as u32,
        buf.as_mut_ptr() as *mut c_void,
        &mut needed,
        ptr::null_mut(),
        0,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }

    buf.truncate(needed);

    let mut routes = Vec::new();
    let mut off = 0usize;

    while off + size_of::<libc::rt_msghdr2>() <= buf.len() {
        let rtm = &*(buf.as_ptr().add(off) as *const libc::rt_msghdr2);
        let msglen = rtm.rtm_msglen as usize;
        if msglen == 0 || off + msglen > buf.len() {
            break;
        }

        if rtm.rtm_version != libc::RTM_VERSION as u8 {
            off += msglen;
            continue;
        }

        // RTM_GET/RTM_ADD/RTM_CHANGE
        let mut addrs: [*const libc::sockaddr; RTAX_MAX] = [ptr::null(); RTAX_MAX];
        let mut p = (buf.as_ptr().add(off) as *const u8).add(size_of::<libc::rt_msghdr2>());
        let mut addrs_mask = rtm.rtm_addrs as i32;

        for i in 0..RTAX_MAX {
            if (addrs_mask & (1 << i)) != 0 {
                let sa = p as *const libc::sockaddr;
                addrs[i] = sa;

                let slen = if (*sa).sa_len == 0 {
                    size_of::<libc::sockaddr>()
                } else {
                    (*sa).sa_len as usize
                };
                p = p.add(roundup_sa(slen));
            }
        }

        let destination = parse_sockaddr_ip(addrs[RTAX_DST]);
        let gateway = parse_sockaddr_ip(addrs[RTAX_GATEWAY]);
        let netmask = parse_sockaddr_ip(addrs[RTAX_NETMASK]);
        let ifname = parse_ifname(addrs[RTAX_IFP]);

        routes.push(RouteEntry {
            destination,
            gateway,
            netmask,
            ifname,
            flags: rtm.rtm_flags,
        });

        off += msglen;
    }

    Ok(routes)
}

pub fn get_net_routes() -> Result<Vec<NetRoute>, CrossNetError> {
    let routes = unsafe { list_routes()? };
    let mut rets = Vec::new();
    for r in routes {
        if let (Some(dst), Some(gateway), Some(netmask), Some(ifname)) =
            (r.destination, r.gateway, r.netmask, r.ifname)
        {
            let netmask_ext = NetmaskExt::from_addr(netmask);
            let prefix = netmask_ext.get_prefix();
            let (dst, family) = match dst {
                IpAddr::V4(ipv4) => {
                    let d = if prefix == 32 {
                        NetRouteAddr::IpAddr(dst)
                    } else {
                        let pool = Ipv4Pool::new(ipv4, prefix)?;
                        NetRouteAddr::IpPool(IpPool::V4(pool))
                    };
                    (d, NetFamily::Ipv4)
                }
                IpAddr::V6(ipv6) => {
                    let d = if prefix == 128 {
                        NetRouteAddr::IpAddr(dst)
                    } else {
                        let pool = Ipv6Pool::new(ipv6, prefix)?;
                        NetRouteAddr::IpPool(IpPool::V6(pool))
                    };
                    (d, NetFamily::Ipv6)
                }
            };
            let gateway_addr = NetRouteAddr::IpAddr(gateway);
            let route = NetRoute {
                dst,
                src: None,
                gateway: Some(gateway_addr),
                ntype: NetType::Unicast,
                family,
            };
            rets.push(route);
        }
    }
    Ok(rets)
}
