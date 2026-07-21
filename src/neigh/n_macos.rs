use libc::{c_int, c_void};
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use crate::error::CrossNetError;
use crate::iface::MacAddr;

#[derive(Debug, Clone)]
struct NeighEntry {
    ip: Option<IpAddr>,
    lladdr: Option<String>, // mac string
    ifname: Option<String>,
    flags: i32,
}

const RTAX_DST: usize = 0;
const RTAX_GATEWAY: usize = 1;
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
            let sin = sa as *const libc::sockaddr_in;
            Some(IpAddr::V4(Ipv4Addr::from(
                (*sin).sin_addr.s_addr.to_be_bytes(),
            )))
        }
        libc::AF_INET6 => {
            let sin6 = sa as *const libc::sockaddr_in6;
            Some(IpAddr::V6(Ipv6Addr::from((*sin6).sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

unsafe fn parse_ifname(sa: *const libc::sockaddr) -> Option<String> {
    if sa.is_null() || (*sa).sa_family as c_int != libc::AF_LINK {
        return None;
    }
    let sdl = sa as *const libc::sockaddr_dl;
    let nlen = (*sdl).sdl_nlen as usize;
    if nlen == 0 {
        return None;
    }
    let name_ptr = (*sdl).sdl_data.as_ptr() as *const u8;
    let name = std::slice::from_raw_parts(name_ptr, nlen);
    Some(String::from_utf8_lossy(name).to_string())
}

unsafe fn parse_lladdr(sa: *const libc::sockaddr) -> Option<String> {
    if sa.is_null() || (*sa).sa_family as c_int != libc::AF_LINK {
        return None;
    }
    let sdl = sa as *const libc::sockaddr_dl;

    let nlen = (*sdl).sdl_nlen as usize;
    let alen = (*sdl).sdl_alen as usize;
    if alen == 0 {
        return None;
    }

    let base = (*sdl).sdl_data.as_ptr() as *const u8;
    let mac_ptr = base.add(nlen);
    let mac = std::slice::from_raw_parts(mac_ptr, alen);

    Some(
        mac.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

unsafe fn list_neighbors() -> io::Result<Vec<NeighEntry>> {
    // use NET_RT_FLAGS + RTF_LLINFO to filter llinfo（neighbor cache）
    // CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_FLAGS, RTF_LLINFO
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_UNSPEC,
        libc::NET_RT_FLAGS,
        libc::RTF_LLINFO,
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

    let mut out = Vec::new();
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

        let mut addrs: [*const libc::sockaddr; RTAX_MAX] = [ptr::null(); RTAX_MAX];
        let mut p = (buf.as_ptr().add(off) as *const u8).add(size_of::<libc::rt_msghdr2>());
        let addrs_mask = rtm.rtm_addrs as i32;

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

        let ip = parse_sockaddr_ip(addrs[RTAX_DST]);
        let lladdr = parse_lladdr(addrs[RTAX_GATEWAY]);
        let ifname = parse_ifname(addrs[RTAX_IFP]);

        out.push(NeighEntry {
            ip,
            lladdr,
            ifname,
            flags: rtm.rtm_flags,
        });

        off += msglen;
    }

    Ok(out)
}

#[derive(Debug, Clone)]
pub struct MacosNetNeigh {
    pub if_name: String,
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub state: i32, // flag
}

pub(crate) fn get_net_neighs() -> Result<Vec<MacosNetNeigh>, CrossNetError> {
    let neighs = unsafe { list_neighbors()? };
    let mut rets = Vec::new();
    for n in neighs {
        if let (Some(ip), Some(mac), Some(ifname)) = (n.ip, n.lladdr, n.ifname) {
            let mac = MacAddr::from_str(&mac)?;
            rets.push(MacosNetNeigh {
                if_name: ifname,
                ip,
                mac,
                state: n.flags,
            });
        }
    }
    Ok(rets)
}
