use libc::c_int;
use libc::c_void;
use std::io;
use std::mem::size_of;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
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
// const RTAX_NETMASK: usize = 2;
// const RTAX_GENMASK: usize = 3;
const RTAX_IFP: usize = 4;
// const RTAX_IFA: usize = 5;
// const RTAX_AUTHOR: usize = 6;
// const RTAX_BRD: usize = 7;
const RTAX_MAX: usize = 8;

#[inline]
fn roundup_sa(len: usize) -> usize {
    // macOS / BSD kernel enforces 4‑byte alignment (sizeof(uint32_t))
    if len == 0 {
        4 // When sa_len is zero, occupies 4 bytes
    } else {
        (len + 3) & !3 // Round up to next multiple of 4
    }
}

fn parse_sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    let fam = unsafe { (*sa).sa_family as c_int };
    match fam {
        libc::AF_INET => {
            let sin = sa as *const libc::sockaddr_in;
            Some(IpAddr::V4(Ipv4Addr::from(unsafe {
                (*sin).sin_addr.s_addr.to_le_bytes()
            })))
        }
        libc::AF_INET6 => {
            let sin6 = sa as *const libc::sockaddr_in6;
            let x = unsafe { (*sin6).sin6_addr.s6_addr };
            Some(IpAddr::V6(Ipv6Addr::from(x)))
        }
        _ => None,
    }
}

fn parse_ifname(sa: *const libc::sockaddr) -> Option<String> {
    if sa.is_null() || unsafe { (*sa).sa_family as c_int } != libc::AF_LINK {
        return None;
    }
    let sdl = sa as *const libc::sockaddr_dl;
    let nlen = unsafe { (*sdl).sdl_nlen as usize };
    if nlen == 0 {
        return None;
    }
    let name_ptr = unsafe { (*sdl).sdl_data.as_ptr() as *const u8 };
    let name = unsafe { std::slice::from_raw_parts(name_ptr, nlen) };
    Some(String::from_utf8_lossy(name).to_string())
}

fn parse_lladdr(sa: *const libc::sockaddr) -> Option<String> {
    if sa.is_null() || unsafe { (*sa).sa_family as c_int } != libc::AF_LINK {
        return None;
    }
    let sdl = sa as *const libc::sockaddr_dl;

    let nlen = unsafe { (*sdl).sdl_nlen as usize };
    let alen = unsafe { (*sdl).sdl_alen as usize };
    if alen == 0 {
        return None;
    }

    let base = unsafe { (*sdl).sdl_data.as_ptr() as *const u8 };
    let mac_ptr = unsafe { base.add(nlen) };
    let mac = unsafe { std::slice::from_raw_parts(mac_ptr, alen) };

    Some(
        mac.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn list_neighbors() -> io::Result<Vec<NeighEntry>> {
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
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            ptr::null_mut(),
            &mut needed,
            ptr::null_mut(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut buf = vec![0u8; needed];
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            buf.as_mut_ptr() as *mut c_void,
            &mut needed,
            ptr::null_mut(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    buf.truncate(needed);

    let mut out = Vec::new();
    let mut off = 0usize;

    while off + size_of::<libc::rt_msghdr>() <= buf.len() {
        let rtm = unsafe { &*(buf.as_ptr().add(off) as *const libc::rt_msghdr) };
        let msglen = rtm.rtm_msglen as usize;
        if msglen == 0 || off + msglen > buf.len() {
            break;
        }
        if rtm.rtm_version != libc::RTM_VERSION as u8 {
            off += msglen;
            continue;
        }

        let mut addrs: [*const libc::sockaddr; RTAX_MAX] = [ptr::null(); RTAX_MAX];
        let mut p =
            unsafe { (buf.as_ptr().add(off) as *const u8).add(size_of::<libc::rt_msghdr>()) };
        let addrs_mask = rtm.rtm_addrs as i32;

        for i in 0..RTAX_MAX {
            if (addrs_mask & (1 << i)) != 0 {
                let sa = p as *const libc::sockaddr;
                addrs[i] = sa;

                let sa_len = unsafe { (*sa).sa_len as usize };
                p = unsafe { p.add(roundup_sa(sa_len)) };
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
    // println!("list_neighbors: {:?}", out);

    Ok(out)
}

#[derive(Debug, Clone)]
pub struct MacosNetNeigh {
    pub ifname: Option<String>,
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub state: i32, // flag
}

pub(crate) fn get_net_neighs() -> Result<Vec<MacosNetNeigh>, CrossNetError> {
    let neighs = list_neighbors()?;
    let mut rets = Vec::new();
    for n in neighs {
        if let (Some(ip), Some(mac)) = (n.ip, n.lladdr) {
            let mac = MacAddr::from_str(&mac)?;
            rets.push(MacosNetNeigh {
                ifname: n.ifname,
                ip,
                mac,
                state: n.flags,
            });
        }
    }
    Ok(rets)
}

#[cfg(target_os = "macos")]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_macos() {
        let rets = get_net_neighs().unwrap();
        for ret in rets {
            println!("ip: {}, mac: {}", ret.ip.to_string(), ret.mac.to_string());
        }
    }
}
