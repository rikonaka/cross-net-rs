use regex::Regex;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::process::Command;

use crate::error::CrossNetError;
use crate::iface::MacAddr;
use crate::neigh::NetIf;

#[derive(Debug, Clone)]
struct UnixNetNeigh {
    pub ifx: String,
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub state: String,
}

fn get() -> Result<UnixNetNeigh, CrossNetError> {
    let ipv4_output = Command::new("arp").arg("-an").output()?;
    let ipv4_output_str = String::from_utf8_lossy(&ipv4_output.stdout);
    // ignore incomplete entries
    let arp_re = Regex::new(
        r"^\?\s+\((?P<ip>\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})\)\s+at\s+(?P<mac>[0-9a-fA-F:]+)\s+on\s+\S+\s+\S+\s+\S+\s+\[\S+\]",
    )?;
    // ? (169.254.169.254) at (incomplete) on en0 [ethernet]
    // ? (172.16.86.1) at c2:c7:db:1d:39:66 on bridge102 ifscope permanent [bridge]
    // ? (172.16.86.255) at ff:ff:ff:ff:ff:ff on bridge102 ifscope [bridge]
    // ? (192.168.0.1) at f8:ce:21:39:5b:f4 on en0 ifscope [ethernet]
    // ? (192.168.0.102) at cc:4d:75:8d:a1:a5 on en0 ifscope [ethernet]
    // ? (192.168.0.105) at de:cb:f1:62:24:68 on en0 ifscope permanent [ethernet]
    // ? (192.168.0.108) at 6:69:3c:a5:6a:3e on en0 ifscope [ethernet]
    // ? (192.168.0.109) at f4:28:9d:1b:f2:95 on en0 ifscope [ethernet]
    // ? (192.168.0.110) at 42:6c:f:e9:a8:65 on en0 ifscope [ethernet]
    // ? (192.168.0.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
    // ? (192.168.5.1) at c2:c7:db:1d:39:65 on bridge101 ifscope permanent [bridge]
    // ? (192.168.5.78) at 0:c:29:65:2d:9b on bridge101 ifscope [bridge]
    // ? (192.168.5.255) at ff:ff:ff:ff:ff:ff on bridge101 ifscope [bridge]
    // ? (192.168.62.1) at c2:c7:db:1d:39:64 on bridge100 ifscope permanent [bridge]
    // ? (192.168.62.255) at ff:ff:ff:ff:ff:ff on bridge100 ifscope [bridge]
    // ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
    // ? (232.215.218.197) at 1:0:5e:57:da:c5 on en0 ifscope permanent [ethernet]

    let ipv6_output = Command::new("ndp").arg("-an").output()?;
    let ipv6_output_str = String::from_utf8_lossy(&ipv6_output.stdout);

    let ndp_re =
        Regex::new(r"^(?P<ip>[0-9\w:%]+)\s+(?P<mac>[0-9a-fA-F:]+)\s+\S+\s+\S+\s+\w(\s+\w)?")?;
    // Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs
    // 2409:8a6c:1763:4351::1000               de:cb:f1:62:24:68    en0 permanent R
    // 2409:8a6c:1763:4351:da:8c8b:e171:9e55   de:cb:f1:62:24:68    en0 permanent R
    // 2409:8a6c:1763:4351:8001:1205:abef:f5f8 de:cb:f1:62:24:68    en0 permanent R
    // fe80::1%lo0                             (incomplete)         lo0 permanent R
    // fe80::1234:5678:abcd:ef01%en0           (incomplete)         en0 expired   N
    // fe80::1807:d761:578a:6885%en0           42:6c:f:e9:a8:65     en0 21h58m44s S
    // fe80::1c53:4e36:7c1a:e431%en0           de:cb:f1:62:24:68    en0 permanent R
    // fe80::6e16:29ff:fe00:fd5b%en0           6c:16:29:0:fd:5b     en0 21h46m41s S
    // fe80::ae49:4251:a476:1253%en0           (incomplete)         en0 expired   N
    // fe80::ce81:b1c:bd2c:69e%en0             (incomplete)         en0 expired   N
    // fe80::face:21ff:fe39:5bf4%en0           f8:ce:21:39:5b:f4    en0 5s        R  R
    // fe80::849f:6fff:fecf:28ff%awdl0         86:9f:6f:cf:28:ff  awdl0 permanent R
    // fe80::849f:6fff:fecf:28ff%llw0          86:9f:6f:cf:28:ff   llw0 permanent R
    // fe80::f693:9983:bc6c:485b%utun0         (incomplete)       utun0 permanent R
    // fe80::799c:5339:de85:ff18%utun1         (incomplete)       utun1 permanent R
    // fe80::6c04:b35b:22df:351e%utun2         (incomplete)       utun2 permanent R
    // fe80::ce81:b1c:bd2c:69e%utun3           (incomplete)       utun3 permanent R
    // fe80::c0c7:dbff:fe1d:3964%bridge100     c2:c7:db:1d:39:64 bridge100 permanent R
    // fe80::c0c7:dbff:fe1d:3965%bridge101     c2:c7:db:1d:39:65 bridge101 permanent R
    // fe80::c0c7:dbff:fe1d:3966%bridge102     c2:c7:db:1d:39:66 bridge102 permanent R

    let sn = SystemNeighborInner {
        ipv4: ipv4_output_str.to_string(),
        re4: arp_re,
        ipv6: ipv6_output_str.to_string(),
        re6: ndp_re,
    };
    Ok(sn)
}
