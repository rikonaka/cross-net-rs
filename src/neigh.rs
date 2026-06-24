use regex::Regex;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

use crate::error::CrossNetError;
use crate::iface::MacAddr;

pub(crate) enum MacState {
    REACHABLE,
    STALE,
    DELAY,
    PROBE,
    INCOMPLETE,
    FAILED,
}

pub(crate) struct MacInfo {
    mac: MacAddr,
    /// The interface name associated with the MAC address, if available.
    iface: Option<String>,
    state: MacState,
}

#[derive(Debug, Clone)]
struct SystemNeighborInner {
    ipv4_output: String,
    re4: Regex,
    ipv6_output: String,
    re6: Regex,
}

impl SystemNeighborInner {
    #[cfg(target_os = "linux")]
    fn get() -> Result<SystemNeighborInner, CrossNetError> {
        let normal_re = Regex::new(
            r"^(?P<ip>[0-9a-fA-F:.]+)\s+(dev\s+(?P<dev>[\w\d]+)\s+)?(lladdr\s+(?P<mac>[0-9a-fA-F:]+)\s+)?(?P<state>\S+)",
        )?;

        // 192.168.5.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE
        // 192.168.5.2 dev ens33 lladdr 00:50:56:f7:49:0d REACHABLE
        // 192.168.5.78 dev ens33 lladdr 00:0c:29:cf:62:2f STALE
        let output = Command::new("ip").arg("-4").arg("neighbor").output()?;
        let ipv4_output = String::from_utf8_lossy(&output.stdout).to_string();

        // fe80::c395:cac0:2c61:5161 dev ens33 INCOMPLETE
        // fe80::c395:cac0:2c61:5162 dev ens33 lladdr 00:0c:29:cf:62:39 REACHABLE
        let output = Command::new("ip").arg("-6").arg("neighbor").output()?;
        let ipv6_output = String::from_utf8_lossy(&output.stdout).to_string();
        // ignore INCOMPLETE entries

        let sni = SystemNeighborInner {
            ipv4_output,
            re4: normal_re.clone(),
            ipv6_output,
            re6: normal_re,
        };
        Ok(sni)
    }
    #[cfg(target_os = "windows")]
    fn get() -> Result<SystemNeighborInner, CrossNetError> {
        /*
        ifIndex IPAddress                                          LinkLayerAddress      State       PolicyStore
        ------- ---------                                          ----------------      -----       -----------
        18      ff02::1:ffb1:8476                                  33-33-FF-B1-84-76     Permanent   ActiveStore
        18      ff02::1:ff3c:f747                                  33-33-FF-3C-F7-47     Permanent   ActiveStore
        18      ff02::1:3                                          33-33-00-01-00-03     Permanent   ActiveStore
        18      ff02::1:2                                          33-33-00-01-00-02     Permanent   ActiveStore
        18      ff02::fb                                           33-33-00-00-00-FB     Permanent   ActiveStore
        18      ff02::16                                           33-33-00-00-00-16     Permanent   ActiveStore
        18      ff02::c                                            33-33-00-00-00-0C     Permanent   ActiveStore
        18      ff02::2                                            33-33-00-00-00-02     Permanent   ActiveStore
        18      ff02::1                                            33-33-00-00-00-01     Permanent   ActiveStore
        18      fe80::f187:4754:cd47:3b24                          00-00-00-00-00-00     Unreachable ActiveStore
        18      fe80::e1a8:a4dd:240a:757f                          00-00-00-00-00-00     Unreachable ActiveStore
        18      fe80::de4a:3eff:feb1:8476                          00-00-00-00-00-00     Unreachable ActiveStore
        21      ff02::1:ff1d:7337                                  33-33-FF-1D-73-37     Permanent   ActiveStore
        18      239.255.255.250                                    01-00-5E-7F-FF-FA     Permanent   ActiveStore
        18      192.168.5.255                                      FF-FF-FF-FF-FF-FF     Permanent   ActiveStore
        18      192.168.5.1                                        00-00-00-00-00-00     Unreachable ActiveStore
        19      10.100.45.34                                       70-B5-E8-2B-E7-02     Stale       ActiveStore
        19      10.100.45.1                                        00-00-00-00-00-00     Unreachable ActiveStore
        1       239.255.255.253                                                          Permanent   ActiveStore
        */

        let normal_re = Regex::new(
            r"^(?P<ind>\d+)\s+(?P<ip>[0-9a-fA-F:.]+)\s+((?P<mac>[0-9a-fA-F-]+)\s+)?(?P<state>\w+).+",
        )?;

        let output = Command::new("powershell.exe")
            .arg("Get-NetNeighbor")
            .output()?;
        let ipv4_output = String::from_utf8_lossy(&output.stdout).to_string();

        let sni = SystemNeighborInner {
            ipv4_output,
            re4: normal_re.clone(),
            // The all output is stored in ipv4_output,
            // so we can just use the same regex for ipv6_output,
            // this is in order to call Get-NetNeighbor only once,
            // which is faster than calling it twice for ipv4 and ipv6 separately.
            ipv6_output: String::new(),
            re6: normal_re,
        };
        Ok(sni)
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "macos"
    ))]
    fn get() -> Result<SystemNeighborInner, CrossNetError> {
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
        let output = Command::new("arp").arg("-an").output()?;
        let ipv4_output = String::from_utf8_lossy(&output.stdout).to_string();
        // ignore incomplete entries
        let arp_re = Regex::new(
            r"^\?\s+\((?P<ip>[0-9.]+)\)\s+at\s+((?P<mac>[0-9a-fA-F:]+)|\((?P<type>\w+)\))\s+on\s+(?P<dev>\S+)\s+\w+\s+(?P<state>\S+).+",
        )?;

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
        let output = Command::new("ndp").arg("-an").output()?;
        let ipv6_output = String::from_utf8_lossy(&output.stdout).to_string();
        let ndp_re = Regex::new(
            r"^(?P<ip>[0-9a-fA-F:]+)(%(?P<dev>[\w\d]+))?\s+((?P<mac>[0-9a-fA-F:]+)|\((?P<type>\w+)\))\s+(?P<dev2>[\w\d]+)\s+(?P<state>\w+).+",
        )?;

        let sni = SystemNeighborInner {
            ipv4_output,
            re4: arp_re,
            ipv6_output,
            re6: ndp_re,
        };
        Ok(sni)
    }
}

pub struct NeighborCache(HashMap<IpAddr, MacInfo>);

impl fmt::Display for NeighborCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (ip, mac_info) in &self.0 {
            let iface_str = match &mac_info.iface {
                Some(iface) => iface.clone(),
                None => "N/A".to_string(),
            };
            write!(f, "{}: {}({})", ip, mac_info.mac.to_string(), iface_str,)?;
        }
        Ok(())
    }
}

pub fn get_neighbor_cache() -> Result<HashMap<IpAddr, MacAddr>, CrossNetError> {
    let mut neighbor_cache = HashMap::new();
    let sni = SystemNeighborInner::get()?;

    // parse ipv4 neighbor cache
    for line in sni.ipv4_output.lines() {
        if let Some(caps) = sni.re4.captures(line) {
            if let Some(ip_str) = caps.name("ip") {
                let ip_str = ip_str.as_str();
                let ip = match IpAddr::from_str(ip_str) {
                    Ok(ip) => ip,
                    Err(e) => {
                        eprintln!(
                            "failed to parse ip address: [{}], line: [{}] error: {}",
                            ip_str, line, e
                        );
                        panic!("XXX");
                        // continue;
                    }
                };
                if let Some(mac_str) = caps.name("mac") {
                    let mac_str = &mac_str.as_str().replace("-", ":");
                    match MacAddr::from_str(mac_str) {
                        Ok(m) => {
                            neighbor_cache.insert(ip, m);
                        }
                        Err(_e) => {
                            return Err(CrossNetError::ParseMacAddrErr {
                                mac: mac_str.to_string(),
                            });
                        }
                    }
                }
            }
        } else {
            #[cfg(feature = "debug")]
            eprintln!("line does not match arp regex:\n[{}]", line);
        }
    }

    // parse ipv6 neighbor cache
    for line in sni.ipv6_output.lines() {
        if let Some(caps) = sni.re6.captures(line) {
            if let Some(ip_str) = caps.name("ip") {
                let ip_str = ip_str.as_str();
                let ip = match IpAddr::from_str(ip_str) {
                    Ok(ip) => ip,
                    Err(e) => {
                        eprintln!(
                            "failed to parse ip address: [{}], line: [{}] error: {}",
                            ip_str, line, e
                        );
                        panic!("YYY");
                        // continue;
                    }
                };
                if let Some(mac_str) = caps.name("mac") {
                    let mac_str = &mac_str.as_str().replace("-", ":");
                    match MacAddr::from_str(mac_str) {
                        Ok(m) => {
                            neighbor_cache.insert(ip, m);
                        }
                        Err(_e) => {
                            return Err(CrossNetError::ParseMacAddrErr {
                                mac: mac_str.to_string(),
                            });
                        }
                    }
                }
            }
        } else {
            #[cfg(feature = "debug")]
            eprintln!("line does not match ndp regex:\n[{}]", line);
        }
    }

    Ok(neighbor_cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_neighbor_cache() {
        let neighbor_cache = get_neighbor_cache().unwrap();
        println!("Neighbor cache: {:?}", neighbor_cache);
    }
}
