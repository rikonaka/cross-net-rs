use regex::Regex;
use std::process::Command;
use subnetwork::IpPool;

use crate::error::CrossNetError;
use crate::route::NetRoute;
use crate::route::NetRouteAddr;

pub fn get_net_routes() -> Result<Vec<NetRoute>, CrossNetError> {
    let output = Command::new("netstat").arg("-rn").output()?;
    let output_str = String::from_utf8_lossy(&output.stdout);
    let route_re = Regex::new(
        r"^(?P<dst>[\w\d:.]+)(%(?P<dev1>[\w\d]+))?(\/(?P<prefix>\d+))?\s+(?P<via>[\w\d#.]+)\s+\w+\s+(?P<dev2>[\w\d]+)$",
    )?;

    // Routing tables
    // Internet:
    // Destination        Gateway            Flags         Netif Expire
    // default            192.168.5.2        UGS             em0
    // 127.0.0.1          link#2             UH              lo0
    // 192.168.5.0/24     link#1             U               em0
    // 192.168.5.4        link#2             UHS             lo0
    //
    // Internet6:
    // Destination                       Gateway                       Flags         Netif Expire
    // ::/96                             link#2                        URS             lo0
    // ::1                               link#2                        UHS             lo0
    // ::ffff:0.0.0.0/96                 link#2                        URS             lo0
    // fe80::%lo0/10                     link#2                        URS             lo0
    // fe80::%em0/64                     link#1                        U               em0
    // fe80::20c:29ff:fef9:c591%lo0      link#2                        UHS             lo0
    // fe80::%lo0/64                     link#2                        U               lo0
    // fe80::1%lo0                       link#2                        UHS             lo0
    // ff02::/16                         link#2                        URS             lo0

    for line in output_str.lines() {
        let line = line.trim();
        if let Some(caps) = route_re.captures(line) {
            let dst = match caps.name("dst") {
                Some(dst_str) => {
                    let dst_str = dst_str.as_str();
                    Some(dst_str.to_string())
                }
                None => None,
            };
            let dev1 = match caps.name("dev1") {
                Some(dev1_str) => {
                    let dev1_str = dev1_str.as_str();
                    Some(dev1_str.to_string())
                }
                None => None,
            };
            let prefix = match caps.name("prefix") {
                Some(prefix_str) => {
                    let prefix_str = prefix_str.as_str();
                    let prefix: u8 = prefix_str.parse()?;
                    Some(prefix)
                }
                None => None,
            };
            let via = match caps.name("via") {
                Some(via_str) => {
                    let via_str = via_str.as_str();
                    Some(via_str.to_string())
                }
                None => None,
            };
            let dev2 = match caps.name("dev2") {
                Some(dev2_str) => {
                    let dev2_str = dev2_str.as_str();
                    Some(dev2_str.to_string())
                }
                None => None,
            };

            if let Some(dst) = dst {
                let via_addr = if let Some(via) = via {
                    if via == "link#" {
                        None
                    } else {
                        let via_addr: IpPool = via.parse()?;
                        Some(via_addr)
                    }
                } else {
                    None
                };

                let route = NetRoute::new(dst, via_addr, dev1, dev2, prefix);
                return Ok(vec![route]);
            }

            #[cfg(feature = "debug")]
            eprintln!(
                "dst: {:?}, via: {:?}, dev1: {:?}, dev2: {:?}, prefix: {:?}",
                dst, via, dev1, dev2, prefix
            );
        }
    }

    let rets = Vec::new();
    return Ok(rets);
}
