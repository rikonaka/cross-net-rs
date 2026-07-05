use regex::Regex;
use std::net::IpAddr;
use std::process::Command;

use crate::error::CrossNetError;
use crate::iface::NetFamily;
use crate::route::NetRoute;
use crate::route::NetRouteAddr;
use crate::route::NetType;

/// On MacOS or other Unix-like operating systems, we only return the default route.
/// Then search route through the command `route -n get <ip>`, and parse the output to get the route information.
pub(crate) fn get_net_routes() -> Result<Vec<NetRoute>, CrossNetError> {
    let output = Command::new("netstat").arg("-rn").output()?;
    let output_str = String::from_utf8_lossy(&output.stdout);
    let route_re =
        Regex::new(r"^default\s+(?P<via>[\w\d:.]+)(%[\w\d]+)?\s+\w+\s+(?P<dev>[\w\d]+)$")?;

    // FreeBSD15
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

    // MacOS
    // Routing tables
    // Internet:
    // Destination        Gateway            Flags               Netif Expire
    // default            192.168.0.1        UGScg                 en0
    // default            link#20            UCSIg           bridge100      !
    // default            link#22            UCSIg           bridge101      !
    // default            link#25            UCSIg           bridge102      !
    // 127                127.0.0.1          UCS                   lo0
    // 127.0.0.1          127.0.0.1          UH                    lo0
    // 169.254            link#12            UCS                   en0      !
    // 169.254.169.254    link#12            UHRLSW                en0      !
    // 172.16.86/24       link#25            UC              bridge102      !
    // 172.16.86.255      ff.ff.ff.ff.ff.ff  UHLWbI          bridge102      !
    // 192.168.0          link#12            UCS                   en0      !
    // 192.168.0.1/32     link#12            UCS                   en0      !
    // 192.168.0.1        f8:ce:21:39:5b:f4  UHLWIir               en0   1200
    // 192.168.0.102/32   link#12            UCS                   en0      !
    // 192.168.0.102      c0:c7:db:d1:df:c4  UHLWI                 lo0
    // 192.168.0.104      cc:4d:75:8d:a1:a5  UHLWI                 en0   1142
    // 192.168.0.107      22:bc:68:28:ee:50  UHLWI                 en0    889
    // 192.168.0.108      6c:16:29:0:fd:5b   UHLWI                 en0    629
    // 192.168.0.109      a6:f6:0:b1:b8:33   UHLWI                 en0    366
    // 192.168.0.110      a2:b2:7:72:7a:77   UHLWI                 en0   1147
    // 192.168.0.111      62:17:25:d2:6e:41  UHLWI                 en0    956
    // 192.168.0.112      6:69:3c:a5:6a:3e   UHLWI                 en0    614
    // 192.168.0.255      ff:ff:ff:ff:ff:ff  UHLWbI                en0      !
    // 192.168.5          link#22            UC              bridge101      !
    // 192.168.5.255      ff.ff.ff.ff.ff.ff  UHLWbI          bridge101      !
    // 192.168.62         link#20            UC              bridge100      !
    // 192.168.62.255     ff.ff.ff.ff.ff.ff  UHLWbI          bridge100      !
    // 224.0.0/4          link#12            UmCS                  en0      !
    // 224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0
    // 255.255.255.255/32 link#12            UCS                   en0      !
    //
    // Internet6:
    // Destination                             Gateway                                 Flags               Netif Expire
    // default                                 fe80::face:21ff:fe39:5bf4%en0           UGcg                  en0
    // default                                 fe80::%utun0                            UGcIg               utun0
    // default                                 fe80::%utun1                            UGcIg               utun1
    // default                                 fe80::%utun2                            UGcIg               utun2
    // default                                 fe80::%utun3                            UGcIg               utun3
    // ::1                                     ::1                                     UHL                   lo0
    // 2409:8a6c:1767:f351::/64                link#12                                 UC                    en0
    // 2409:8a6c:1767:f351::1001               c0:c7:db:d1:df:c4                       UHL                   lo0
    // 2409:8a6c:1767:f351:1829:e562:959:2001  c0:c7:db:d1:df:c4                       UHL                   lo0
    // 2409:8a6c:1767:f351:a092:4f97:206c:1050 c0:c7:db:d1:df:c4                       UHL                   lo0
    // fe80::%lo0/64                           fe80::1%lo0                             UcI                   lo0
    // fe80::1%lo0                             link#1                                  UHLI                  lo0
    // fe80::%en0/64                           link#12                                 UCI                   en0
    // fe80::3f:139d:b5af:ae9%en0              c0:c7:db:d1:df:c4                       UHLI                  lo0
    // fe80::10f4:1ef8:8564:4851%en0           22:bc:68:28:ee:50                       UHLWIi                en0
    // fe80::face:21ff:fe39:5bf4%en0           f8:ce:21:39:5b:f4                       UHLWIir               en0
    // fe80::6059:3eff:fea6:4358%awdl0         62:59:3e:a6:43:58                       UHLI                  lo0
    // fe80::6059:3eff:fea6:4358%llw0          62:59:3e:a6:43:58                       UHLI                  lo0
    // fe80::%utun0/64                         fe80::b7ab:d6d3:e79b:e2f6%utun0         UcI                 utun0
    // fe80::b7ab:d6d3:e79b:e2f6%utun0         link#15                                 UHLI                  lo0
    // fe80::%utun1/64                         fe80::4f52:5f66:598c:54cd%utun1         UcI                 utun1
    // fe80::4f52:5f66:598c:54cd%utun1         link#16                                 UHLI                  lo0
    // fe80::%utun2/64                         fe80::8491:b1ee:71fe:2118%utun2         UcI                 utun2
    // fe80::8491:b1ee:71fe:2118%utun2         link#17                                 UHLI                  lo0
    // fe80::%utun3/64                         fe80::ce81:b1c:bd2c:69e%utun3           UcI                 utun3
    // fe80::ce81:b1c:bd2c:69e%utun3           link#18                                 UHLI                  lo0
    // fe80::%bridge100/64                     link#20                                 UCI             bridge100
    // fe80::c0c7:dbff:fe1d:3964%bridge100     c2.c7.db.1d.39.64                       UHLI                  lo0
    // fe80::%bridge101/64                     link#22                                 UCI             bridge101
    // fe80::c0c7:dbff:fe1d:3965%bridge101     c2.c7.db.1d.39.65                       UHLI                  lo0
    // fe80::%bridge102/64                     link#25                                 UCI             bridge102
    // fe80::c0c7:dbff:fe1d:3966%bridge102     c2.c7.db.1d.39.66                       UHLI                  lo0
    // ff00::/8                                ::1                                     UmCI                  lo0
    // ff00::/8                                link#12                                 UmCI                  en0
    // ff00::/8                                link#13                                 UmCI                awdl0
    // ff00::/8                                link#14                                 UmCI                 llw0
    // ff00::/8                                fe80::b7ab:d6d3:e79b:e2f6%utun0         UmCI                utun0
    // ff00::/8                                fe80::4f52:5f66:598c:54cd%utun1         UmCI                utun1
    // ff00::/8                                fe80::8491:b1ee:71fe:2118%utun2         UmCI                utun2
    // ff00::/8                                fe80::ce81:b1c:bd2c:69e%utun3           UmCI                utun3
    // ff00::/8                                link#20                                 UmCI            bridge100
    // ff00::/8                                link#22                                 UmCI            bridge101
    // ff00::/8                                link#25                                 UmCI            bridge102
    // ff01::%lo0/32                           ::1                                     UmCI                  lo0
    // ff01::%en0/32                           link#12                                 UmCI                  en0
    // ff01::%utun0/32                         fe80::b7ab:d6d3:e79b:e2f6%utun0         UmCI                utun0
    // ff01::%utun1/32                         fe80::4f52:5f66:598c:54cd%utun1         UmCI                utun1
    // ff01::%utun2/32                         fe80::8491:b1ee:71fe:2118%utun2         UmCI                utun2
    // ff01::%utun3/32                         fe80::ce81:b1c:bd2c:69e%utun3           UmCI                utun3
    // ff01::%bridge100/32                     link#20                                 UmCI            bridge100
    // ff01::%bridge101/32                     link#22                                 UmCI            bridge101
    // ff01::%bridge102/32                     link#25                                 UmCI            bridge102
    // ff02::%lo0/32                           ::1                                     UmCI                  lo0
    // ff02::%en0/32                           link#12                                 UmCI                  en0
    // ff02::%utun0/32                         fe80::b7ab:d6d3:e79b:e2f6%utun0         UmCI                utun0
    // ff02::%utun1/32                         fe80::4f52:5f66:598c:54cd%utun1         UmCI                utun1
    // ff02::%utun2/32                         fe80::8491:b1ee:71fe:2118%utun2         UmCI                utun2
    // ff02::%utun3/32                         fe80::ce81:b1c:bd2c:69e%utun3           UmCI                utun3
    // ff02::%bridge100/32                     link#20                                 UmCI            bridge100
    // ff02::%bridge101/32                     link#22                                 UmCI            bridge101
    // ff02::%bridge102/32                     link#25                                 UmCI            bridge102

    let mut rets = Vec::new();
    for line in output_str.lines() {
        let line = line.trim();
        if let Some(caps) = route_re.captures(line) {
            let (via, family) = match caps.name("via") {
                Some(via_str) => {
                    let via_str = via_str.as_str();
                    let family = if via_str.contains(":") {
                        NetFamily::Ipv6
                    } else {
                        NetFamily::Ipv4
                    };
                    let via: IpAddr = via_str.parse()?;
                    (Some(NetRouteAddr::IpAddr(via)), family)
                }
                None => (None, NetFamily::Ipv4),
            };
            let dev = match caps.name("dev") {
                Some(dev_str) => {
                    let dev_str = dev_str.as_str();
                    Some(dev_str.to_string())
                }
                None => None,
            };

            let route = NetRoute {
                dst: None,
                src: None,
                gateway: via,
                ntype: NetType::Default,
                family,
                if_name: dev,
            };
            rets.push(route);
        } else if line.contains("default") {
            #[cfg(feature = "debug")]
            eprintln!("no match for line: [{}]", line);
        }
    }

    Ok(rets)
}

pub(crate) struct SearchRouteRet {
    pub interface: Option<String>,
    pub gateway: Option<IpAddr>,
}

pub(crate) fn search_route(ip: IpAddr) -> Result<SearchRouteRet, CrossNetError> {
    let output = Command::new("route")
        .arg("-n")
        .arg("get")
        .arg(ip.to_string())
        .output()?;
    let output_str = String::from_utf8_lossy(&output.stdout);

    //    route to: 192.168.5.3
    // destination: 192.168.5.0
    //        mask: 255.255.255.0
    //   interface: bridge101
    //       flags: <UP,DONE,CLONING>
    //  recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
    //        0         0         0         0         0         0      1500     -9968

    //    route to: 1.1.1.1
    // destination: default
    //        mask: default
    //     gateway: 192.168.0.1
    //   interface: en0
    //       flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
    //  recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
    //        0         0         0         0         0         0      1500         0

    let mut interface: Option<String> = None;
    let mut gateway: Option<IpAddr> = None;

    for line in output_str.lines() {
        let line = line.trim();
        if line.starts_with("interface:") {
            let parts: Vec<&str> = line.split(":").collect();
            if parts.len() >= 2 {
                let interface_str = parts[1].trim().to_string();
                interface = Some(interface_str);
            }
        }
        if line.starts_with("gateway:") {
            let parts: Vec<&str> = line.split(":").collect();
            if parts.len() >= 2 {
                let gateway_str = parts[1].trim();
                if gateway_str.len() > 0 {
                    let gateway_ip: IpAddr = gateway_str.parse()?;
                    gateway = Some(gateway_ip);
                }
            }
        }
    }

    let ret = SearchRouteRet { interface, gateway };
    Ok(ret)
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_unix() {
        let rets = get_net_routes().unwrap();
        for ret in rets {
            if let Some(gateway) = ret.gateway {
                if let Some(if_name) = &ret.if_name {
                    println!("gateway: {}, if_name: {}", gateway, if_name);
                }
            }
        }
    }
}
