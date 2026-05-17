use ipnetwork::IpNetwork;
use log::warn;
use nat_common::{DnsConfig, IpVersion};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::ops::Add;

pub fn remote_ip_with_dns(
    domain: &str,
    ip_version: &IpVersion,
    dns_config: &DnsConfig,
) -> io::Result<String> {
    remote_ip_with_resolver(domain, ip_version, dns_config, system_resolve)
}

fn remote_ip_with_resolver<F>(
    domain: &str,
    ip_version: &IpVersion,
    dns_config: &DnsConfig,
    resolver: F,
) -> io::Result<String>
where
    F: Fn(&str) -> io::Result<Vec<IpAddr>>,
{
    // 首先尝试直接解析为IP地址
    if let Ok(ip) = domain.parse::<IpAddr>() {
        reject_fake_ip_if_needed(domain, ip, dns_config)?;
        return match ip_version {
            IpVersion::V4 => {
                if ip.is_ipv4() {
                    Ok(ip.to_string())
                } else {
                    Err(io::Error::other(
                        "Domain resolved to IPv6 but IPv4 was requested",
                    ))
                }
            }
            IpVersion::V6 => {
                if ip.is_ipv6() {
                    Ok(ip.to_string())
                } else {
                    Err(io::Error::other(
                        "Domain resolved to IPv4 but IPv6 was requested",
                    ))
                }
            }
            IpVersion::All => Ok(ip.to_string()),
        };
    }

    // 如果不是IP地址，则进行DNS解析
    if dns_config.resolver_mode != "system" {
        warn!(
            "dns resolver_mode={} is not implemented yet, fallback to system resolver",
            dns_config.resolver_mode
        );
    }
    let resolved = resolver(domain)?;
    let candidates: Vec<IpAddr> = resolved
        .into_iter()
        .filter(|ip| match ip_version {
            IpVersion::V4 => ip.is_ipv4(),
            IpVersion::V6 => ip.is_ipv6(),
            IpVersion::All => true,
        })
        .collect();

    let mut saw_fake_ip = None;
    let selected = match ip_version {
        IpVersion::V4 => candidates.iter().find(|ip| ip.is_ipv4()).copied(),
        IpVersion::V6 => candidates.iter().find(|ip| ip.is_ipv6()).copied(),
        IpVersion::All => {
            // 优先IPv4，如果没有IPv4则使用IPv6
            candidates
                .iter()
                .find(|ip| ip.is_ipv4())
                .or_else(|| candidates.iter().find(|ip| ip.is_ipv6()))
                .copied()
        }
    };

    for ip in &candidates {
        if is_fake_ip(*ip, dns_config) {
            saw_fake_ip = Some(*ip);
            if dns_config.reject_fake_ip {
                warn!("resolved fake-ip {ip} for domain {domain}, reject it");
                return Err(io::Error::other(format!(
                    "resolved fake-ip {ip} for domain {domain}, reject it"
                )));
            }
            warn!("resolved fake-ip {ip} for domain {domain}, reject_fake_ip=false, allow it");
        }
    }

    let Some(ip) = selected else {
        return match ip_version {
            IpVersion::V4 => Err(io::Error::other("Failed to resolve IPv4 address")),
            IpVersion::V6 => Err(io::Error::other("Failed to resolve IPv6 address")),
            IpVersion::All => Err(io::Error::other("Failed to resolve any IP address")),
        };
    };
    if saw_fake_ip == Some(ip) || is_fake_ip(ip, dns_config) {
        if dns_config.reject_fake_ip {
            warn!("resolved fake-ip {ip} for domain {domain}, reject it");
            return Err(io::Error::other(format!(
                "resolved fake-ip {ip} for domain {domain}, reject it"
            )));
        }
        warn!("resolved fake-ip {ip} for domain {domain}, reject_fake_ip=false, allow it");
    }
    Ok(ip.to_string())
}

fn system_resolve(domain: &str) -> io::Result<Vec<IpAddr>> {
    let socket_addrs: Vec<SocketAddr> = domain.to_string().add(":80").to_socket_addrs()?.collect();
    Ok(socket_addrs.into_iter().map(|addr| addr.ip()).collect())
}

fn reject_fake_ip_if_needed(domain: &str, ip: IpAddr, dns_config: &DnsConfig) -> io::Result<()> {
    if is_fake_ip(ip, dns_config) {
        if dns_config.reject_fake_ip {
            warn!("resolved fake-ip {ip} for domain {domain}, reject it");
            return Err(io::Error::other(format!(
                "resolved fake-ip {ip} for domain {domain}, reject it"
            )));
        }
        warn!("resolved fake-ip {ip} for domain {domain}, reject_fake_ip=false, allow it");
    }
    Ok(())
}

pub fn is_fake_ip(ip: IpAddr, dns_config: &DnsConfig) -> bool {
    dns_config
        .fake_ip_cidrs
        .iter()
        .filter_map(|cidr| cidr.parse::<IpNetwork>().ok())
        .any(|network| network.contains(ip))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use nat_common::{DnsConfig, IpVersion};
    use std::net::{IpAddr, Ipv4Addr};

    // #[test]
    // fn test_default_src_ip() {
    //     use std::net::Ipv4Addr;
    //     let ip = super::default_src_ip().unwrap();
    //     println!("Default source IP: {}", ip);
    //     assert!(!ip.is_empty());
    //     assert!(ip.parse::<Ipv4Addr>().is_ok());
    // }
    #[test]
    fn test_remote_ip_v4() {
        use std::net::Ipv4Addr;
        let domain = "203.0.113.10".to_string();
        let ip = super::remote_ip_with_dns(&domain, &IpVersion::V4, &DnsConfig::default()).unwrap();
        println!("Resolved IPv4 for {domain}: {ip}");
        assert!(!ip.is_empty());
        assert!(ip.parse::<Ipv4Addr>().is_ok());
    }

    #[test]
    fn test_remote_ip_both() {
        let domain = "203.0.113.10".to_string();
        let ip =
            super::remote_ip_with_dns(&domain, &IpVersion::All, &DnsConfig::default()).unwrap();
        println!("Resolved IP (Both mode) for {domain}: {ip}");
        assert!(!ip.is_empty());
        // Should resolve to either IPv4 or IPv6, but prefer IPv4
        assert!(ip.parse::<std::net::IpAddr>().is_ok());
    }

    #[test]
    fn test_resolve_localhost() {
        let domain = "localhost".to_string();
        let ip =
            super::remote_ip_with_dns(&domain, &IpVersion::All, &DnsConfig::default()).unwrap();
        println!("Resolved IP (Both mode) for {domain}: {ip}");
        assert!(!ip.is_empty());
        // Should resolve to either IPv4 or IPv6, but prefer IPv4
        assert!(ip.parse::<std::net::IpAddr>().is_ok());

        let ip = super::remote_ip_with_dns(&domain, &IpVersion::V6, &DnsConfig::default()).unwrap();
        println!("Resolved IP (V6) for {domain}: {ip}");
        assert!(!ip.is_empty());
        // Should resolve to either IPv4 or IPv6, but prefer IPv4
        assert!(ip.parse::<std::net::IpAddr>().is_ok());
    }

    #[test]
    fn test_remote_ip_fail() {
        let ipv6_literal = "2001:db8::1".to_string();
        let res = super::remote_ip_with_dns(&ipv6_literal, &IpVersion::V4, &DnsConfig::default());
        assert!(res.is_err());

        let ipv4_literal = "203.0.113.10".to_string();
        let res = super::remote_ip_with_dns(&ipv4_literal, &IpVersion::V6, &DnsConfig::default());
        assert!(res.is_err());
    }

    #[test]
    fn detects_default_fake_ip_range() {
        let config = DnsConfig::default();
        assert!(super::is_fake_ip(
            IpAddr::V4(Ipv4Addr::new(198, 19, 184, 4)),
            &config
        ));
        assert!(super::is_fake_ip(
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
            &config
        ));
        assert!(!super::is_fake_ip(
            IpAddr::V4(Ipv4Addr::new(198, 20, 0, 1)),
            &config
        ));
    }

    #[test]
    fn rejects_fake_ip_from_mock_resolver() {
        let config = DnsConfig::default();
        let err = super::remote_ip_with_resolver("example.com", &IpVersion::V4, &config, |_| {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(198, 19, 184, 4))])
        })
        .unwrap_err();
        assert!(err.to_string().contains("resolved fake-ip"));
    }

    #[test]
    fn accepts_real_ip_from_mock_resolver() {
        let config = DnsConfig::default();
        let ip = super::remote_ip_with_resolver("example.com", &IpVersion::V4, &config, |_| {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
        })
        .unwrap();
        assert_eq!(ip, "93.184.216.34");
    }

    #[test]
    fn allows_fake_ip_when_reject_disabled() {
        let config = DnsConfig {
            reject_fake_ip: false,
            ..Default::default()
        };
        let ip = super::remote_ip_with_resolver("example.com", &IpVersion::V4, &config, |_| {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(198, 19, 184, 4))])
        })
        .unwrap();
        assert_eq!(ip, "198.19.184.4");
    }
}
