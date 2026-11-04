//! Source restriction for connection requests (soft-fork addition).
//!
//! `--control-allow` / `CONTROL_ALLOW` is a comma-separated list of networks (CIDR or a bare address). When set,
//! hbbs accepts the requests that start a session -- `PunchHoleRequest` and `RequestRelay` -- only from a source in
//! one of those networks; every other source has the request dropped and logged. Registration (`RegisterPeer`,
//! `RegisterPk`), heartbeats and NAT tests are untouched, so devices check in from anywhere while sessions can be
//! started only from, e.g., a VPN. Empty or unset keeps upstream behaviour: every source is allowed.

use hbb_common::{log, ResultType};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

static ALLOWED: OnceLock<Vec<IpNetwork>> = OnceLock::new();

/// Parse the list. An entry that is not a network or an address is an error: a typo must not silently open the
/// server to everyone.
pub fn parse(list: &str) -> ResultType<Vec<IpNetwork>> {
    let mut out = Vec::new();
    for raw in list.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let net = if entry.contains('/') {
            entry.parse::<IpNetwork>().map_err(|err| err.to_string())
        } else {
            entry.parse::<IpAddr>().map(IpNetwork::from).map_err(|err| err.to_string())
        };
        match net {
            Ok(net) => out.push(net),
            Err(err) => hbb_common::bail!("invalid control-allow entry {entry:?}: {err}"),
        }
    }
    Ok(out)
}

/// Set the list once at startup (later calls are ignored).
pub fn init(list: &str) -> ResultType<()> {
    let nets = parse(list)?;
    if nets.is_empty() {
        log::info!("control-allow: unset, connection requests accepted from any source");
    } else {
        log::info!("control-allow: connection requests accepted only from {:?}", nets);
    }
    let _ = ALLOWED.set(nets);
    Ok(())
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Whether `ip` may start a session under `nets` (empty = everyone).
pub fn allows(nets: &[IpNetwork], ip: IpAddr) -> bool {
    let ip = normalize(ip);
    nets.is_empty() || nets.iter().any(|net| net.contains(ip))
}

/// Whether the configured list lets `addr` start a session.
pub fn allowed(addr: &SocketAddr) -> bool {
    match ALLOWED.get() {
        Some(nets) => allows(nets, addr.ip()),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_list_allows_everyone() {
        let nets = parse("").unwrap();
        assert!(allows(&nets, ip("203.0.113.9")));
        assert!(allows(&nets, ip("2001:db8::1")));
    }

    #[test]
    fn listed_networks_and_addresses_only() {
        let nets = parse("192.168.255.0/25, 172.23.7.0/24,10.9.8.7").unwrap();
        assert!(allows(&nets, ip("192.168.255.3")));
        assert!(allows(&nets, ip("172.23.7.200")));
        assert!(allows(&nets, ip("10.9.8.7")));
        assert!(!allows(&nets, ip("10.9.8.8")));
        assert!(!allows(&nets, ip("192.168.255.200")));
        assert!(!allows(&nets, ip("203.0.113.9")));
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_its_ipv4_network() {
        let nets = parse("172.23.7.0/24").unwrap();
        assert!(allows(&nets, ip("::ffff:172.23.7.5")));
        assert!(!allows(&nets, ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn ipv6_networks() {
        let nets = parse("2001:db8:1::/48").unwrap();
        assert!(allows(&nets, ip("2001:db8:1::42")));
        assert!(!allows(&nets, ip("2001:db8:2::42")));
    }

    #[test]
    fn a_bad_entry_is_an_error_not_an_open_door() {
        assert!(parse("172.23.7.0/24,not-a-network").is_err());
        assert!(parse("172.23.7.0/33").is_err());
    }
}
