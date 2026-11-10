use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::time::timeout;

use crate::config::{Config, VpnConfig};
use crate::globalprotect::{self, Connection};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnState {
    Up,
    Down,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpnStatus {
    pub state: VpnState,
    /// Matched VPN interface, reported even when the default route does not use it.
    pub interface: Option<String>,
    pub checks: Vec<CheckResult>,
    /// What GlobalProtect reports about its own connection (current gateway, tunnel address).
    #[serde(default)]
    pub globalprotect: Option<Connection>,
}

/// VPN is up when an interface from the VPN pool exists AND the default route goes through it
/// (GlobalProtect keeps utunN with a pool IP after disconnect). Nothing else decides the state.
pub async fn detect(cfg: &Config) -> VpnStatus {
    let iface = match find_interface(&cfg.vpn) {
        Ok(found) => found,
        Err(e) => {
            return VpnStatus {
                state: VpnState::Unknown,
                interface: None,
                checks: vec![result("interface", false, format!("error: {e:#}"))],
                globalprotect: None,
            };
        }
    };
    let iface_check = result(
        "interface",
        iface.is_some(),
        match &iface {
            Some((name, ip)) => format!("{name} {ip}"),
            None => "no interface with an address from vpn.subnets".into(),
        },
    );

    let route = default_route_interface(cfg.check.timeout).await;
    let name = iface.as_ref().map(|(name, _)| name.clone());
    let route_ok = route.is_some() && route == name;
    let route_check = result(
        "default route",
        route_ok,
        format!("via {}", route.as_deref().unwrap_or("?")),
    );

    let tunnel_up = iface_check.ok && route_ok;
    let gp = cfg.vpn.check_globalprotect.then(globalprotect::connection).flatten();
    let gp_check = gp.as_ref().map(|c| globalprotect_check(c, tunnel_up));

    let mut checks = vec![iface_check, route_check];
    checks.extend(gp_check);
    VpnStatus {
        state: if tunnel_up { VpnState::Up } else { VpnState::Down },
        interface: name,
        checks,
        globalprotect: gp,
    }
}

/// GlobalProtect's own report is a cross-check, never the verdict. The client writes it apart from the tunnel
/// itself: it lags the kernel on connect, and on some machines it stays "disconnected" while connected. Traffic
/// follows the routing table, so a pool address plus the default route on the tunnel outweigh a contradicting
/// report; the report can only confirm a tunnel that is down anyway.
fn globalprotect_check(conn: &Connection, tunnel_up: bool) -> CheckResult {
    let gateway = conn.gateway_host.as_deref().map(|h| format!(", gateway {h}")).unwrap_or_default();
    let stale = conn.disconnected() && tunnel_up;
    let note = if stale { " (ignored: the tunnel interface and the default route are up)" } else { "" };
    result("globalprotect", !conn.disconnected() || stale, format!("{}{gateway}{note}", conn.status))
}

pub fn find_interface(vpn: &VpnConfig) -> Result<Option<(String, IpAddr)>> {
    let re = Regex::new(&vpn.interface_pattern)?;
    for iface in if_addrs::get_if_addrs()? {
        let ip = iface.ip();
        if re.is_match(&iface.name) && vpn.subnets.iter().any(|net| net.contains(&ip)) {
            return Ok(Some((iface.name, ip)));
        }
    }
    Ok(None)
}

pub async fn default_route_interface(limit: Duration) -> Option<String> {
    let out = timeout(limit, Command::new("/sbin/route").args(["-n", "get", "default"]).output())
        .await
        .ok()?
        .ok()?;
    route_interface(&String::from_utf8_lossy(&out.stdout))
}

pub fn route_interface(route_output: &str) -> Option<String> {
    route_output
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface:").map(|s| s.trim().to_string()))
}

/// Static host routes via physical interfaces: a full-tunnel VPN pins its gateway this way.
pub fn gateway_routes(vpn_iface: &Regex) -> Vec<(Ipv4Addr, String)> {
    match std::process::Command::new("/usr/sbin/netstat").args(["-rn", "-f", "inet"]).output() {
        Ok(out) => parse_gateway_routes(&String::from_utf8_lossy(&out.stdout), vpn_iface),
        Err(_) => Vec::new(),
    }
}

fn parse_gateway_routes(netstat: &str, vpn_iface: &Regex) -> Vec<(Ipv4Addr, String)> {
    netstat
        .lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let (dest, flags, iface) = (cols.first()?, cols.get(2)?, cols.get(3)?);
            let ip: Ipv4Addr = dest.parse().ok()?;
            let host_via_gw = flags.contains('G') && flags.contains('H');
            (host_via_gw && *iface != "lo0" && !vpn_iface.is_match(iface)).then(|| (ip, iface.to_string()))
        })
        .collect()
}

fn result(name: &str, ok: bool, detail: String) -> CheckResult {
    CheckResult {
        name: name.to_string(),
        ok,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gateway_host_routes() {
        let netstat = "Destination        Gateway            Flags               Netif Expire\n\
            default            10.4.3.6           UGScg               utun4\n\
            default            192.168.1.1        UGScIg                en0\n\
            10.4.2.1           10.4.3.6           UGHS                utun4\n\
            74.221.136.175     192.168.1.1        UGHS                  en0\n\
            192.168.1.1/32     link#14            UCS                   en0      !\n";
        let re = Regex::new(r"^utun\d+$").unwrap();
        assert_eq!(
            parse_gateway_routes(netstat, &re),
            vec![("74.221.136.175".parse().unwrap(), "en0".to_string())]
        );
    }

    #[test]
    fn globalprotect_report_never_overrides_a_tunnel_that_is_up() {
        let conn = |status: &str| Connection {
            status: status.into(),
            ..Connection::default()
        };
        // Stale report (stays "disconnected" while connected): shown, but it must not fail the check.
        let stale = globalprotect_check(&conn("disconnected"), true);
        assert!(stale.ok);
        assert!(stale.detail.starts_with("disconnected (ignored"), "{}", stale.detail);
        // Tunnel down as well: the report agrees and is shown as failing.
        let down = globalprotect_check(&conn("disconnected"), false);
        assert!(!down.ok);
        assert_eq!(down.detail, "disconnected");
        assert!(globalprotect_check(&conn("connected-non-pa"), true).ok);
        assert!(globalprotect_check(&conn("connected-non-pa"), false).ok);
    }

    #[test]
    fn parses_route_interface() {
        let out = "   route to: default\ndestination: default\n    gateway: 10.4.3.6\n  interface: utun4\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n";
        assert_eq!(route_interface(out).as_deref(), Some("utun4"));
        assert_eq!(route_interface("route: writing to routing socket: not in table"), None);
    }
}
