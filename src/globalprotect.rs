use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;
use std::sync::LazyLock;
use std::time::SystemTime;

use plist::Value;
use regex::Regex;
use serde::{Deserialize, Serialize};

const SETTINGS: &str = "/Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist";
const USER_SETTINGS: &str = "Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist";
pub const EVENT_LOG: &str = "/Library/Logs/PaloAltoNetworks/GlobalProtect/pan_gp_event.log";
const LOG_TAIL_BYTES: u64 = 4 << 20;
const MAX_HOSTS: usize = 64;

static HOSTNAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}\b").unwrap()
});

// e.g. "Gateway Login starts to HOST", "Prelogin to gateway (null) HOST", "login finished with address HOST and user X"
static GATEWAY_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"(?i)\b(?:gateway|to|address)\s+(?:\(null\)\s+)?({})", HOSTNAME.as_str().trim_start_matches("(?i)"))).unwrap()
});

/// What GlobalProtect reports about its own connection (`DEM` block of the root-owned settings plist,
/// rewritten by PanGPS on every connect / disconnect).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    /// e.g. `connected-non-pa`; the exact vocabulary depends on the client version.
    pub status: String,
    pub gateway_host: Option<String>,
    pub gateway_ip: Option<IpAddr>,
    pub gateway_location: Option<String>,
    pub tunnel_ip: Option<IpAddr>,
}

impl Connection {
    /// Only an explicit "disconnected" counts, and even that is a cross-check: see `detect::globalprotect_check`.
    pub fn disconnected(&self) -> bool {
        self.status.to_ascii_lowercase().contains("disconnect")
    }
}

/// Current GlobalProtect connection, or `None` when the client keeps no such state (other VPN, old client).
pub fn connection() -> Option<Connection> {
    parse_connection(&Value::from_file(SETTINGS).ok()?)
}

pub fn parse_connection(value: &Value) -> Option<Connection> {
    let dem = find_dict(value, "DEM")?;
    let text = |key: &str| dem.get(key).and_then(Value::as_string).map(str::to_string);
    let status = text("tunnel-status")?;
    let (gateway_host, gateway_ip) = text("gateway-address").map(|s| parse_gateway_address(&s)).unwrap_or_default();
    let tunnel_ip = text("tunnel-ip").and_then(|s| field(&s, "ipv4").and_then(|v| v.parse().ok()));
    Some(Connection {
        status,
        gateway_host,
        gateway_ip,
        gateway_location: text("gateway-location").filter(|s| !s.is_empty()),
        tunnel_ip,
    })
}

fn find_dict<'a>(value: &'a Value, key: &str) -> Option<&'a plist::Dictionary> {
    let dict = value.as_dictionary()?;
    if let Some(found) = dict.get(key).and_then(Value::as_dictionary) {
        return Some(found);
    }
    dict.values().find_map(|v| find_dict(v, key))
}

/// `gateway=HOST,ipv4=1.2.3.4,ipv6=` -> (host, ip). The address is public, so IPv4 wins.
fn parse_gateway_address(s: &str) -> (Option<String>, Option<IpAddr>) {
    let host = field(s, "gateway").and_then(|h| normalize(&h));
    let ip = field(s, "ipv4").or_else(|| field(s, "ipv6")).and_then(|v| v.parse().ok());
    (host, ip)
}

fn field(s: &str, key: &str) -> Option<String> {
    s.split(',')
        .find_map(|part| part.trim().strip_prefix(key).and_then(|rest| rest.strip_prefix('=')))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Host names from the user-writable event log are only believed when they plausibly belong to the VPN.
fn trusted(host: &str, portals: &BTreeSet<String>, gateway: Option<&str>, suffixes: &[String]) -> bool {
    portals.contains(host)
        || gateway == Some(host)
        || suffixes.iter().any(|s| {
            let s = s.trim_start_matches('.').to_ascii_lowercase();
            host == s || host.ends_with(&format!(".{s}"))
        })
}

/// Portal and gateway host names known to the GlobalProtect client on this machine.
/// Portals (plists) and the gateway GlobalProtect reports itself are always trusted; names that only appear in
/// the event log must end in one of `trusted_suffixes`.
pub fn discover(user_home: Option<&Path>, trusted_suffixes: &[String]) -> BTreeSet<String> {
    let mut portals = BTreeSet::new();
    let user_settings = user_home.map(|home| home.join(USER_SETTINGS));
    for path in [Some(Path::new(SETTINGS)), user_settings.as_deref()].into_iter().flatten() {
        if let Ok(value) = Value::from_file(path) {
            collect_portals(&value, &mut portals);
        }
    }
    let gateway = connection().and_then(|c| c.gateway_host);
    let mut hosts = portals.clone();
    hosts.extend(gateway.clone());
    if let Ok(log) = read_tail(Path::new(EVENT_LOG), LOG_TAIL_BYTES) {
        hosts.extend(
            parse_gateways(&log)
                .into_iter()
                .filter(|h| trusted(h, &portals, gateway.as_deref(), trusted_suffixes)),
        );
    }
    hosts.into_iter().take(MAX_HOSTS).collect()
}

pub fn event_log_mtime() -> Option<SystemTime> {
    std::fs::metadata(EVENT_LOG).and_then(|m| m.modified()).ok()
}

fn collect_portals(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Dictionary(dict) => {
            for (key, value) in dict {
                if matches!(key.as_str(), "Portal" | "LastUrl")
                    && let Some(host) = value.as_string().and_then(normalize)
                {
                    out.insert(host);
                }
                collect_portals(value, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| collect_portals(v, out)),
        _ => {}
    }
}

/// Accepts "host", "host:port" or "https://host/path".
fn normalize(raw: &str) -> Option<String> {
    let rest = raw.trim().split_once("://").map_or(raw.trim(), |(_, rest)| rest);
    let host = rest.split(['/', ':']).next()?.to_ascii_lowercase();
    let whole = HOSTNAME.find(&host).is_some_and(|m| m.as_str() == host);
    whole.then_some(host)
}

/// Host names from gateway lines, most recent first.
fn parse_gateways(log: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for line in log.lines().rev() {
        if !line.to_ascii_lowercase().contains("gateway") {
            continue;
        }
        for caps in GATEWAY_HOST.captures_iter(line) {
            let host = caps[1].to_ascii_lowercase();
            if seen.insert(host.clone()) {
                out.push(host);
            }
        }
        if out.len() >= MAX_HOSTS {
            break;
        }
    }
    out
}

fn read_tail(path: &Path, max: u64) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(max)))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gateway_log_lines() {
        let log = "\
10/30/2026 20:14:42:676 [Info ]: Gateway pre-Login Starts to us-east-g-acme.gpabc.gw.gpcloudservice.com
10/30/2026 20:14:43:221 [Info ]: Prelogin to gateway (null) us-west-g-acme.gpabc.gw.gpcloudservice.com without ipv6
10/30/2026 20:14:43:368 [Info ]: Preferred Gateway login finished with address us-east-g-acme.gpabc.gw.gpcloudservice.com and user john.doe.
10/30/2026 20:14:43:368 [Info ]: Portal login completed with address vpn.acme.example and conect method of user-logon.
10/30/2026 20:14:44:085 [Info ]: Gateway selection(Priority-TCP-SSL-Weight): US East(1-129-253-20).
10/30/2026 20:15:00:000 [Info ]: User was logged out of Gateway eu-west-g-acme.gpabc.gw.gpcloudservice.com.
";
        assert_eq!(
            parse_gateways(log),
            vec![
                "eu-west-g-acme.gpabc.gw.gpcloudservice.com".to_string(),
                "us-east-g-acme.gpabc.gw.gpcloudservice.com".to_string(),
                "us-west-g-acme.gpabc.gw.gpcloudservice.com".to_string(),
            ]
        );
    }

    #[test]
    fn collects_portals_from_nested_plist() {
        let mut inner = plist::Dictionary::new();
        inner.insert("Portal".into(), Value::String("vpn.acme.example".into()));
        inner.insert("LastUrl".into(), Value::String("https://Portal2.acme.example:443/global".into()));
        inner.insert("Other".into(), Value::String("ignored.example".into()));
        let mut root = plist::Dictionary::new();
        root.insert("GlobalProtect".into(), Value::Dictionary(inner));
        let mut out = BTreeSet::new();
        collect_portals(&Value::Dictionary(root), &mut out);
        assert_eq!(out, ["portal2.acme.example".to_string(), "vpn.acme.example".to_string()].into());
    }

    fn dem_plist(status: &str) -> Value {
        let mut dem = plist::Dictionary::new();
        dem.insert("tunnel-status".into(), Value::String(status.into()));
        dem.insert(
            "gateway-address".into(),
            Value::String("gateway=US-East-G-Acme.gpabc.gw.gpcloudservice.com,ipv4=137.83.250.80,ipv6=".into()),
        );
        dem.insert("gateway-location".into(), Value::String("US East".into()));
        dem.insert("tunnel-ip".into(), Value::String("ipv4=10.4.2.247,ipv6=".into()));
        let mut gp = plist::Dictionary::new();
        gp.insert("DEM".into(), Value::Dictionary(dem));
        let mut brand = plist::Dictionary::new();
        brand.insert("GlobalProtect".into(), Value::Dictionary(gp));
        let mut root = plist::Dictionary::new();
        root.insert("Palo Alto Networks".into(), Value::Dictionary(brand));
        Value::Dictionary(root)
    }

    #[test]
    fn reads_connection_and_gateway_from_dem() {
        let c = parse_connection(&dem_plist("connected-non-pa")).unwrap();
        assert!(!c.disconnected());
        assert_eq!(c.gateway_host.as_deref(), Some("us-east-g-acme.gpabc.gw.gpcloudservice.com"));
        assert_eq!(c.gateway_ip, Some("137.83.250.80".parse().unwrap()));
        assert_eq!(c.tunnel_ip, Some("10.4.2.247".parse().unwrap()));
        assert_eq!(c.gateway_location.as_deref(), Some("US East"));
    }

    #[test]
    fn only_an_explicit_disconnect_counts() {
        assert!(parse_connection(&dem_plist("disconnected")).unwrap().disconnected());
        assert!(parse_connection(&dem_plist("Disconnected-by-user")).unwrap().disconnected());
        assert!(!parse_connection(&dem_plist("connecting")).unwrap().disconnected());
        assert!(!parse_connection(&dem_plist("something-new")).unwrap().disconnected());
        assert!(parse_connection(&Value::Dictionary(plist::Dictionary::new())).is_none());
    }

    #[test]
    fn log_hosts_must_be_trusted() {
        let portals: BTreeSet<String> = ["vpn.acme.example".to_string()].into();
        let suffixes = vec!["gpcloudservice.com".to_string()];
        assert!(trusted("vpn.acme.example", &portals, None, &suffixes));
        assert!(trusted("eu-g-acme.gpabc.gw.gpcloudservice.com", &portals, None, &suffixes));
        assert!(trusted("gw.corp.example", &portals, Some("gw.corp.example"), &suffixes));
        assert!(!trusted("evil.example", &portals, None, &suffixes));
        assert!(!trusted("notgpcloudservice.com", &portals, None, &suffixes));
    }

    #[test]
    fn normalize_rejects_garbage() {
        assert_eq!(normalize("vpn.acme.example").as_deref(), Some("vpn.acme.example"));
        assert_eq!(normalize("not a host"), None);
        assert_eq!(normalize(""), None);
    }
}
