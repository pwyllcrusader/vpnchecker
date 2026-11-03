use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::LazyLock;
use std::time::SystemTime;

use plist::Value;
use regex::Regex;

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

/// Portal and gateway host names known to the GlobalProtect client on this machine.
pub fn discover(user_home: Option<&Path>) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    let user_settings = user_home.map(|home| home.join(USER_SETTINGS));
    for path in [Some(Path::new(SETTINGS)), user_settings.as_deref()].into_iter().flatten() {
        if let Ok(value) = Value::from_file(path) {
            collect_portals(&value, &mut hosts);
        }
    }
    if let Ok(log) = read_tail(Path::new(EVENT_LOG), LOG_TAIL_BYTES) {
        hosts.extend(parse_gateways(&log));
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

    #[test]
    fn normalize_rejects_garbage() {
        assert_eq!(normalize("vpn.acme.example").as_deref(), Some("vpn.acme.example"));
        assert_eq!(normalize("not a host"), None);
        assert_eq!(normalize(""), None);
    }
}
