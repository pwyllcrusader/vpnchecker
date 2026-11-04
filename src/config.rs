use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use regex::Regex;
use serde::Deserialize;

pub const TEMPLATE: &str = include_str!("../config.example.yaml");

/// Resolver key for gateways learned from the routing table.
pub const LEARNED_GATEWAYS: &str = "@gateways";
/// Resolver key for portal / gateway hosts discovered from GlobalProtect settings and logs.
pub const GLOBALPROTECT_HOSTS: &str = "@globalprotect";

const LAN_CIDRS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub vpn: VpnConfig,
    #[serde(default)]
    pub allow: AllowConfig,
    #[serde(default)]
    pub check: CheckConfig,
    #[serde(default = "yes")]
    pub notify: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpnConfig {
    #[serde(default = "default_interface_pattern")]
    pub interface_pattern: String,
    pub subnets: Vec<IpNet>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowConfig {
    pub lan: bool,
    /// Allow VPN gateways seen as host routes outside the tunnel while the VPN is up.
    pub learn_gateways: bool,
    /// Allow portal / gateway hosts found in GlobalProtect settings and its event log.
    pub globalprotect: bool,
    /// Each entry covers the domain and all of its subdomains.
    pub domains: Vec<String>,
    pub cidrs: Vec<IpNet>,
}

impl Default for AllowConfig {
    fn default() -> Self {
        Self {
            lan: true,
            learn_gateways: true,
            globalprotect: true,
            domains: Vec::new(),
            cidrs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CheckConfig {
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub resolve_interval: Duration,
    #[serde(with = "humantime_serde")]
    pub resolve_retain: Duration,
}

impl Default for CheckConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(2),
            timeout: Duration::from_millis(1500),
            resolve_interval: Duration::from_secs(60),
            resolve_retain: Duration::from_secs(24 * 3600),
        }
    }
}

fn yes() -> bool {
    true
}

fn default_interface_pattern() -> String {
    r"^(utun\d+|gpd\d+)$".to_string()
}

pub fn load(path: &Path) -> Result<Config> {
    let text =
        fs::read_to_string(path).with_context(|| format!("reading config {}", path.display()))?;
    parse(&text).with_context(|| format!("invalid config {}", path.display()))
}

pub fn parse(text: &str) -> Result<Config> {
    let mut cfg: Config = serde_yaml_ng::from_str(text)?;
    let mut domains = Vec::new();
    for mask in &cfg.allow.domains {
        let domain = normalize_mask(mask).context("allow.domains")?;
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    cfg.allow.domains = domains;
    cfg.validate()?;
    Ok(cfg)
}

/// Turns `https://*.Example.com:443/path` into `example.com`.
pub fn normalize_mask(mask: &str) -> Result<String> {
    let mut host = mask.trim();
    if let Some((_, rest)) = host.split_once("://") {
        host = rest;
    }
    host = host.split(['/', '?', '#']).next().unwrap_or_default();
    if let Some((_, rest)) = host.rsplit_once('@') {
        host = rest;
    }
    if let Some((name, port)) = host.rsplit_once(':')
        && port.chars().all(|c| c.is_ascii_digit())
    {
        host = name;
    }
    let host = host.strip_prefix("*.").unwrap_or(host).trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() {
        bail!("{mask:?} is an IP address, put it into allow.cidrs");
    }
    validate_hostname(&host).with_context(|| format!("invalid mask {mask:?}"))?;
    Ok(host)
}

/// Adds `domain` to `allow.domains` by editing the text, so comments and layout survive.
pub fn insert_allow_domain(text: &str, domain: &str) -> Result<String> {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let indent = |l: &str| l.len() - l.trim_start().len();
    let is_content = |l: &str| !l.trim().is_empty() && !l.trim_start().starts_with('#');

    let Some(allow) = lines.iter().position(|l| l.starts_with("allow:")) else {
        lines.extend(["allow:".to_string(), "  domains:".to_string(), format!("    - {domain}")]);
        return Ok(lines.join("\n") + "\n");
    };
    if is_content(&lines[allow]["allow:".len()..]) {
        bail!("`allow:` is written inline; edit the config manually");
    }
    let end = (allow + 1..lines.len())
        .find(|&i| is_content(&lines[i]) && indent(&lines[i]) == 0)
        .unwrap_or(lines.len());
    let key = (allow + 1..end).find(|&i| is_content(&lines[i]) && lines[i].trim_start().starts_with("domains:"));

    let Some(key) = key else {
        let child = (allow + 1..end)
            .find(|&i| is_content(&lines[i]))
            .map_or(2, |i| indent(&lines[i]));
        let pad = " ".repeat(child);
        lines.insert(allow + 1, format!("{pad}domains:"));
        lines.insert(allow + 2, format!("{pad}  - {domain}"));
        return Ok(lines.join("\n") + "\n");
    };

    let key_indent = indent(&lines[key]);
    let pad = " ".repeat(key_indent);
    let rest = lines[key].trim_start()["domains:".len()..].trim_start().to_string();
    if let Some(flow) = rest.strip_prefix('[') {
        let Some((inside, after)) = flow.split_once(']') else {
            bail!("multi-line `domains: [...]` is not supported; edit the config manually");
        };
        let inside = inside.trim();
        if inside.is_empty() {
            let after = after.trim();
            lines[key] = format!("{pad}domains:{}{after}", if after.is_empty() { "" } else { " " });
            lines.insert(key + 1, format!("{pad}  - {domain}"));
        } else {
            lines[key] = format!("{pad}domains: [{inside}, {domain}]{after}");
        }
        return Ok(lines.join("\n") + "\n");
    }
    if is_content(&rest) {
        bail!("unexpected value for allow.domains; edit the config manually");
    }

    let mut last_item = None;
    for (i, line) in lines.iter().enumerate().take(end).skip(key + 1) {
        if !is_content(line) {
            continue;
        }
        let item = line.trim_start().starts_with("- ") || line.trim() == "-";
        if indent(line) > key_indent || (item && indent(line) == key_indent) {
            if item {
                last_item = Some(i);
            }
        } else {
            break;
        }
    }
    match last_item {
        Some(i) => {
            let item_pad = " ".repeat(indent(&lines[i]));
            lines.insert(i + 1, format!("{item_pad}- {domain}"));
        }
        None => lines.insert(key + 1, format!("{pad}  - {domain}")),
    }
    Ok(lines.join("\n") + "\n")
}

/// The configured domain that covers `name` (itself or a parent), most specific first.
pub fn covering_zone<'a>(zones: &'a [String], name: &str) -> Option<&'a str> {
    zones
        .iter()
        .filter(|z| name == z.as_str() || name.strip_suffix(z.as_str()).is_some_and(|p| p.ends_with('.')))
        .max_by_key(|z| z.len())
        .map(String::as_str)
}

impl Config {
    fn validate(&self) -> Result<()> {
        Regex::new(&self.vpn.interface_pattern).context("vpn.interface_pattern")?;
        if self.vpn.subnets.is_empty() {
            bail!("vpn.subnets must list the VPN address pool (macOS always has system utun interfaces)");
        }
        if self.check.interval < Duration::from_millis(500) {
            bail!("check.interval must be at least 500ms");
        }
        if self.check.timeout.is_zero() {
            bail!("check.timeout must be positive");
        }
        if self.check.resolve_interval < Duration::from_secs(5) {
            bail!("check.resolve_interval must be at least 5s");
        }
        Ok(())
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.allow.learn_gateways
            && !self.allow.globalprotect
            && self.allow.domains.is_empty()
            && self.allow.cidrs.is_empty()
        {
            out.push(
                "allowlist is empty and learn_gateways is off: the VPN client cannot reach its portal/gateway"
                    .to_string(),
            );
        }
        out
    }

    pub fn vpn_subnets(&self) -> BTreeSet<IpNet> {
        self.vpn.subnets.iter().map(IpNet::trunc).collect()
    }

    /// Resolver keys (domains plus learned sets) whose addresses are allowed.
    pub fn allow_keys(&self) -> Vec<String> {
        let mut keys = self.allow.domains.clone();
        if self.allow.learn_gateways {
            keys.push(LEARNED_GATEWAYS.to_string());
        }
        if self.allow.globalprotect {
            keys.push(GLOBALPROTECT_HOSTS.to_string());
        }
        keys
    }

    pub fn allow_cidrs(&self) -> BTreeSet<IpNet> {
        let mut cidrs: BTreeSet<IpNet> = self.allow.cidrs.iter().map(IpNet::trunc).collect();
        if self.allow.lan {
            cidrs.extend(LAN_CIDRS.iter().map(|c| c.parse::<IpNet>().unwrap()));
        }
        cidrs
    }
}

/// Strict: the daemon (root) writes /etc/resolver/<host>, so no `..` or `/` may slip through.
fn validate_hostname(host: &str) -> Result<()> {
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if !valid {
        bail!("invalid host name {host:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_parses() {
        let cfg = parse(TEMPLATE).unwrap();
        assert!(cfg.notify);
        assert_eq!(cfg.check.interval, Duration::from_secs(2));
        assert!(cfg.allow_cidrs().contains(&"192.168.0.0/16".parse().unwrap()));
        assert!(cfg.allow_keys().contains(&LEARNED_GATEWAYS.to_string()));
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let cfg = parse("vpn:\n  subnets: [10.4.0.0/16]\n").unwrap();
        assert!(cfg.allow.lan && cfg.allow.learn_gateways);
        assert!(cfg.warnings().is_empty());
    }

    #[test]
    fn allowlist_without_lan() {
        let cfg = parse(
            "vpn:\n  subnets: [10.4.0.0/16]\nallow:\n  lan: false\n  learn_gateways: false\n  globalprotect: false\n  domains: [vpn.corp.example]\n  cidrs: [203.0.113.5/32]\n",
        )
        .unwrap();
        assert_eq!(cfg.allow_keys(), vec!["vpn.corp.example".to_string()]);
        assert_eq!(cfg.allow_cidrs().len(), 1);

        let empty = parse("vpn:\n  subnets: [10.4.0.0/16]\nallow:\n  learn_gateways: false\n  globalprotect: false\n").unwrap();
        assert_eq!(empty.warnings().len(), 1);
    }

    #[test]
    fn rejects_invalid() {
        assert!(parse("vpn:\n  subnets: []\n").is_err());
        assert!(parse("vpn:\n  subnets: [10.0.0.0/8]\nmode: state\n").is_err());
        assert!(parse("vpn:\n  subnets: [10.0.0.0/8]\nallow:\n  domains: ['-x']\n").is_err());
        assert!(parse("vpn:\n  subnets: [10.0.0.0/8]\ncheck:\n  interval: 100ms\n").is_err());
        for bad in ["..", "a..b", "-a.com", "a-.com", "a b.com", "a_b.com", "", "*", "1.2.3.4"] {
            assert!(normalize_mask(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn masks_normalized() {
        for (mask, want) in [
            ("example.com", "example.com"),
            ("*.Example.COM.", "example.com"),
            ("https://x.example.com:8443/a?b#c", "x.example.com"),
            ("user@host.example.com", "host.example.com"),
        ] {
            assert_eq!(normalize_mask(mask).unwrap(), want);
        }
        let cfg = parse("vpn:\n  subnets: [10.0.0.0/8]\nallow:\n  domains: ['*.a.com', a.com, B.com]\n").unwrap();
        assert_eq!(cfg.allow.domains, ["a.com", "b.com"]);
    }

    #[test]
    fn zones_cover_subdomains() {
        let zones = vec!["example.com".to_string(), "api.example.com".to_string()];
        assert_eq!(covering_zone(&zones, "example.com"), Some("example.com"));
        assert_eq!(covering_zone(&zones, "a.b.example.com"), Some("example.com"));
        assert_eq!(covering_zone(&zones, "x.api.example.com"), Some("api.example.com"));
        assert_eq!(covering_zone(&zones, "badexample.com"), None);
    }

    fn domains_after_insert(text: &str) -> Vec<String> {
        let out = insert_allow_domain(text, "new.example").unwrap();
        parse(&out).unwrap_or_else(|e| panic!("{e:#}\n{out}")).allow.domains
    }

    #[test]
    fn insert_into_template_keeps_comments() {
        let out = insert_allow_domain(TEMPLATE, "new.example").unwrap();
        assert!(out.contains("  domains:\n    - new.example\n  #  - vpn.example.corp"));
        assert_eq!(out.matches('#').count(), TEMPLATE.matches('#').count());
        assert_eq!(parse(&out).unwrap().allow.domains, ["new.example"]);
    }

    #[test]
    fn insert_variants() {
        let base = "vpn:\n  subnets: [10.0.0.0/8]\n";
        assert_eq!(domains_after_insert(base), ["new.example"]);
        assert_eq!(domains_after_insert(&format!("{base}allow:\n  lan: false\n")), ["new.example"]);
        assert_eq!(
            domains_after_insert(&format!("{base}allow:\n  domains: [a.com]  # c\n  lan: true\n")),
            ["a.com", "new.example"]
        );
        assert_eq!(
            domains_after_insert(&format!("{base}allow:\n  domains:\n    - a.com\n    # x\n    - b.com\n\n  lan: true\ncheck: {{}}\n")),
            ["a.com", "b.com", "new.example"]
        );
        assert_eq!(
            domains_after_insert(&format!("allow:\n  domains:\n  - a.com\n  cidrs: []\n{base}")),
            ["a.com", "new.example"]
        );
        assert_eq!(domains_after_insert(&format!("{base}allow:\n  domains:\n  lan: true\n")), ["new.example"]);
        assert!(insert_allow_domain(&format!("{base}allow:\n  domains: [\n    a.com]\n"), "x.com").is_err());
        assert!(insert_allow_domain(&format!("{base}allow: {{lan: true}}\n"), "x.com").is_err());
    }
}
