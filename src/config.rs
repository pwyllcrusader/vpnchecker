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
/// Resolver key for the gateway address GlobalProtect itself reports for the current connection.
pub const GP_GATEWAY: &str = "@gp-gateway";
/// Resolver key for the resolved `protect.hosts` (Claude / Cursor servers).
pub const PROTECTED_HOSTS: &str = "@protected";
/// Resolver key for remote addresses seen on sockets of protected processes.
pub const OBSERVED: &str = "@observed";

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
    /// `full` (default): additionally block all outbound traffic of the machine unless it goes through the VPN.
    /// `scoped`: only the protected apps (Claude / Cursor / Rider) are affected.
    #[serde(default)]
    pub mode: Mode,
    /// Claude / Cursor / Rider protection. Always active, in both modes; the freeze only in `scoped` or with `protect.freeze`.
    #[serde(default)]
    pub protect: ProtectConfig,
    #[serde(default)]
    pub allow: AllowConfig,
    #[serde(default)]
    pub check: CheckConfig,
    #[serde(default)]
    pub update: UpdateConfig,
    #[serde(default = "yes")]
    pub notify: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Scoped,
    #[default]
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// SIGSTOP while the VPN is down, SIGCONT afterwards: nothing is lost.
    #[default]
    Stop,
    /// SIGTERM, then SIGKILL.
    Kill,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpnConfig {
    #[serde(default = "default_interface_pattern")]
    pub interface_pattern: String,
    pub subnets: Vec<IpNet>,
    /// Treat the VPN as down when GlobalProtect itself reports a disconnected tunnel.
    #[serde(default = "yes")]
    pub check_globalprotect: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProtectConfig {
    /// In `full` mode also freeze (or kill, see `action`) the protected processes while the VPN is down. pf already
    /// blocks them there, so off by default. Always on in `scoped` mode.
    pub freeze: bool,
    pub action: Action,
    /// Domain suffixes whose DNS lookups are blocked locally while the VPN is down (no query leaves the Mac).
    pub domains: Vec<String>,
    /// Concrete hosts resolved (while the VPN is up) into the set of server addresses blocked outside the tunnel.
    pub hosts: Vec<String>,
    /// Regexes matched against the full command line; a match, and all its children, is protected.
    pub process_patterns: Vec<String>,
    pub extra_process_patterns: Vec<String>,
    pub dns_shield: bool,
    pub dns_port: u16,
    /// Kernel pf block of the known Claude / Cursor server addresses outside the tunnel.
    pub pf_block: bool,
    /// Also learn server addresses from the sockets of protected processes while the VPN is up. Catches rotating
    /// cloud addresses, but also whatever else those apps talk to (GitHub, CDNs), which then becomes unreachable
    /// for every app while the VPN is down. Off by default.
    pub observe_connections: bool,
    /// Wake-gap detection and relaunch scan period while blocked.
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// A pause between two ticks longer than this means the Mac slept: freeze first, verify afterwards.
    #[serde(with = "humantime_serde")]
    pub wake_gap: Duration,
    /// Minimum time to stay frozen after a wake.
    #[serde(with = "humantime_serde")]
    pub wake_hold: Duration,
    /// Consecutive good checks required before resuming.
    pub resume_checks: u32,
}

impl Default for ProtectConfig {
    fn default() -> Self {
        let owned = |list: &[&str]| list.iter().map(|s| s.to_string()).collect();
        Self {
            freeze: false,
            action: Action::Stop,
            domains: owned(&["anthropic.com", "claude.ai", "claude.com", "cursor.sh", "cursor.com"]),
            hosts: owned(&[
                "api.anthropic.com",
                "claude.ai",
                "console.anthropic.com",
                "statsig.anthropic.com",
                "cursor.com",
                "api2.cursor.sh",
                "api3.cursor.sh",
                "repo.cursor.sh",
            ]),
            process_patterns: owned(&[
                r"/Claude\.app/Contents/",
                r"/Cursor\.app/Contents/",
                r"/\.cursor/(extensions|bin|cursor-server)/",
                r"@anthropic-ai/claude-code",
                r"/\.local/share/claude/",
                r"(^|/)claude( |$)",
                r"(^|/)cursor-agent( |$)",
                r"/Rider\.app/Contents/",
            ]),
            extra_process_patterns: Vec::new(),
            dns_shield: true,
            dns_port: 5399,
            pf_block: true,
            observe_connections: false,
            interval: Duration::from_millis(250),
            wake_gap: Duration::from_secs(3),
            wake_hold: Duration::from_secs(5),
            resume_checks: 4,
        }
    }
}

impl ProtectConfig {
    pub fn patterns(&self) -> Vec<String> {
        self.process_patterns.iter().chain(&self.extra_process_patterns).cloned().collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowConfig {
    pub lan: bool,
    /// Allow VPN gateways seen as host routes outside the tunnel while the VPN is up.
    pub learn_gateways: bool,
    /// Allow portal / gateway hosts found in GlobalProtect settings and its event log.
    pub globalprotect: bool,
    /// Host names found in the (user-writable) GlobalProtect event log are only trusted when they end in one of
    /// these suffixes, equal a portal, or equal the gateway GlobalProtect reports itself. In `full` mode every
    /// lookup under them goes through the DNS forwarder, so gateways never used before and rotating addresses
    /// are allowed the moment the client resolves them.
    pub gateway_suffixes: Vec<String>,
    /// Hosts the VPN client probes before it connects (GlobalProtect's captive portal test). Allowed in `full`
    /// mode: a refused probe looks like a captive portal to the client, which then waits instead of connecting.
    /// GlobalProtect rotates through all three defaults and takes two refused probes for a captive portal, so
    /// allowing only one of them is not enough.
    pub probe_hosts: Vec<String>,
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
            gateway_suffixes: vec!["gpcloudservice.com".to_string()],
            probe_hosts: ["captive.apple.com", "clients3.google.com", "www.msftconnecttest.com"]
                .map(str::to_string)
                .to_vec(),
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

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateConfig {
    /// The installed daemon looks for newer GitHub releases, installs them and restarts.
    pub auto: bool,
    /// Ask the user (the config owner, in their GUI session) before installing. Nothing is downloaded without a
    /// yes; no answer, or nobody to ask, means no update. `false` installs unattended.
    pub confirm: bool,
    /// How often it looks for a newer release (only while the VPN is up).
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            auto: true,
            confirm: true,
            interval: Duration::from_secs(24 * 3600),
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
    // They become forwarder zones, which are matched against lower-case query names.
    for list in [&mut cfg.allow.gateway_suffixes, &mut cfg.allow.probe_hosts] {
        for name in list.iter_mut() {
            *name = name.to_ascii_lowercase();
        }
    }
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
        if self.update.interval < Duration::from_secs(3600) {
            bail!("update.interval must be at least 1h");
        }
        for suffix in &self.allow.gateway_suffixes {
            validate_hostname(suffix).context("allow.gateway_suffixes")?;
        }
        for host in &self.allow.probe_hosts {
            validate_hostname(host).context("allow.probe_hosts")?;
        }
        let p = &self.protect;
        for domain in &p.domains {
            validate_hostname(domain).context("protect.domains")?;
        }
        for host in &p.hosts {
            validate_hostname(host).context("protect.hosts")?;
        }
        // Both write /etc/resolver/<domain>: a name cannot be shielded and allowed at the same time.
        let a = &self.allow;
        let allowed: Vec<String> = a.domains.iter().chain(&a.gateway_suffixes).chain(&a.probe_hosts).cloned().collect();
        for domain in &p.domains {
            if let Some(zone) = covering_zone(&allowed, domain) {
                bail!("protect.domains: {domain} is covered by the allow entry {zone}");
            }
        }
        for zone in &allowed {
            if let Some(domain) = covering_zone(&p.domains, zone) {
                bail!("allow: {zone} is covered by protect.domains entry {domain}");
            }
        }
        for pattern in p.patterns() {
            Regex::new(&pattern).with_context(|| format!("protect.process_patterns: {pattern:?}"))?;
        }
        if p.patterns().is_empty() {
            bail!("protect.process_patterns must not be empty");
        }
        if p.interval < Duration::from_millis(100) {
            bail!("protect.interval must be at least 100ms");
        }
        if p.wake_gap < Duration::from_secs(2) {
            bail!("protect.wake_gap must be at least 2s");
        }
        if p.resume_checks == 0 {
            bail!("protect.resume_checks must be at least 1");
        }
        if p.dns_port < 1024 {
            bail!("protect.dns_port must be 1024 or higher");
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

    /// Whether the protected processes are frozen / killed while the VPN is down.
    pub fn freezes(&self) -> bool {
        self.mode == Mode::Scoped || self.protect.freeze
    }

    pub fn vpn_subnets(&self) -> BTreeSet<IpNet> {
        self.vpn.subnets.iter().map(IpNet::trunc).collect()
    }

    /// Zones answered by the DNS forwarder: every address a lookup under them returns is allowed before the
    /// client gets the answer. `allow.domains` always; in `full` mode also what the VPN client itself needs to
    /// reconnect, because there a blocked gateway or probe means the VPN never comes back.
    pub fn forward_zones(&self) -> Vec<String> {
        let mut zones = self.allow.domains.clone();
        if self.mode == Mode::Full && self.allow.globalprotect {
            for zone in self.allow.gateway_suffixes.iter().chain(&self.allow.probe_hosts) {
                if covering_zone(&zones, zone).is_none() {
                    zones.push(zone.clone());
                }
            }
        }
        zones
    }

    /// Resolver keys (forwarder zones plus learned sets) whose addresses are allowed.
    pub fn allow_keys(&self) -> Vec<String> {
        let mut keys = self.forward_zones();
        if self.allow.learn_gateways {
            keys.push(LEARNED_GATEWAYS.to_string());
        }
        if self.allow.globalprotect {
            keys.push(GLOBALPROTECT_HOSTS.to_string());
            keys.push(GP_GATEWAY.to_string());
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

/// Protection settings for commands that run without a valid config (stop / uninstall must still release things).
pub fn protect_or_default(path: &Path) -> ProtectConfig {
    load(path).map(|c| c.protect).unwrap_or_default()
}

/// Strict: the daemon (root) writes /etc/resolver/<host>, so no `..` or `/` may slip through.
pub fn validate_hostname(host: &str) -> Result<()> {
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
    fn full_is_the_default_and_protection_has_defaults() {
        let cfg = parse("vpn:\n  subnets: [10.4.0.0/16]\n").unwrap();
        assert_eq!(cfg.mode, Mode::Full);
        let scoped = parse("vpn:\n  subnets: [10.4.0.0/16]\nmode: scoped\n").unwrap();
        assert_eq!(scoped.mode, Mode::Scoped);
        assert!(!cfg.protect.freeze && !cfg.freezes(), "pf already blocks everything in full mode");
        assert!(scoped.freezes(), "scoped mode always freezes");
        assert_eq!(cfg.protect.action, Action::Stop);
        assert!(cfg.protect.dns_shield && cfg.protect.pf_block);
        assert!(!cfg.protect.observe_connections, "observed addresses cause collateral blocking, opt-in only");
        assert!(cfg.protect.domains.contains(&"anthropic.com".to_string()));
        assert!(cfg.protect.domains.contains(&"cursor.sh".to_string()));
        assert!(cfg.protect.patterns().iter().any(|p| p.contains("Rider")), "Rider is protected by default");
        assert!(cfg.vpn.check_globalprotect);
        assert!(cfg.allow_keys().contains(&GP_GATEWAY.to_string()));
    }

    #[test]
    fn full_mode_and_custom_protection() {
        let cfg = parse(
            "vpn:\n  subnets: [10.4.0.0/16]\nmode: full\nprotect:\n  freeze: true\n  action: kill\n  extra_process_patterns: ['/Foo\\.app/']\n  resume_checks: 2\n",
        )
        .unwrap();
        assert_eq!(cfg.mode, Mode::Full);
        assert!(cfg.freezes());
        assert_eq!(cfg.protect.action, Action::Kill);
        assert_eq!(cfg.protect.patterns().last().unwrap(), "/Foo\\.app/");
    }

    #[test]
    fn auto_update_defaults_and_limits() {
        let base = "vpn:\n  subnets: [10.4.0.0/16]\n";
        let cfg = parse(base).unwrap();
        assert!(cfg.update.auto);
        assert!(cfg.update.confirm, "never installs without asking unless told to");
        assert_eq!(cfg.update.interval, Duration::from_secs(24 * 3600));
        let template = parse(TEMPLATE).unwrap();
        assert!(template.update.auto && template.update.confirm, "the template spells the defaults out");

        let unattended = parse(&format!("{base}update:\n  confirm: false\n")).unwrap();
        assert!(unattended.update.auto && !unattended.update.confirm);

        let off = parse(&format!("{base}update:\n  auto: false\n  interval: 6h\n")).unwrap();
        assert!(!off.update.auto);
        assert_eq!(off.update.interval, Duration::from_secs(6 * 3600));

        assert!(parse(&format!("{base}update:\n  interval: 5m\n")).is_err(), "no polling GitHub every few minutes");
        assert!(parse(&format!("{base}update:\n  channel: beta\n")).is_err(), "unknown field");
    }

    #[test]
    fn rejects_bad_protection() {
        for bad in [
            "protect:\n  domains: ['..']\n",
            "protect:\n  domains: ['a..b']\n",
            "protect:\n  domains: ['../etc']\n",
            "protect:\n  process_patterns: ['(']\n",
            "protect:\n  process_patterns: []\n",
            "protect:\n  wake_gap: 500ms\n",
            "protect:\n  resume_checks: 0\n",
            "protect:\n  dns_port: 53\n",
            "protect:\n  action: freeze\n",
        ] {
            let text = format!("vpn:\n  subnets: [10.4.0.0/16]\n{bad}");
            assert!(parse(&text).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn dns_names_are_validated() {
        assert!(validate_hostname("api2.cursor.sh").is_ok());
        for bad in ["", ".", "a..b", "-a.com", "a-.com", "a/b", "a b", ".com"] {
            assert!(validate_hostname(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn protect_and_allow_domains_must_not_overlap() {
        let base = "vpn:\n  subnets: [10.4.0.0/16]\n";
        assert!(parse(&format!("{base}allow:\n  domains: [claude.ai]\n")).is_err(), "shielded by default");
        assert!(parse(&format!("{base}allow:\n  domains: [api.anthropic.com]\n")).is_err(), "under a shielded zone");
        assert!(parse(&format!("{base}allow:\n  domains: [ai]\n")).is_err(), "parent of a shielded zone");
        assert!(parse(&format!("{base}allow:\n  domains: [example.com]\n")).is_ok());
    }

    #[test]
    fn full_mode_forwards_what_the_vpn_client_needs() {
        let base = "vpn:\n  subnets: [10.4.0.0/16]\n";
        let full = parse(base).unwrap();
        assert_eq!(
            full.forward_zones(),
            ["gpcloudservice.com", "captive.apple.com", "clients3.google.com", "www.msftconnecttest.com"],
            "every host GlobalProtect probes: two refused probes read as a captive portal"
        );
        assert!(full.allow_keys().contains(&"gpcloudservice.com".to_string()), "learned addresses reach pf");

        let scoped = parse(&format!("{base}mode: scoped\nallow:\n  domains: [example.com]\n")).unwrap();
        assert_eq!(scoped.forward_zones(), ["example.com"], "scoped mode never blocks the VPN client");

        let off = parse(&format!("{base}allow:\n  globalprotect: false\n")).unwrap();
        assert!(off.forward_zones().is_empty());

        let covered = parse(&format!("{base}allow:\n  domains: [gpcloudservice.com, google.com]\n")).unwrap();
        assert_eq!(
            covered.forward_zones(),
            ["gpcloudservice.com", "google.com", "captive.apple.com", "www.msftconnecttest.com"],
            "covered zones are not repeated"
        );

        let custom =
            parse(&format!("{base}allow:\n  gateway_suffixes: [VPN.Corp.Example]\n  probe_hosts: []\n")).unwrap();
        assert_eq!(custom.forward_zones(), ["vpn.corp.example"]);

        assert!(parse(&format!("{base}allow:\n  probe_hosts: [claude.ai]\n")).is_err(), "shielded and allowed");
        assert!(parse(&format!("{base}allow:\n  gateway_suffixes: [anthropic.com]\n")).is_err());
        assert!(parse(&format!("{base}allow:\n  probe_hosts: ['a..b']\n")).is_err());
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
