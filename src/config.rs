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
    let cfg: Config = serde_yaml_ng::from_str(text)?;
    cfg.validate()?;
    Ok(cfg)
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
        for domain in &self.allow.domains {
            validate_hostname(domain).context("allow.domains")?;
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

fn validate_hostname(host: &str) -> Result<()> {
    let valid = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
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
    }
}
