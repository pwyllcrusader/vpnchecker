use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use tracing::{debug, info};

// Stock /etc/pf.conf evaluates `anchor "com.apple/*"`, so no system config edits are needed.
pub const ANCHOR: &str = "com.apple/vpnchecker";
const ALLOW_TABLE: &str = "vpnchecker_allow";
const VPN_TABLE: &str = "vpnchecker_vpn";
const PROTECTED_TABLE: &str = "vpnchecker_protected";
const PFCTL: &str = "/sbin/pfctl";
const TOKEN_FILE: &str = "/var/run/vpnchecker.pftoken";

/// How tunnel traffic is recognized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    /// The current VPN interface (daemon running).
    Interface(String),
    /// Source address from the VPN pool: keeps working with any utunN after the daemon exits.
    Subnets(BTreeSet<IpNet>),
}

/// Everything outbound is blocked except loopback, the tunnel, DNS/DHCP/NTP, ICMPv6 (NDP) and the allowlist.
pub fn render(via: Option<&Via>, allow: &BTreeSet<IpNet>) -> String {
    let mut rules = String::new();
    if let Some(Via::Subnets(subnets)) = via {
        rules += &table(VPN_TABLE, subnets);
    }
    // Declared even when empty: the DNS forwarder adds addresses to it between reloads.
    rules += &table(ALLOW_TABLE, allow);
    rules += "pass out quick on lo0 all\n";
    match via {
        // if-bound: a floating state would keep passing tunnel connections that fall back to en0.
        Some(Via::Interface(iface)) if valid_interface_name(iface) => {
            rules += &format!("pass out quick on {iface} all keep state (if-bound)\n");
        }
        Some(Via::Subnets(subnets)) if !subnets.is_empty() => {
            rules += &format!("pass out quick from <{VPN_TABLE}> keep state\n");
        }
        _ => {}
    }
    rules += "pass out quick proto { tcp udp } to any port 53 keep state\n";
    rules += "pass out quick proto udp to any port { 67 68 123 546 547 } keep state\n";
    rules += "pass out quick inet6 proto icmp6 all keep state\n";
    rules += &format!("pass out quick to <{ALLOW_TABLE}> keep state\n");
    rules += "block return out quick all\n";
    rules
}

/// Scoped mode: only the known Claude / Cursor server addresses are affected. They pass through the tunnel and are
/// refused everywhere else, so a dropped VPN (or a wake before the daemon reacts) cannot leak them. Everything
/// else on the machine is untouched, which keeps VPN reconnects, captive portals and split tunnel working.
pub fn render_scoped(via: Option<&Via>, protected: &BTreeSet<IpNet>) -> String {
    if protected.is_empty() {
        return String::new();
    }
    let mut rules = table(PROTECTED_TABLE, protected);
    match via {
        Some(Via::Interface(iface)) if valid_interface_name(iface) => {
            rules += &format!("pass out quick on {iface} to <{PROTECTED_TABLE}> keep state (if-bound)\n");
        }
        Some(Via::Subnets(subnets)) if !subnets.is_empty() => {
            rules += &table(VPN_TABLE, subnets);
            rules += &format!("pass out quick from <{VPN_TABLE}> to <{PROTECTED_TABLE}> keep state\n");
        }
        _ => {}
    }
    rules += &format!("block return out quick to <{PROTECTED_TABLE}>\n");
    rules
}

fn table(name: &str, addrs: &BTreeSet<IpNet>) -> String {
    if addrs.is_empty() {
        return format!("table <{name}> persist\n");
    }
    let list: Vec<String> = addrs.iter().map(ToString::to_string).collect();
    format!("table <{name}> persist {{ {} }}\n", list.join(", "))
}

/// Adds addresses to the loaded allow table without reloading the ruleset.
pub fn allow_add(ips: &[IpAddr]) -> Result<()> {
    let ips: Vec<String> = ips.iter().map(ToString::to_string).collect();
    let mut args = vec!["-a", ANCHOR, "-t", ALLOW_TABLE, "-T", "add"];
    args.extend(ips.iter().map(String::as_str));
    pfctl(&args, None)?;
    Ok(())
}

pub fn valid_interface_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15 && name.chars().all(|c| c.is_ascii_alphanumeric())
}

pub struct Pf {
    dry_run: bool,
    applied: Option<String>,
}

impl Pf {
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run, applied: None }
    }

    /// Enables pf with a reference token so other pf users are not affected.
    pub fn enable(&mut self) -> Result<()> {
        if self.dry_run {
            return Ok(());
        }
        let out = pfctl(&["-E"], None)?;
        let token = out
            .lines()
            .find(|l| l.contains("Token"))
            .and_then(|l| l.split(':').nth(1))
            .map(|t| t.trim().to_string())
            .context("pfctl -E did not return a token")?;
        release_saved_token();
        fs::write(TOKEN_FILE, &token).context("saving pf token")?;
        info!(%token, "pf enabled");
        Ok(())
    }

    /// Returns true if the ruleset changed.
    pub fn apply(&mut self, rules: &str) -> Result<bool> {
        if self.applied.as_deref() == Some(rules) {
            return Ok(false);
        }
        if self.dry_run {
            info!("[dry-run] anchor {ANCHOR} rules:\n{rules}");
        } else {
            pfctl(&["-a", ANCHOR, "-f", "-"], Some(rules))?;
        }
        self.applied = Some(rules.to_string());
        Ok(true)
    }

    /// Drops connections sourced from the VPN pool so none of them survive a tunnel loss.
    pub fn kill_states_from(&self, subnets: &BTreeSet<IpNet>) {
        if self.dry_run {
            return;
        }
        for net in subnets {
            if let Err(e) = pfctl(&["-k", &net.to_string()], None) {
                debug!(%net, error = %e, "kill states failed");
            }
        }
    }
}

pub fn flush() -> Result<()> {
    pfctl(&["-a", ANCHOR, "-F", "all"], None)?;
    Ok(())
}

pub fn release_saved_token() {
    if let Ok(token) = fs::read_to_string(TOKEN_FILE) {
        let token = token.trim();
        if !token.is_empty() && token.chars().all(|c| c.is_ascii_digit()) {
            let _ = pfctl(&["-X", token], None);
        }
        let _ = fs::remove_file(TOKEN_FILE);
    }
}

fn pfctl(args: &[&str], stdin: Option<&str>) -> Result<String> {
    let mut child = Command::new(PFCTL)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running pfctl")?;
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().context("pfctl stdin")?;
        pipe.write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        bail!("pfctl {} failed: {}", args.join(" "), text.trim());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow() -> BTreeSet<IpNet> {
        ["74.221.136.175/32", "192.168.0.0/16"].iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn interface_rules() {
        let rules = render(Some(&Via::Interface("utun4".into())), &allow());
        assert!(rules.starts_with("table <vpnchecker_allow> persist { 74.221.136.175/32, 192.168.0.0/16 }\n"));
        for needle in ["on lo0", "on utun4 all keep state (if-bound)", "port 53", "icmp6", "to <vpnchecker_allow>"] {
            assert!(rules.contains(needle), "missing {needle}");
        }
        assert!(rules.ends_with("block return out quick all\n"));
    }

    #[test]
    fn no_vpn_blocks_everything_but_essentials() {
        let rules = render(None, &BTreeSet::new());
        assert!(rules.starts_with("table <vpnchecker_allow> persist\n"));
        assert!(!rules.contains("utun"));
        assert!(rules.ends_with("block return out quick all\n"));

        let bad = render(Some(&Via::Interface("utun0 all".into())), &BTreeSet::new());
        assert!(!bad.contains("utun0"));
    }

    #[test]
    fn subnet_rules_for_exit() {
        let vpn: BTreeSet<IpNet> = ["10.4.0.0/16".parse().unwrap()].into();
        let rules = render(Some(&Via::Subnets(vpn)), &allow());
        assert!(rules.starts_with("table <vpnchecker_vpn> persist { 10.4.0.0/16 }\n"));
        assert!(rules.contains("pass out quick from <vpnchecker_vpn> keep state"));
        assert!(rules.ends_with("block return out quick all\n"));
    }

    fn protected() -> BTreeSet<IpNet> {
        ["160.79.104.10/32", "2606:4700::6812:137d/128"].iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn scoped_rules_touch_only_protected_addresses() {
        let rules = render_scoped(Some(&Via::Interface("utun4".into())), &protected());
        assert!(rules.starts_with("table <vpnchecker_protected> persist { 160.79.104.10/32, 2606:4700::6812:137d/128 }\n"));
        let lines: Vec<&str> = rules.lines().collect();
        let pass = lines.iter().position(|l| l.starts_with("pass out quick on utun4 to <vpnchecker_protected>")).unwrap();
        let block = lines.iter().position(|l| *l == "block return out quick to <vpnchecker_protected>").unwrap();
        assert!(pass < block, "the tunnel pass must come before the block");
        assert!(!rules.contains("block return out quick all"), "scoped mode never blocks the whole machine");
        assert!(!rules.contains("port 53"));
    }

    #[test]
    fn scoped_without_vpn_blocks_protected_only() {
        let rules = render_scoped(None, &protected());
        assert!(!rules.contains("pass"));
        assert!(rules.ends_with("block return out quick to <vpnchecker_protected>\n"));
    }

    #[test]
    fn scoped_exit_rules_pass_by_source_subnet() {
        let vpn: BTreeSet<IpNet> = ["10.4.0.0/16".parse().unwrap()].into();
        let rules = render_scoped(Some(&Via::Subnets(vpn)), &protected());
        assert!(rules.contains("pass out quick from <vpnchecker_vpn> to <vpnchecker_protected> keep state"));
    }

    #[test]
    fn scoped_with_nothing_learned_loads_no_rules() {
        assert_eq!(render_scoped(None, &BTreeSet::new()), "");
    }

    #[test]
    fn interface_names_validated() {
        assert!(valid_interface_name("utun12"));
        assert!(!valid_interface_name("utun0 all"));
        assert!(!valid_interface_name(""));
    }
}
