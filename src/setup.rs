//! `vpnchecker setup`: the guided first-time setup the installer package runs. It asks one question (what to
//! protect), makes sure the VPN is detected, and only then installs the daemon.

use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use nix::unistd::User;
use regex::Regex;

use crate::config::{self, Config, Mode};
use crate::detect::{self, CheckResult, VpnState};
use crate::notify::{self, Dialog, Reply};
use crate::{launchd, sys};

const WHOLE_MAC: &str = "Whole Mac";
const APPS_ONLY: &str = "Apps Only";
const CANCEL: &str = "Cancel";
const CHECK_AGAIN: &str = "Check Again";
const OK: &str = "OK";

/// Exit code 0: installed; 1: the user cancelled, the daemon was not installed.
pub async fn run(config: Option<PathBuf>, socket: &Path, user: Option<&str>) -> Result<ExitCode> {
    sys::require_root()?;
    let user = target_user(user)?;
    let uid = Some(user.uid.as_raw());
    let config_path = config.unwrap_or_else(|| sys::config_path_of(&user));
    match guided(&user, &config_path, socket).await {
        Ok(true) => {
            notify::send(uid, "vpnchecker is installed and running.");
            Ok(ExitCode::SUCCESS)
        }
        Ok(false) => {
            println!("setup cancelled, the daemon was not installed");
            Ok(ExitCode::from(1))
        }
        Err(e) => {
            let message = format!("vpnchecker could not be set up.\n\n{e:#}");
            let failed = Dialog {
                message: &message,
                buttons: &[OK],
                caution: true,
                ..Dialog::default()
            };
            notify::dialog(uid, &failed).await;
            Err(e)
        }
    }
}

/// Whose config is set up and who is asked: `--user`, else the user behind sudo, else whoever sits at the screen
/// (the installer package runs this as plain root).
fn target_user(name: Option<&str>) -> Result<User> {
    if let Some(name) = name {
        return User::from_name(name)?.with_context(|| format!("no such user: {name}"));
    }
    let invoking = sys::invoking_user()?;
    if !invoking.uid.is_root() {
        return Ok(invoking);
    }
    sys::console_user().context("nobody is logged in at the screen: log in and run the installer again, or pass --user")
}

/// Returns false when the user cancelled.
async fn guided(user: &User, config_path: &Path, socket: &Path) -> Result<bool> {
    let uid = Some(user.uid.as_raw());
    let shown = config_path.display();
    // An installed daemon already has a config its user is happy with: this is an upgrade, nothing to ask.
    let first_install = !launchd::installed();
    let new_config = !config_path.exists();
    if new_config {
        write_as(user, config_path, config::TEMPLATE)?;
        println!("created {shown}");
    }
    let mut text = fs::read_to_string(config_path).with_context(|| format!("reading {shown}"))?;
    let mut cfg = config::parse(&text).with_context(|| format!("invalid config {shown}"))?;

    if first_install {
        // The one question of the setup.
        match notify::dialog(uid, &mode_dialog(cfg.mode, &mode_question(config_path))).await {
            None => println!("no dialog could be shown, keeping mode {}", cfg.mode.as_str()),
            Some(Reply::Cancelled) => return Ok(false),
            Some(Reply::Button(name)) => {
                let mode = if name == WHOLE_MAC { Mode::Full } else { Mode::Scoped };
                if mode != cfg.mode {
                    text = config::set_mode(&text, mode);
                    cfg = save(user, config_path, &text)?;
                    if cfg.mode != mode {
                        bail!("could not set mode in {shown}, edit it manually");
                    }
                }
                println!("mode: {}", cfg.mode.as_str());
            }
        }

        // Started without a detected VPN, the daemon would cut the connection (or freeze the apps) at once.
        // The pool of a config created just now is only the template's guess, so it follows the tunnel that is
        // connected instead of being asked for; a pool somebody wrote is theirs and stays.
        let mut pool_is_a_guess = new_config;
        loop {
            let status = detect::detect(&cfg).await;
            if status.state == VpnState::Up {
                break;
            }
            let tunnels = tunnels(&cfg);
            if pool_is_a_guess {
                let route = detect::default_route_interface(cfg.check.timeout).await;
                if let Some((name, ip)) = routed_outside_pool(&cfg, route.as_deref(), &tunnels) {
                    let pool = suggest_pool(ip);
                    text = config::set_vpn_subnets(&text, &[pool])?;
                    cfg = save(user, config_path, &text)?;
                    if cfg.vpn.subnets != [pool] {
                        bail!("could not set vpn.subnets in {shown}, edit it manually");
                    }
                    println!("vpn.subnets set to {pool}: the default route goes through {name} {ip}");
                    pool_is_a_guess = false;
                    continue;
                }
            }
            let message = vpn_message(&cfg, &status.checks, &tunnels, config_path);
            let wait = Dialog {
                message: &message,
                buttons: &[CANCEL, CHECK_AGAIN],
                cancel: Some(CANCEL),
                caution: true,
            };
            match notify::dialog(uid, &wait).await {
                None => bail!(
                    "the VPN is not detected, so the daemon was not installed: it would {} right away. Connect the \
                     VPN and run the installer again. If it is connected, set vpn.subnets in {shown} to the VPN \
                     address pool.",
                    consequence(cfg.mode)
                ),
                Some(Reply::Cancelled) => return Ok(false),
                Some(Reply::Button(_)) => {}
            }
        }
    } else {
        println!("the daemon is already installed: {shown} stays as it is");
    }

    launchd::install(config_path, socket)?;
    Ok(true)
}

fn mode_question(config_path: &Path) -> String {
    format!(
        "What should vpnchecker restrict while the VPN is down?\n\n\
         {WHOLE_MAC}: nothing leaves this Mac except to hosts you allow, and Claude, Cursor and Rider are paused.\n\n\
         {APPS_ONLY}: only Claude, Cursor and Rider are paused and blocked. Everything else keeps working.\n\n\
         You can change this later: `mode` in {}.",
        config_path.display()
    )
}

/// The mode the config already has is the default button.
fn mode_dialog(current: Mode, question: &str) -> Dialog<'_> {
    Dialog {
        message: question,
        buttons: match current {
            Mode::Full => &[CANCEL, APPS_ONLY, WHOLE_MAC],
            Mode::Scoped => &[CANCEL, WHOLE_MAC, APPS_ONLY],
        },
        cancel: Some(CANCEL),
        ..Dialog::default()
    }
}

fn consequence(mode: Mode) -> &'static str {
    match mode {
        Mode::Full => "block the internet",
        Mode::Scoped => "freeze Claude, Cursor and Rider",
    }
}

fn outside_pool(cfg: &Config, tunnels: &[(String, IpAddr)]) -> Vec<(String, IpAddr)> {
    let inside = |ip: &IpAddr| cfg.vpn.subnets.iter().any(|net| net.contains(ip));
    tunnels.iter().filter(|(_, ip)| !inside(ip)).cloned().collect()
}

/// The tunnel that carries the default route although its address is not in the configured pool: a connected
/// full-tunnel VPN that only the pool keeps from being recognised. IPv4 first, as the pool is usually IPv4.
fn routed_outside_pool(cfg: &Config, route: Option<&str>, tunnels: &[(String, IpAddr)]) -> Option<(String, IpAddr)> {
    let mut candidates = outside_pool(cfg, tunnels);
    candidates.retain(|(name, _)| Some(name.as_str()) == route);
    candidates.sort_by_key(|(_, ip)| ip.is_ipv6());
    candidates.into_iter().next()
}

fn vpn_message(cfg: &Config, checks: &[CheckResult], tunnels: &[(String, IpAddr)], config_path: &Path) -> String {
    let mut message = format!(
        "vpnchecker does not see the VPN, so it is not started yet: it would {} right away.\n\n\
         Connect the VPN, then click {CHECK_AGAIN}.",
        consequence(cfg.mode)
    );
    let outside = outside_pool(cfg, tunnels);
    if !outside.is_empty() {
        let pools = cfg.vpn.subnets.iter().map(IpNet::to_string).collect::<Vec<_>>().join(", ");
        let found = outside.iter().map(|(name, ip)| format!("{name} {ip}")).collect::<Vec<_>>().join(", ");
        message.push_str(&format!(
            "\n\nA tunnel is up with an address outside the configured pool ({pools}): {found}. If that is your VPN, \
             set vpn.subnets in {} to its address pool, then click {CHECK_AGAIN}.",
            config_path.display()
        ));
    }
    message.push_str("\n\nChecks:");
    for check in checks {
        message.push_str(&format!("\n{} {}: {}", if check.ok { "✓" } else { "✗" }, check.name, check.detail));
    }
    message
}

/// Addresses on interfaces that can be the VPN tunnel. macOS keeps several utunN with only a link-local IPv6
/// address (iCloud, Handoff): those say nothing.
fn tunnels(cfg: &Config) -> Vec<(String, IpAddr)> {
    let Ok(pattern) = Regex::new(&cfg.vpn.interface_pattern) else {
        return Vec::new();
    };
    let usable = |ip: &IpAddr| match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local(),
        IpAddr::V6(v6) => !v6.is_loopback() && v6.segments()[0] & 0xffc0 != 0xfe80,
    };
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|iface| pattern.is_match(&iface.name))
        .map(|iface| (iface.name.clone(), iface.ip()))
        .filter(|(_, ip)| usable(ip))
        .collect()
}

/// A pool that contains `ip`: its whole private range, since the VPN hands out a different address each time.
fn suggest_pool(ip: IpAddr) -> IpNet {
    let ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"];
    let private = ranges.iter().filter_map(|r| r.parse::<IpNet>().ok()).find(|net| net.contains(&ip));
    let prefix = if ip.is_ipv4() { 16 } else { 64 };
    private.unwrap_or_else(|| IpNet::new(ip, prefix).map(|net| net.trunc()).unwrap_or_else(|_| IpNet::from(ip)))
}

fn save(user: &User, path: &Path, text: &str) -> Result<Config> {
    let cfg = config::parse(text).context("the edited config does not parse, left unchanged")?;
    write_as(user, path, text)?;
    Ok(cfg)
}

fn as_user(user: &User, program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.uid(user.uid.as_raw()).gid(user.gid.as_raw());
    cmd
}

/// Writes `text` to `path` with the rights of `user`, not of root: the config lives in their home, and root
/// following a symlink planted there would overwrite any file on the Mac. Written in place, so an existing file
/// keeps its owner (the daemon trusts the config owner).
fn write_as(user: &User, path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        let made = as_user(user, "/bin/mkdir").arg("-p").arg(dir).status().context("running mkdir")?;
        if !made.success() {
            bail!("could not create {}", dir.display());
        }
    }
    let mut tee = as_user(user, "/usr/bin/tee")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .context("running tee")?;
    let written = tee.stdin.take().context("tee has no stdin")?.write_all(text.as_bytes());
    let done = tee.wait().context("waiting for tee")?;
    if written.is_err() || !done.success() {
        bail!("could not write {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mode: &str, subnets: &str) -> Config {
        config::parse(&format!("mode: {mode}\nvpn:\n  subnets: [{subnets}]\n")).unwrap()
    }

    fn check(name: &str, ok: bool, detail: &str) -> CheckResult {
        CheckResult {
            name: name.into(),
            ok,
            detail: detail.into(),
        }
    }

    fn tunnel(name: &str, ip: &str) -> (String, IpAddr) {
        (name.to_string(), ip.parse().unwrap())
    }

    #[test]
    fn suggests_the_private_range_of_the_tunnel_address() {
        let pool = |ip: &str| suggest_pool(ip.parse().unwrap()).to_string();
        assert_eq!(pool("10.4.2.247"), "10.0.0.0/8");
        assert_eq!(pool("172.20.1.5"), "172.16.0.0/12");
        assert_eq!(pool("192.168.77.3"), "192.168.0.0/16");
        assert_eq!(pool("100.96.0.7"), "100.64.0.0/10");
        assert_eq!(pool("25.3.4.5"), "25.3.0.0/16");
        assert_eq!(pool("fd12:3456:789a:1::5"), "fd12:3456:789a:1::/64");
    }

    #[test]
    fn the_pool_follows_only_the_tunnel_that_carries_the_default_route() {
        let template = cfg("full", "10.0.0.0/8");
        let tunnels = [tunnel("utun3", "fd00::5"), tunnel("utun4", "fd12::9"), tunnel("utun4", "172.20.1.5")];
        assert_eq!(routed_outside_pool(&template, Some("utun4"), &tunnels), Some(tunnel("utun4", "172.20.1.5")));
        // Not connected (default route on Wi-Fi), or connected and already inside the pool: nothing to change.
        assert_eq!(routed_outside_pool(&template, Some("en0"), &tunnels), None);
        assert_eq!(routed_outside_pool(&template, None, &tunnels), None);
        assert_eq!(routed_outside_pool(&cfg("full", "172.16.0.0/12, fd12::/16"), Some("utun4"), &tunnels), None);
    }

    #[test]
    fn vpn_message_points_at_a_tunnel_outside_the_pool() {
        let checks = [
            check("interface", false, "no interface with an address from vpn.subnets"),
            check("default route", false, "via en0"),
        ];
        let tunnels = [tunnel("utun4", "172.20.1.5")];
        let path = Path::new("/Users/a/.config/vpnchecker/config.yaml");

        let full = vpn_message(&cfg("full", "10.0.0.0/8"), &checks, &tunnels, path);
        assert!(full.contains("would block the internet right away"), "{full}");
        assert!(full.contains("outside the configured pool (10.0.0.0/8): utun4 172.20.1.5"), "{full}");
        assert!(full.contains("set vpn.subnets in /Users/a/.config/vpnchecker/config.yaml"), "{full}");
        assert!(full.contains("✗ default route: via en0"), "{full}");

        // The address is inside the pool: the pool is not the problem, so it is not mentioned.
        let scoped = vpn_message(&cfg("scoped", "172.16.0.0/12"), &checks, &tunnels, path);
        assert!(scoped.contains("would freeze Claude, Cursor and Rider right away"), "{scoped}");
        assert!(!scoped.contains("outside the configured pool"), "{scoped}");
        assert!(!vpn_message(&cfg("full", "10.0.0.0/8"), &checks, &[], path).contains("outside"));
    }

    #[test]
    fn the_current_mode_is_the_default_button() {
        assert_eq!(mode_dialog(Mode::Full, "?").buttons.last(), Some(&WHOLE_MAC));
        assert_eq!(mode_dialog(Mode::Scoped, "?").buttons.last(), Some(&APPS_ONLY));
        assert_eq!(mode_dialog(Mode::Scoped, "?").cancel, Some(CANCEL));
    }

    #[test]
    fn writes_the_config_as_the_user_and_in_place() {
        use std::os::unix::fs::MetadataExt;
        let me = User::from_uid(nix::unistd::getuid()).unwrap().unwrap();
        let dir = std::env::temp_dir().join(format!("vpnchecker-setup-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("config.yaml");

        write_as(&me, &path, config::TEMPLATE).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), config::TEMPLATE);
        let inode = fs::metadata(&path).unwrap().ino();
        let cfg = save(&me, &path, &config::set_mode(config::TEMPLATE, Mode::Scoped)).unwrap();
        assert_eq!(cfg.mode, Mode::Scoped);
        assert_eq!(config::load(&path).unwrap().mode, Mode::Scoped);
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode, "rewritten in place, not replaced");
        // A text that does not parse never reaches the file.
        assert!(save(&me, &path, "vpn: [").is_err());
        assert_eq!(config::load(&path).unwrap().mode, Mode::Scoped);

        fs::remove_dir_all(&dir).unwrap();
    }
}
