use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nix::unistd::{Gid, Uid, chown};

use crate::{config, dnsproxy, dnsshield, pf, procs, sys};

pub const LABEL: &str = "com.vpnchecker.daemon";
pub const LOG: &str = "/var/log/vpnchecker.log";
const PLIST: &str = "/Library/LaunchDaemons/com.vpnchecker.daemon.plist";
// Root-owned location so a non-root user cannot swap the binary launchd runs as root.
const BIN_DIR: &str = "/Library/PrivilegedHelperTools";
pub const BIN: &str = "/Library/PrivilegedHelperTools/vpnchecker";
// CLI symlink, so `vpnchecker` works in any shell however the daemon was installed (install.sh, cargo install).
const LINK: &str = "/usr/local/bin/vpnchecker";

pub fn install(config_path: &Path, socket: &Path) -> Result<()> {
    sys::require_root()?;
    let config_path = config_path
        .canonicalize()
        .with_context(|| format!("config not found: {} (run `vpnchecker config init`)", config_path.display()))?;
    config::load(&config_path)?;

    unload()?;

    fs::create_dir_all(BIN_DIR)?;
    let tmp = format!("{BIN}.new");
    let _ = fs::remove_file(&tmp);
    fs::copy(std::env::current_exe()?, &tmp).context("copying binary")?;
    // fs::copy clones the source owner on APFS; a user-owned binary run by root would be a privesc.
    chown(Path::new(&tmp), Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).context("chown binary")?;
    fs::set_permissions(&tmp, Permissions::from_mode(0o755))?;
    fs::rename(&tmp, BIN)?;

    fs::write(PLIST, plist(&config_path, socket)).context("writing launchd plist")?;
    chown(Path::new(PLIST), Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).context("chown plist")?;
    fs::set_permissions(PLIST, Permissions::from_mode(0o644))?;
    load()?;
    let cli = match ensure_cli_link() {
        Ok(true) => LINK.to_string(),
        Ok(false) => format!("{BIN} ({LINK} is not a symlink, left alone)"),
        Err(e) => format!("{BIN} (could not link {LINK}: {e:#})"),
    };
    println!(
        "installed {LABEL}\n  binary: {BIN}\n  cli:    {cli}\n  plist:  {PLIST}\n  config: {}\n  log:    {LOG}",
        config_path.display()
    );
    Ok(())
}

/// `/usr/local/bin/vpnchecker` -> the installed binary. Also run after an update: a daemon installed with
/// `sudo vpnchecker install` before 0.1.7 has no link yet, and the installer is never run again.
pub fn ensure_cli_link() -> Result<bool> {
    link_cli(Path::new(BIN), Path::new(LINK))
}

/// Points `link` at `bin`, replacing a symlink that is already there. A regular file at `link` belongs to someone
/// else and is left alone (returns false). The daemon is installed either way: the CLI is then `bin` itself.
fn link_cli(bin: &Path, link: &Path) -> Result<bool> {
    match fs::symlink_metadata(link) {
        Ok(meta) if !meta.file_type().is_symlink() => return Ok(false),
        Ok(_) => fs::remove_file(link).with_context(|| format!("replacing {}", link.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", link.display())),
    }
    if let Some(dir) = link.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::os::unix::fs::symlink(bin, link).with_context(|| format!("linking {}", link.display()))?;
    Ok(true)
}

/// Unfreezes Claude / Cursor / Rider and removes the dns shield: nothing may stay blocked once the daemon is gone.
async fn release_protection(config_path: &Path) {
    let protect = config::protect_or_default(config_path);
    if let Ok(matcher) = procs::Matcher::new(&protect.patterns()) {
        let resumed = procs::resume_all(&matcher).await;
        println!("resumed {resumed} Claude / Cursor / Rider processes");
    }
    let removed = dnsshield::remove_all_system();
    println!("removed {removed} dns shield files");
}

pub async fn uninstall(config_path: &Path, socket: &Path) -> Result<()> {
    sys::require_root()?;
    unload()?;
    release_protection(config_path).await;
    for path in [PLIST, BIN] {
        if let Err(e) = fs::remove_file(path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(e).with_context(|| format!("removing {path}"));
        }
    }
    if fs::read_link(LINK).is_ok_and(|target| target == Path::new(BIN)) {
        let _ = fs::remove_file(LINK);
    }
    pf::flush()?;
    pf::release_saved_token();
    dnsproxy::remove_resolver_files()?;
    let _ = fs::remove_file(socket);
    println!("uninstalled {LABEL}, pf rules removed");
    Ok(())
}

pub fn start() -> Result<()> {
    sys::require_root()?;
    if !Path::new(PLIST).exists() {
        bail!("not installed, run `sudo vpnchecker install`");
    }
    if loaded() {
        launchctl(&["kickstart", &target()])
    } else {
        load()
    }
}

pub async fn stop(config_path: &Path, keep_block: bool) -> Result<()> {
    sys::require_root()?;
    unload()?;
    release_protection(config_path).await;
    // Without the daemon these files would point allowed domains at a dead forwarder.
    dnsproxy::remove_resolver_files()?;
    if keep_block {
        println!("stopped, pf rules kept");
    } else {
        pf::flush()?;
        pf::release_saved_token();
        println!("stopped, pf rules removed");
    }
    Ok(())
}

pub fn restart() -> Result<()> {
    sys::require_root()?;
    if !loaded() {
        return start();
    }
    launchctl(&["kickstart", "-k", &target()])
}

fn target() -> String {
    format!("system/{LABEL}")
}

fn loaded() -> bool {
    Command::new("/bin/launchctl")
        .args(["print", &target()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn wait_loaded(want: bool) -> bool {
    for _ in 0..50 {
        if loaded() == want {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// bootout returns before the job is fully gone; bootstrapping too early fails silently or with EIO.
fn unload() -> Result<()> {
    if loaded() {
        launchctl(&["bootout", &target()])?;
        if !wait_loaded(false) {
            bail!("{LABEL} is still loaded after bootout");
        }
    }
    Ok(())
}

fn load() -> Result<()> {
    launchctl(&["bootstrap", "system", PLIST])?;
    if !wait_loaded(true) {
        bail!("{LABEL} did not start, see {LOG}");
    }
    Ok(())
}

fn launchctl(args: &[&str]) -> Result<()> {
    let out = Command::new("/bin/launchctl").args(args).output()?;
    if !out.status.success() {
        bail!(
            "launchctl {} failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn plist(config: &Path, socket: &Path) -> String {
    let config = xml_escape(&config.display().to_string());
    let socket = xml_escape(&socket.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{BIN}</string>
        <string>--config</string>
        <string>{config}</string>
        <string>--socket</string>
        <string>{socket}</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{LOG}</string>
    <key>StandardErrorPath</key>
    <string>{LOG}</string>
</dict>
</plist>
"#
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_escapes_paths() {
        let p = plist(Path::new("/Users/a&b/.config/vpnchecker/config.yaml"), Path::new("/var/run/x.sock"));
        assert!(p.contains("/Users/a&amp;b/.config"));
        assert!(p.contains("<string>run</string>"));
    }

    #[test]
    fn cli_link_is_created_replaced_and_never_overwrites_a_file() {
        let dir = std::env::temp_dir().join(format!("vpnchecker-link-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let bin = dir.join("bin");
        let link = dir.join("missing-dir").join("vpnchecker");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&bin, b"x").unwrap();

        // Fresh install: parent directory and link are created.
        assert!(link_cli(&bin, &link).unwrap());
        assert_eq!(fs::read_link(&link).unwrap(), bin);
        // A stale link (older install location) is repointed.
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(dir.join("old"), &link).unwrap();
        assert!(link_cli(&bin, &link).unwrap());
        assert_eq!(fs::read_link(&link).unwrap(), bin);
        // A regular file is someone else's and stays untouched.
        fs::remove_file(&link).unwrap();
        fs::write(&link, b"theirs").unwrap();
        assert!(!link_cli(&bin, &link).unwrap());
        assert_eq!(fs::read(&link).unwrap(), b"theirs");

        fs::remove_dir_all(&dir).unwrap();
    }
}
