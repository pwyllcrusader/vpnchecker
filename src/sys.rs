use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use nix::unistd::{Uid, User, geteuid, getuid};

pub fn is_root() -> bool {
    geteuid().is_root()
}

pub fn require_root() -> Result<()> {
    if !is_root() {
        bail!("this command requires root, run it with sudo");
    }
    Ok(())
}

/// The real user behind sudo, or the current user.
pub fn invoking_user() -> Result<User> {
    if is_root()
        && let Ok(name) = std::env::var("SUDO_USER")
        && let Some(user) = User::from_name(&name)?
    {
        return Ok(user);
    }
    User::from_uid(getuid())?.context("cannot determine current user")
}

pub fn default_config_path() -> Result<PathBuf> {
    Ok(config_path_of(&invoking_user()?))
}

pub fn config_path_of(user: &User) -> PathBuf {
    user.dir.join(".config/vpnchecker/config.yaml")
}

/// The user logged in at the screen, if any: the owner of the console device (root at the login window).
pub fn console_user() -> Option<User> {
    let uid = file_owner(std::path::Path::new("/dev/console")).filter(|uid| !uid.is_root())?;
    User::from_uid(uid).ok().flatten()
}

pub fn file_owner(path: &std::path::Path) -> Option<Uid> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| Uid::from_raw(m.uid()))
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
