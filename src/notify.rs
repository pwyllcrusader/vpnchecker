use tokio::process::Command;
use tracing::debug;

use crate::sys;

/// Shows a macOS notification in the GUI session of `uid` (needed when running as root).
pub fn send(uid: Option<u32>, message: &str) {
    let script = [
        "-e",
        "on run argv",
        "-e",
        "display notification (item 1 of argv) with title \"vpnchecker\"",
        "-e",
        "end run",
        message,
    ];
    let mut cmd = if sys::is_root() {
        let Some(uid) = uid.filter(|&u| u != 0) else {
            return;
        };
        let mut cmd = Command::new("/bin/launchctl");
        cmd.args(["asuser", &uid.to_string(), "/usr/bin/sudo", "-u", &format!("#{uid}"), "/usr/bin/osascript"]);
        cmd
    } else {
        Command::new("/usr/bin/osascript")
    };
    cmd.args(script).kill_on_drop(false);
    if let Err(e) = cmd.spawn() {
        debug!(error = %e, "notification failed");
    }
}
