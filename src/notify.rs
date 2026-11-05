use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;
use tracing::debug;

use crate::sys;

const BUTTON_UPDATE: &str = "Update";
const BUTTON_LATER: &str = "Later";
const BUTTON_SKIP: &str = "Skip This Version";
/// An unanswered dialog closes by itself after this long and counts as "later".
const ASK_SECS: u64 = 300;

/// What the user chose when asked about a new version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Update,
    Later,
    Skip,
}

/// `osascript` in the GUI session of `uid` (needed when running as root). `None` when there is nobody to show
/// anything to.
fn osascript(uid: Option<u32>) -> Option<Command> {
    if !sys::is_root() {
        return Some(Command::new("/usr/bin/osascript"));
    }
    let uid = uid.filter(|&u| u != 0)?;
    let mut cmd = Command::new("/bin/launchctl");
    cmd.args(["asuser", &uid.to_string(), "/usr/bin/sudo", "-u", &format!("#{uid}"), "/usr/bin/osascript"]);
    Some(cmd)
}

/// Shows a macOS notification.
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
    let Some(mut cmd) = osascript(uid) else {
        return;
    };
    cmd.args(script).kill_on_drop(false);
    if let Err(e) = cmd.spawn() {
        debug!(error = %e, "notification failed");
    }
}

/// Asks the user whether to install a new version and waits for the answer. `None`: nobody could be asked
/// (no GUI session, or the dialog could not be shown), which must never be read as consent.
pub async fn ask_update(uid: Option<u32>, message: &str) -> Option<Answer> {
    ask(uid, message, ASK_SECS).await
}

async fn ask(uid: Option<u32>, message: &str, secs: u64) -> Option<Answer> {
    let dialog = format!(
        "set answer to display dialog (item 1 of argv) with title \"vpnchecker\" \
         buttons {{\"{BUTTON_SKIP}\", \"{BUTTON_LATER}\", \"{BUTTON_UPDATE}\"}} \
         default button \"{BUTTON_UPDATE}\" giving up after {secs}"
    );
    let script = [
        "-e",
        "on run argv",
        "-e",
        dialog.as_str(),
        "-e",
        "if gave up of answer then return \"\"",
        "-e",
        "return button returned of answer",
        "-e",
        "end run",
        message,
    ];
    let mut cmd = osascript(uid)?;
    cmd.args(script).stdin(Stdio::null()).kill_on_drop(true);
    let out = match timeout(Duration::from_secs(secs + 30), cmd.output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            debug!(error = %e, "update dialog failed");
            return None;
        }
        Err(_) => return None,
    };
    if !out.status.success() {
        debug!(stderr = %String::from_utf8_lossy(&out.stderr).trim(), "update dialog could not be shown");
        return None;
    }
    Some(parse_answer(&String::from_utf8_lossy(&out.stdout)))
}

/// Only the exact "Update" button is consent; a timeout or anything unexpected means "later".
fn parse_answer(stdout: &str) -> Answer {
    match stdout.trim() {
        BUTTON_UPDATE => Answer::Update,
        BUTTON_SKIP => Answer::Skip,
        _ => Answer::Later,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_update_button_is_consent() {
        assert_eq!(parse_answer("Update\n"), Answer::Update);
        assert_eq!(parse_answer("Skip This Version\n"), Answer::Skip);
        for other in ["Later\n", "", "\n", "update", "Update now", "button returned:Update", "OK"] {
            assert_eq!(parse_answer(other), Answer::Later, "{other:?}");
        }
    }

    /// Run with `cargo test -- --ignored`: shows the real dialog for two seconds and lets it time out.
    #[tokio::test]
    #[ignore = "shows a dialog on screen"]
    async fn an_unanswered_dialog_means_later() {
        let answer = ask(None, "vpnchecker test dialog.\n\nIt closes by itself, do not click.", 2).await;
        assert_eq!(answer, Some(Answer::Later));
    }
}
