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
/// A setup dialog waits longer: connecting the VPN can take a browser login. The installer package gives the whole
/// setup an hour (pkg/build.sh).
const SETUP_SECS: u64 = 900;

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

/// A question for the user during `vpnchecker setup`.
#[derive(Debug, Clone, Default)]
pub struct Dialog<'a> {
    pub message: &'a str,
    /// One to three buttons (a macOS limit), left to right; the last one is the default.
    pub buttons: &'a [&'a str],
    /// The button, one of `buttons`, that Esc presses. Clicking it counts as [`Reply::Cancelled`].
    pub cancel: Option<&'a str>,
    /// A warning icon instead of the plain one.
    pub caution: bool,
}

/// How a [`Dialog`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// The clicked button.
    Button(String),
    /// The cancel button, Esc, or nobody answered in time.
    Cancelled,
}

/// Shows `dialog` in the GUI session of `uid` and waits for the answer. `None`: it could not be shown (nobody is
/// logged in), which must never be read as an answer.
pub async fn dialog(uid: Option<u32>, dialog: &Dialog<'_>) -> Option<Reply> {
    show(uid, dialog, SETUP_SECS).await
}

async fn show(uid: Option<u32>, dialog: &Dialog<'_>, secs: u64) -> Option<Reply> {
    // Every text travels as an argument, never inside the script: argv is message, cancel, buttons...
    let mut display = String::from(
        "set answer to display dialog (item 1 of argv) with title \"vpnchecker setup\" \
         buttons (items 3 thru -1 of argv) default button (item -1 of argv)",
    );
    if dialog.cancel.is_some() {
        display.push_str(" cancel button (item 2 of argv)");
    }
    display.push_str(&format!(" with icon {} giving up after {secs}", if dialog.caution { "caution" } else { "note" }));
    let result = "return button returned of answer";
    let mut cmd = osascript(uid)?;
    for line in ["on run argv", &display, "if gave up of answer then return \"\"", result, "end run"] {
        cmd.args(["-e", line]);
    }
    cmd.args([dialog.message, dialog.cancel.unwrap_or_default()])
        .args(dialog.buttons)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let out = match timeout(Duration::from_secs(secs + 30), cmd.output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            debug!(error = %e, "dialog failed");
            return None;
        }
        Err(_) => return None,
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    let reply = parse_reply(out.status.success(), &String::from_utf8_lossy(&out.stdout), &stderr);
    if reply.is_none() {
        debug!(stderr = %stderr.trim(), "dialog could not be shown");
    }
    reply
}

/// osascript prints the clicked button; the cancel button makes it fail with error -128.
fn parse_reply(success: bool, stdout: &str, stderr: &str) -> Option<Reply> {
    if !success {
        return stderr.contains("(-128)").then_some(Reply::Cancelled);
    }
    let name = stdout.trim_end_matches('\n');
    Some(if name.is_empty() { Reply::Cancelled } else { Reply::Button(name.to_string()) })
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

    #[test]
    fn dialog_replies() {
        assert_eq!(parse_reply(true, "Whole Mac\n", ""), Some(Reply::Button("Whole Mac".into())));
        // Nobody answered in time.
        assert_eq!(parse_reply(true, "\n", ""), Some(Reply::Cancelled));
        assert_eq!(parse_reply(false, "", "42:99: execution error: User canceled. (-128)\n"), Some(Reply::Cancelled));
        // Not shown at all: never an answer.
        assert_eq!(parse_reply(false, "", "execution error: No user interaction allowed. (-1713)\n"), None);
    }

    /// Run with `cargo test -- --ignored`: shows both kinds of setup dialog for two seconds and lets them time out.
    #[tokio::test]
    #[ignore = "shows dialogs on screen"]
    async fn unanswered_setup_dialogs_mean_cancelled() {
        let message = "vpnchecker test dialog with \"quotes\" and a\nsecond line.\n\nIt closes by itself, do not click.";
        let choice = Dialog {
            message,
            buttons: &["Cancel", "Apps Only", "Whole Mac"],
            cancel: Some("Cancel"),
            ..Dialog::default()
        };
        assert_eq!(show(None, &choice, 2).await, Some(Reply::Cancelled));
        let plain = Dialog {
            message,
            buttons: &["OK"],
            caution: true,
            ..Dialog::default()
        };
        assert_eq!(show(None, &plain, 2).await, Some(Reply::Cancelled));
    }

    /// Run with `cargo test -- --ignored`: shows the real dialog for two seconds and lets it time out.
    #[tokio::test]
    #[ignore = "shows a dialog on screen"]
    async fn an_unanswered_dialog_means_later() {
        let answer = ask(None, "vpnchecker test dialog.\n\nIt closes by itself, do not click.", 2).await;
        assert_eq!(answer, Some(Answer::Later));
    }
}
