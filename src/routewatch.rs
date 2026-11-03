use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
use tokio::sync::Notify;
use tracing::warn;

// <net/route.h> message types and flags (macOS).
const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTM_CHANGE: u8 = 0x3;
const RTM_NEWADDR: u8 = 0xc;
const RTM_DELADDR: u8 = 0xd;
const RTM_IFINFO: u8 = 0xe;
const RTF_LLINFO: i32 = 0x400;
const RTF_WASCLONED: i32 = 0x20000;

/// Wakes `notify` on kernel route / address / interface changes, so VPN loss is seen in milliseconds.
pub fn spawn(notify: Arc<Notify>) -> Result<()> {
    let fd = socket(AddressFamily::Route, SockType::Raw, SockFlag::empty(), None)
        .context("opening PF_ROUTE socket")?;
    let mut sock = File::from(fd);
    std::thread::Builder::new()
        .name("routewatch".into())
        .spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf) {
                    Ok(n) if is_relevant(&buf[..n]) => notify.notify_one(),
                    Ok(_) => {}
                    Err(e) => {
                        warn!(error = %e, "route socket read failed");
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            }
        })
        .context("spawning routewatch thread")?;
    Ok(())
}

/// Ignores RTM_GET (our own `route get` probes would loop) and per-destination ARP / cloned routes.
fn is_relevant(msg: &[u8]) -> bool {
    if msg.len() < 12 {
        return false;
    }
    let flags = i32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]);
    match msg[3] {
        RTM_ADD | RTM_DELETE | RTM_CHANGE => flags & (RTF_LLINFO | RTF_WASCLONED) == 0,
        RTM_NEWADDR | RTM_DELADDR | RTM_IFINFO => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(kind: u8, flags: i32) -> Vec<u8> {
        let mut m = vec![0u8; 92];
        m[2] = 5;
        m[3] = kind;
        m[8..12].copy_from_slice(&flags.to_ne_bytes());
        m
    }

    #[test]
    fn filters_route_messages() {
        assert!(is_relevant(&msg(RTM_DELETE, 0x803)));
        assert!(is_relevant(&msg(RTM_ADD, 0x803)));
        assert!(is_relevant(&msg(RTM_IFINFO, 0)));
        assert!(is_relevant(&msg(RTM_DELADDR, 0)));
        assert!(!is_relevant(&msg(0x4, 0x803)), "RTM_GET");
        assert!(!is_relevant(&msg(RTM_ADD, RTF_WASCLONED | 0x5)));
        assert!(!is_relevant(&msg(RTM_DELETE, RTF_LLINFO | 0x5)));
        assert!(!is_relevant(&[0u8; 4]));
    }
}
