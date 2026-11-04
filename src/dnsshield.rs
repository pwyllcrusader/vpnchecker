use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// First line of every resolver file we write; files without it are never touched.
pub const MARKER: &str = "# managed by vpnchecker - removed when the VPN is up";
const RESOLVER_DIR: &str = "/etc/resolver";

/// While the VPN is down, lookups for the protected domains are sent to a local responder that refuses them
/// (macOS per-domain resolvers, resolver(5)). The query never reaches the network, so the ISP / router
/// never sees `api.anthropic.com` or `*.cursor.sh`.
pub struct DnsShield {
    dir: PathBuf,
    domains: Vec<String>,
    port: u16,
    dry_run: bool,
    active: bool,
}

impl DnsShield {
    pub fn new(domains: Vec<String>, port: u16, dry_run: bool) -> Self {
        Self::with_dir(PathBuf::from(RESOLVER_DIR), domains, port, dry_run)
    }

    pub fn with_dir(dir: PathBuf, domains: Vec<String>, port: u16, dry_run: bool) -> Self {
        Self { dir, domains, port, dry_run, active: false }
    }

    pub fn active(&self) -> bool {
        self.active
    }

    pub fn configure(&mut self, domains: Vec<String>, port: u16) {
        if self.active && (self.domains != domains || self.port != port) {
            self.disable();
        }
        self.domains = domains;
        self.port = port;
    }

    /// Returns true if anything changed.
    pub fn enable(&mut self) -> bool {
        if self.active {
            return false;
        }
        self.active = true;
        if self.dry_run {
            info!(domains = ?self.domains, "[dry-run] dns shield on");
            return false;
        }
        if let Err(e) = fs::create_dir_all(&self.dir) {
            warn!("dns shield: cannot create {}: {e}", self.dir.display());
            return false;
        }
        let content = resolver_file(self.port);
        let mut changed = false;
        for domain in &self.domains {
            let path = self.dir.join(domain);
            match fs::read_to_string(&path) {
                Ok(existing) if !existing.starts_with(MARKER) => {
                    warn!("dns shield: {} exists and is not ours, leaving it alone", path.display());
                    continue;
                }
                Ok(existing) if existing == content => continue,
                _ => {}
            }
            match fs::write(&path, &content).and_then(|()| fs::set_permissions(&path, fs::Permissions::from_mode(0o644))) {
                Ok(()) => changed = true,
                Err(e) => warn!("dns shield: writing {} failed: {e}", path.display()),
            }
        }
        if changed {
            flush_dns_cache();
            info!(domains = ?self.domains, "dns shield on: lookups for these domains stay on this Mac");
        }
        changed
    }

    pub fn disable(&mut self) -> bool {
        let was = std::mem::replace(&mut self.active, false);
        if self.dry_run {
            if was {
                info!("[dry-run] dns shield off");
            }
            return false;
        }
        let removed = remove_all(&self.dir);
        if removed > 0 {
            flush_dns_cache();
            info!("dns shield off");
        }
        removed > 0
    }
}

pub fn resolver_file(port: u16) -> String {
    format!("{MARKER}\nnameserver 127.0.0.1\nport {port}\n")
}

/// Removes every resolver file carrying our marker. Returns how many were removed.
pub fn remove_all(dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let ours = fs::read_to_string(&path).is_ok_and(|text| text.starts_with(MARKER));
        if ours && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// For `stop` / `uninstall`.
pub fn remove_all_system() -> usize {
    let removed = remove_all(Path::new(RESOLVER_DIR));
    if removed > 0 {
        flush_dns_cache();
    }
    removed
}

fn flush_dns_cache() {
    let _ = Command::new("/usr/bin/dscacheutil").arg("-flushcache").output();
    let _ = Command::new("/usr/bin/killall").args(["-HUP", "mDNSResponder"]).output();
}

/// DNS reply that refuses the query (RCODE 5): no data, nothing cached negatively, the lookup fails at once.
pub fn refused_reply(req: &[u8]) -> Option<Vec<u8>> {
    if req.len() < 12 || req[2] & 0x80 != 0 {
        return None; // too short, or already a response
    }
    let mut pos = 12;
    loop {
        let len = *req.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression pointers do not occur in a question
        }
        pos += 1 + len;
    }
    let end = pos.checked_add(4)?; // QTYPE + QCLASS
    if end > req.len() {
        return None;
    }
    let mut reply = req[..end].to_vec();
    reply[2] = 0x80 | (req[2] & 0x79); // QR=1, keep opcode and RD, clear AA/TC
    reply[3] = 0x80 | 5; // RA, RCODE=REFUSED
    reply[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    reply[6..12].fill(0); // AN / NS / AR counts
    Some(reply)
}

/// Local responder for the shielded domains. Cheap enough to run for the whole life of the daemon.
pub async fn serve(port: u16) -> Result<()> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .with_context(|| format!("binding 127.0.0.1:{port} for the dns shield"))?;
    let socket = Arc::new(socket);
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    if let Some(reply) = refused_reply(&buf[..n]) {
                        debug!(%peer, "dns shield refused a lookup");
                        let _ = socket.send_to(&reply, peer).await;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "dns shield socket error");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vpnchecker-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// Query for api.anthropic.com A IN, with an EDNS OPT record appended.
    fn query() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        for label in ["api", "anthropic", "com"] {
            q.push(label.len() as u8);
            q.extend(label.as_bytes());
        }
        q.extend([0, 0, 1, 0, 1]);
        q.extend([0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]); // OPT
        q
    }

    #[test]
    fn refuses_a_query_and_drops_additional_records() {
        let reply = refused_reply(&query()).unwrap();
        assert_eq!(&reply[..2], &[0x12, 0x34], "id is echoed");
        assert_eq!(reply[2] & 0x80, 0x80, "QR");
        assert_eq!(reply[2] & 0x01, 0x01, "RD is kept");
        assert_eq!(reply[3] & 0x0f, 5, "REFUSED");
        assert_eq!(&reply[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reply.len(), 35, "header + question only");
    }

    #[tokio::test]
    async fn responder_refuses_over_real_udp() {
        let port = {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        serve(port).await.unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query(), ("127.0.0.1", port)).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("reply within 2s")
            .unwrap();
        assert_eq!(&buf[..2], &[0x12, 0x34]);
        assert_eq!(buf[3] & 0x0f, 5, "REFUSED");
        assert_eq!(n, 35);
    }

    #[test]
    fn ignores_responses_and_garbage() {
        let mut response = query();
        response[2] |= 0x80;
        assert!(refused_reply(&response).is_none());
        assert!(refused_reply(&[1, 2, 3]).is_none());
        assert!(refused_reply(&query()[..16]).is_none(), "truncated question");
    }

    #[test]
    fn writes_and_removes_only_our_files() {
        let dir = tmp("shield");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("claude.ai"), "nameserver 10.0.0.1\n").unwrap(); // someone else's
        let mut shield = DnsShield::with_dir(dir.clone(), vec!["anthropic.com".into(), "claude.ai".into()], 5399, false);

        assert!(shield.enable());
        assert!(shield.active());
        assert_eq!(fs::read_to_string(dir.join("anthropic.com")).unwrap(), resolver_file(5399));
        assert_eq!(fs::read_to_string(dir.join("claude.ai")).unwrap(), "nameserver 10.0.0.1\n", "foreign file untouched");
        assert!(!shield.enable(), "idempotent");

        assert!(shield.disable());
        assert!(!dir.join("anthropic.com").exists());
        assert!(dir.join("claude.ai").exists(), "foreign file survives disable");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dry_run_touches_nothing() {
        let dir = tmp("dry");
        let mut shield = DnsShield::with_dir(dir.clone(), vec!["anthropic.com".into()], 5399, true);
        shield.enable();
        assert!(!dir.exists());
    }

    #[test]
    fn remove_all_ignores_a_missing_dir() {
        assert_eq!(remove_all(Path::new("/nonexistent/vpnchecker")), 0);
    }
}
