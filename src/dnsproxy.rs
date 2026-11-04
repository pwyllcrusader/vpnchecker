use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::covering_zone;
use crate::pf;
use crate::resolver::Resolver;

pub const PORT: u16 = 10053;
const LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), PORT);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_IDLE: Duration = Duration::from_secs(10);
pub const RESOLVER_DIR: &str = "/etc/resolver";
const MARKER: &str = "# managed by vpnchecker";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Upstream {
    domain: Option<String>,
    servers: Vec<SocketAddr>,
}

/// DNS forwarder for allow.domains: /etc/resolver/<zone> sends every subdomain here, and the
/// answer's addresses enter the pf allow table before the client gets the answer.
pub struct Proxy {
    zones: RwLock<Vec<String>>,
    upstreams: RwLock<Vec<Upstream>>,
    resolver: Arc<Mutex<Resolver>>,
    dry_run: bool,
}

impl Proxy {
    pub async fn start(resolver: Arc<Mutex<Resolver>>, dry_run: bool) -> Result<Arc<Self>> {
        let udp = UdpSocket::bind(LISTEN).await.with_context(|| format!("binding udp {LISTEN}"))?;
        let tcp = TcpListener::bind(LISTEN).await.with_context(|| format!("binding tcp {LISTEN}"))?;
        let proxy = Arc::new(Self {
            zones: RwLock::new(Vec::new()),
            upstreams: RwLock::new(Vec::new()),
            resolver,
            dry_run,
        });
        proxy.refresh_upstreams();
        tokio::spawn(serve_udp(proxy.clone(), Arc::new(udp)));
        tokio::spawn(serve_tcp(proxy.clone(), tcp));
        info!("dns forwarder listening on {LISTEN}");
        Ok(proxy)
    }

    pub fn set_zones(&self, zones: &[String]) {
        *self.zones.write().unwrap() = zones.to_vec();
    }

    /// Re-reads the system DNS configuration (it changes with the network and the VPN).
    pub fn refresh_upstreams(&self) {
        let upstreams = match Command::new("/usr/sbin/scutil").arg("--dns").output() {
            Ok(out) => parse_scutil(&String::from_utf8_lossy(&out.stdout)),
            Err(e) => {
                warn!("scutil --dns failed: {e}");
                return;
            }
        };
        let mut current = self.upstreams.write().unwrap();
        if *current != upstreams {
            debug!(?upstreams, "dns upstreams");
            *current = upstreams;
        }
    }

    fn upstream_for(&self, name: &str) -> Vec<SocketAddr> {
        let upstreams = self.upstreams.read().unwrap();
        upstreams
            .iter()
            .filter(|u| u.domain.as_deref().is_some_and(|d| in_zone(name, d)))
            .max_by_key(|u| u.domain.as_ref().map_or(0, String::len))
            .or_else(|| upstreams.iter().find(|u| u.domain.is_none()))
            .map(|u| u.servers.clone())
            .unwrap_or_default()
    }

    async fn answer(&self, query: &[u8], tcp: bool) -> Vec<u8> {
        let Some(name) = question_name(query) else {
            return servfail(query);
        };
        let mut servers = self.upstream_for(&name);
        if servers.is_empty() {
            self.refresh_upstreams();
            servers = self.upstream_for(&name);
        }
        for server in servers {
            // UDP first even for TCP clients: some VPN DNS servers do not answer over TCP.
            let mut result = forward_udp(server, query).await;
            if tcp
                && let Ok(response) = &result
                && response[2] & 0x02 != 0
                && let Ok(full) = forward_tcp(server, query).await
            {
                result = Ok(full);
            }
            match result {
                Ok(response) => {
                    self.learn(&name, &response).await;
                    return response;
                }
                Err(e) => debug!(%name, %server, error = %e, "upstream failed"),
            }
        }
        servfail(query)
    }

    async fn learn(&self, name: &str, response: &[u8]) {
        let ips = answer_ips(response);
        let zone = covering_zone(&self.zones.read().unwrap(), name).map(str::to_string);
        let Some(zone) = zone.filter(|_| !ips.is_empty()) else {
            return;
        };
        let resolver = self.resolver.clone();
        let dry_run = self.dry_run;
        let name = name.to_string();
        // Under the resolver lock so a concurrent full ruleset reload cannot drop the new addresses.
        let _ = tokio::task::spawn_blocking(move || {
            let mut resolver = resolver.lock().unwrap();
            let new = resolver.learn(&zone, ips);
            if new.is_empty() {
                return;
            }
            info!(%zone, %name, ?new, "learned addresses");
            if !dry_run && let Err(e) = pf::allow_add(&new) {
                warn!("adding learned addresses to pf failed: {e:#}");
            }
        })
        .await;
    }
}

async fn serve_udp(proxy: Arc<Proxy>, socket: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                debug!(error = %e, "dns udp recv failed");
                continue;
            }
        };
        let query = buf[..len].to_vec();
        let (proxy, socket) = (proxy.clone(), socket.clone());
        tokio::spawn(async move {
            let response = proxy.answer(&query, false).await;
            let _ = socket.send_to(&response, peer).await;
        });
    }
}

async fn serve_tcp(proxy: Arc<Proxy>, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(serve_tcp_client(proxy.clone(), stream));
            }
            Err(e) => debug!(error = %e, "dns tcp accept failed"),
        }
    }
}

async fn serve_tcp_client(proxy: Arc<Proxy>, mut stream: TcpStream) {
    loop {
        let Ok(Ok(len)) = timeout(TCP_IDLE, stream.read_u16()).await else {
            return;
        };
        let mut query = vec![0u8; len.into()];
        if stream.read_exact(&mut query).await.is_err() {
            return;
        }
        let response = proxy.answer(&query, true).await;
        let Ok(len) = u16::try_from(response.len()) else {
            return;
        };
        if stream.write_all(&len.to_be_bytes()).await.is_err() || stream.write_all(&response).await.is_err() {
            return;
        }
    }
}

async fn forward_udp(server: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let bind: SocketAddr = match server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(server).await?;
    socket.send(query).await?;
    let mut buf = vec![0u8; 65535];
    timeout(UPSTREAM_TIMEOUT, async {
        loop {
            let len = socket.recv(&mut buf).await?;
            if len >= 12 && buf[..2] == query[..2] {
                return Ok(buf[..len].to_vec());
            }
        }
    })
    .await
    .context("timeout")?
}

async fn forward_tcp(server: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(query.len())?;
    timeout(UPSTREAM_TIMEOUT, async {
        let mut stream = TcpStream::connect(server).await?;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(query).await?;
        let len = stream.read_u16().await?;
        let mut buf = vec![0u8; len.into()];
        stream.read_exact(&mut buf).await?;
        Ok(buf)
    })
    .await
    .context("timeout")?
}

fn in_zone(name: &str, zone: &str) -> bool {
    name == zone || name.strip_suffix(zone).is_some_and(|p| p.ends_with('.'))
}

fn servfail(query: &[u8]) -> Vec<u8> {
    let mut response = query.to_vec();
    if response.len() >= 12 {
        response[2] |= 0x80;
        response[3] = 0x80 | 2;
    }
    response
}

fn read_u16(msg: &[u8], pos: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]).into())
}

/// Reads a (possibly compressed) name; returns it lowercased and the offset right after it.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    for _ in 0..128 {
        let len = usize::from(*msg.get(pos)?);
        match len & 0xC0 {
            0xC0 => {
                end.get_or_insert(pos + 2);
                pos = ((len & 0x3F) << 8) | usize::from(*msg.get(pos + 1)?);
            }
            0 if len == 0 => return Some((name, end.unwrap_or(pos + 1))),
            0 => {
                let label = msg.get(pos + 1..pos + 1 + len)?;
                if !label.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_') || name.len() > 253 {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|c| char::from(c.to_ascii_lowercase())));
                pos += 1 + len;
            }
            _ => return None,
        }
    }
    None
}

fn question_name(msg: &[u8]) -> Option<String> {
    if read_u16(msg, 4)? == 0 {
        return None;
    }
    read_name(msg, 12).map(|(name, _)| name)
}

/// A and AAAA records from the answer section (CNAME targets included, they are in the same section).
fn answer_ips(msg: &[u8]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    let _ = (|| -> Option<()> {
        let (questions, answers) = (read_u16(msg, 4)?, read_u16(msg, 6)?);
        let mut pos = 12;
        for _ in 0..questions {
            pos = read_name(msg, pos)?.1 + 4;
        }
        for _ in 0..answers {
            pos = read_name(msg, pos)?.1;
            let (rtype, rdlen) = (read_u16(msg, pos)?, read_u16(msg, pos + 8)?);
            let rdata = msg.get(pos + 10..pos + 10 + rdlen)?;
            match (rtype, rdata.len()) {
                (1, 4) => ips.push(IpAddr::from(<[u8; 4]>::try_from(rdata).ok()?)),
                (28, 16) => ips.push(IpAddr::from(<[u8; 16]>::try_from(rdata).ok()?)),
                _ => {}
            }
            pos += 10 + rdlen;
        }
        Some(())
    })();
    ips
}

/// Default and per-domain resolvers from `scutil --dns`, minus mDNS and this forwarder.
fn parse_scutil(text: &str) -> Vec<Upstream> {
    let main = text.split("DNS configuration (for scoped queries)").next().unwrap_or_default();
    let mut out = Vec::new();
    for block in main.split("resolver #").skip(1) {
        let (mut domain, mut ips, mut port, mut mdns) = (None, Vec::<IpAddr>::new(), 53, false);
        for line in block.lines() {
            let Some((key, value)) = line.split_once(" : ") else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "domain" => domain = Some(value.trim_end_matches('.').to_ascii_lowercase()),
                "port" => port = value.parse().unwrap_or(53),
                "options" => mdns |= value.contains("mdns"),
                k if k.starts_with("nameserver[") => ips.extend(value.parse::<IpAddr>()),
                _ => {}
            }
        }
        let servers: Vec<SocketAddr> = ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .filter(|s| *s != LISTEN)
            .collect();
        if !mdns && !servers.is_empty() {
            out.push(Upstream { domain, servers });
        }
    }
    out
}

fn resolver_file() -> String {
    format!("{MARKER}\nnameserver 127.0.0.1\nport {PORT}\n")
}

fn is_managed(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|text| text.starts_with(MARKER))
}

/// Points the system resolver at the forwarder for each zone. Returns true if anything changed.
pub fn sync_resolver_files(zones: &[String]) -> bool {
    let dir = Path::new(RESOLVER_DIR);
    let mut changed = false;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !zones.contains(&name) && is_managed(&entry.path()) {
                match fs::remove_file(entry.path()) {
                    Ok(()) => changed = true,
                    Err(e) => warn!("removing {} failed: {e}", entry.path().display()),
                }
            }
        }
    }
    if zones.is_empty() {
        return changed;
    }
    if let Err(e) = fs::create_dir_all(dir) {
        warn!("creating {RESOLVER_DIR} failed: {e}");
        return changed;
    }
    let content = resolver_file();
    for zone in zones {
        let path = dir.join(zone);
        match fs::read_to_string(&path) {
            Ok(text) if text == content => {}
            Ok(text) if !text.starts_with(MARKER) => {
                warn!("{} is not managed by vpnchecker, subdomains of {zone} are not learned", path.display());
            }
            _ => match fs::write(&path, &content) {
                Ok(()) => changed = true,
                Err(e) => warn!("writing {} failed: {e}", path.display()),
            },
        }
    }
    changed
}

/// Status of /etc/resolver/<zone> for diagnostics.
pub fn resolver_file_state(zone: &str) -> &'static str {
    let path = Path::new(RESOLVER_DIR).join(zone);
    match fs::read_to_string(&path) {
        Ok(text) if text == resolver_file() => "forwarder",
        Ok(_) => "foreign /etc/resolver file",
        Err(_) => "no /etc/resolver file",
    }
}

/// Drops cached answers so apps re-resolve through the new /etc/resolver files.
pub fn flush_dns_cache() {
    for (cmd, args) in [("/usr/bin/dscacheutil", &["-flushcache"][..]), ("/usr/bin/killall", &["-HUP", "mDNSResponder"][..])] {
        if let Err(e) = Command::new(cmd).args(args).status() {
            warn!("{cmd} failed: {e}");
        }
    }
}

/// Removes this forwarder's /etc/resolver files (stop / uninstall).
pub fn remove_resolver_files() -> Result<()> {
    if sync_resolver_files(&[]) {
        flush_dns_cache();
    }
    let left: Vec<String> = fs::read_dir(RESOLVER_DIR)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| is_managed(&e.path()))
        .map(|e| e.path().display().to_string())
        .collect();
    if !left.is_empty() {
        bail!("could not remove {}", left.join(", "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str) -> Vec<u8> {
        let mut msg = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend(label.as_bytes());
        }
        msg.extend([0, 0, 1, 0, 1]);
        msg
    }

    #[test]
    fn parses_answers_with_compression_and_cname() {
        let mut msg = query("www.Example.com");
        msg[2] = 0x81;
        msg[7] = 3;
        // www.example.com CNAME cdn.example.com
        msg.extend([0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, b'c', b'd', b'n', 0xC0, 16]);
        let cdn = msg.len() - 6;
        // cdn.example.com A 93.184.216.34
        msg.extend([0xC0, cdn as u8, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        // cdn.example.com AAAA 2001:db8::1
        msg.extend([0xC0, cdn as u8, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        msg.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        assert_eq!(question_name(&msg).as_deref(), Some("www.example.com"));
        let ips = answer_ips(&msg);
        assert_eq!(ips, ["93.184.216.34".parse::<IpAddr>().unwrap(), "2001:db8::1".parse().unwrap()]);
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(question_name(&[0; 5]), None);
        let mut looped = query("a.com");
        looped.truncate(12);
        looped.extend([0xC0, 12]);
        assert_eq!(question_name(&looped), None);
        assert!(answer_ips(&looped).is_empty());
        assert_eq!(question_name(&query("a/b.com")), None);
        assert_eq!(servfail(&query("a.com"))[3] & 0x0F, 2);
    }

    #[test]
    fn scutil_upstreams() {
        let text = "DNS configuration\n\nresolver #1\n  search domain[0] : lan\n  nameserver[0] : 192.168.1.1\n  nameserver[1] : fe80::1%en0\n  flags    : Request A records\n\nresolver #2\n  domain   : local\n  options  : mdns\n\nresolver #3\n  domain   : example.com\n  nameserver[0] : 127.0.0.1\n  port     : 10053\n\nresolver #4\n  domain   : corp.example\n  nameserver[0] : 10.0.0.53\n  nameserver[1] : 2001:db8::53\n\nDNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : 8.8.8.8\n";
        let ups = parse_scutil(text);
        assert_eq!(ups.len(), 2);
        assert_eq!(ups[0], Upstream { domain: None, servers: vec!["192.168.1.1:53".parse().unwrap()] });
        assert_eq!(ups[1].domain.as_deref(), Some("corp.example"));
        assert_eq!(ups[1].servers[1], "[2001:db8::53]:53".parse().unwrap());

        let proxy = Proxy {
            zones: RwLock::new(Vec::new()),
            upstreams: RwLock::new(ups),
            resolver: Arc::new(Mutex::new(Resolver::new(Duration::from_secs(60)))),
            dry_run: true,
        };
        assert_eq!(proxy.upstream_for("a.corp.example")[0], "10.0.0.53:53".parse().unwrap());
        assert_eq!(proxy.upstream_for("www.example.com")[0], "192.168.1.1:53".parse().unwrap());
    }
}
