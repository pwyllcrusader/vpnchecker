use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use tokio::net::lookup_host;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::sys;

/// Keeps every IP seen per key (domain or `@`-prefixed learned set) for `retain`:
/// CDNs rotate addresses and split-horizon DNS answers differ on and off the VPN.
pub struct Resolver {
    seen: HashMap<String, HashMap<IpAddr, u64>>,
    retain: Duration,
}

impl Resolver {
    pub fn new(retain: Duration) -> Self {
        Self {
            seen: HashMap::new(),
            retain,
        }
    }

    pub fn load(path: &Path, retain: Duration) -> Self {
        let mut resolver = Self::new(retain);
        match fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str(&text) {
                Ok(seen) => {
                    resolver.seen = seen;
                    resolver.prune();
                }
                Err(e) => warn!("ignoring corrupt cache {}: {e}", path.display()),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("cannot read cache {}: {e}", path.display()),
        }
        resolver
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec(&self.seen)?)?;
        fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn set_retain(&mut self, retain: Duration) {
        self.retain = retain;
    }

    /// Returns the addresses that were not known before.
    pub fn learn(&mut self, key: &str, ips: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
        let now = sys::now_unix();
        let entry = self.seen.entry(key.to_string()).or_default();
        let mut new = Vec::new();
        for ip in ips {
            if entry.insert(ip, now).is_none() {
                new.push(ip);
            }
        }
        new
    }

    /// Stores lookup results under each host, or all under `key`.
    pub fn learn_resolved(&mut self, key: Option<&str>, resolved: &[(String, Vec<IpAddr>)]) {
        for (host, ips) in resolved {
            if !self.learn(key.unwrap_or(host), ips.iter().copied()).is_empty() {
                info!(%host, ?ips, "new addresses");
            }
        }
        self.prune();
    }

    fn prune(&mut self) {
        let cutoff = sys::now_unix().saturating_sub(self.retain.as_secs());
        for ips in self.seen.values_mut() {
            ips.retain(|_, seen| *seen >= cutoff);
        }
        self.seen.retain(|_, ips| !ips.is_empty());
    }

    pub fn ips<S: AsRef<str>>(&self, keys: &[S]) -> BTreeSet<IpAddr> {
        keys.iter()
            .filter_map(|k| self.seen.get(k.as_ref()))
            .flat_map(|ips| ips.keys().copied())
            .collect()
    }
}

pub async fn resolve(domain: &str, limit: Duration) -> Result<Vec<IpAddr>, String> {
    match timeout(limit, lookup_host((domain, 443))).await {
        Ok(Ok(addrs)) => Ok(addrs.map(|a| a.ip()).collect()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timeout".into()),
    }
}

/// Resolves hosts concurrently; failures are logged and left out.
pub async fn resolve_all<S: AsRef<str>>(hosts: &[S], limit: Duration) -> Vec<(String, Vec<IpAddr>)> {
    let handles: Vec<_> = hosts
        .iter()
        .map(|h| h.as_ref().to_string())
        .map(|host| tokio::spawn(async move { (resolve(&host, limit).await, host) }))
        .collect();
    let mut out = Vec::new();
    for handle in handles {
        match handle.await {
            Ok((Ok(ips), host)) => {
                debug!(%host, ?ips, "resolved");
                out.push((host, ips));
            }
            Ok((Err(e), host)) => debug!(%host, error = %e, "resolve failed"),
            Err(_) => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learns_prunes_and_persists() {
        let mut r = Resolver::new(Duration::from_secs(3600));
        r.learn("a.example", ["1.1.1.1".parse().unwrap()]);
        r.learn("@gateways", ["2.2.2.2".parse().unwrap()]);
        r.seen.get_mut("a.example").unwrap().insert("9.9.9.9".parse().unwrap(), 0);
        r.prune();
        assert_eq!(r.ips(&["a.example"]).len(), 1);
        assert_eq!(r.ips(&["a.example", "@gateways"]).len(), 2);

        let path = std::env::temp_dir().join(format!("vpnchecker-test-{}.json", std::process::id()));
        r.save(&path).unwrap();
        let loaded = Resolver::load(&path, Duration::from_secs(3600));
        assert_eq!(loaded.ips(&["@gateways"]), r.ips(&["@gateways"]));
        let _ = fs::remove_file(path);
    }
}
