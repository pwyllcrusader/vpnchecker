use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{Result, bail};
use ipnet::IpNet;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Notify, mpsc};
use tokio::time::{Interval, MissedTickBehavior, interval};
use tracing::{debug, error, info, warn};

use crate::config::{self, Config, GLOBALPROTECT_HOSTS, LEARNED_GATEWAYS};
use crate::detect::{self, VpnState, VpnStatus};
use crate::dnsproxy::{self, Proxy};
use crate::ipc::{self, Control, Shared, Snapshot};
use crate::pf::{self, Pf, Via};
use crate::resolver::{self, Resolver};
use crate::{globalprotect, notify, routewatch, sys};

// Survives restarts so exit rules and reconnects know addresses seen on and off the VPN.
const CACHE: &str = "/var/db/vpnchecker/cache.json";

struct Daemon {
    config_path: PathBuf,
    cfg: Config,
    pf: Pf,
    // Shared with the DNS forwarder; held while the ruleset is reloaded.
    resolver: Arc<Mutex<Resolver>>,
    proxy: Option<Arc<Proxy>>,
    dry_run: bool,
    vpn: VpnStatus,
    shared: Shared,
    notify_uid: Option<u32>,
    user_home: Option<PathBuf>,
    cache: Option<PathBuf>,
    gp_hosts: BTreeSet<String>,
    gp_log_mtime: Option<SystemTime>,
}

pub async fn run(config_path: PathBuf, socket: &Path, dry_run: bool) -> Result<()> {
    if !dry_run && !sys::is_root() {
        bail!("`run` requires root to manage pf; use --dry-run to test without it");
    }
    let cfg = config::load(&config_path)?;
    for w in cfg.warnings() {
        warn!("{w}");
    }
    let notify_uid = sys::file_owner(&config_path).map(|u| u.as_raw());
    let user_home = sys::file_owner(&config_path)
        .and_then(|uid| nix::unistd::User::from_uid(uid).ok().flatten())
        .map(|user| user.dir);

    let mut pf = Pf::new(dry_run);
    pf.enable()?;

    let shared: Shared = Arc::new(Mutex::new(Snapshot {
        pid: std::process::id(),
        config: config_path.display().to_string(),
        dry_run,
        since: sys::now_unix(),
        ..Default::default()
    }));
    let (tx, mut rx) = mpsc::channel(8);
    if let Err(e) = ipc::serve(socket, shared.clone(), tx, notify_uid) {
        warn!("ipc disabled: {e:#}");
    }

    let cache = (!dry_run).then(|| PathBuf::from(CACHE));
    let resolver = Arc::new(Mutex::new(match &cache {
        Some(path) => Resolver::load(path, cfg.check.resolve_retain),
        None => Resolver::new(cfg.check.resolve_retain),
    }));
    let proxy = match Proxy::start(resolver.clone(), dry_run).await {
        Ok(proxy) => Some(proxy),
        Err(e) => {
            warn!("dns forwarder disabled, subdomains of allow.domains are not learned: {e:#}");
            None
        }
    };
    let mut d = Daemon {
        config_path,
        cfg,
        pf,
        resolver,
        proxy,
        dry_run,
        vpn: VpnStatus::default(),
        shared,
        notify_uid,
        user_home,
        cache,
        gp_hosts: BTreeSet::new(),
        gp_log_mtime: None,
    };
    info!("vpnchecker started");

    // Close everything right away with cached addresses, before DNS and detection.
    d.apply();
    d.sync_zones();
    d.check().await;
    d.resolve().await;
    d.apply();

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let route_events = Arc::new(Notify::new());
    match routewatch::spawn(route_events.clone()) {
        Ok(()) => info!("watching routing table changes"),
        Err(e) => warn!("route events disabled, polling only: {e:#}"),
    }
    let (mut check_tick, mut resolve_tick) = d.ticks();

    loop {
        let mut reconfigured = false;
        tokio::select! {
            _ = route_events.notified() => {
                debug!("routing change, rechecking");
                d.refresh_upstreams();
                d.check().await;
            }
            _ = check_tick.tick() => d.check().await,
            _ = resolve_tick.tick() => {
                d.resolve().await;
                d.apply();
            }
            Some(control) = rx.recv() => match control {
                Control::Reload => reconfigured = d.reload().await,
                Control::Recheck => d.check().await,
            },
            _ = sighup.recv() => reconfigured = d.reload().await,
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
        }
        if reconfigured {
            (check_tick, resolve_tick) = d.ticks();
        }
    }

    // The pf token is kept so the exit rules stay active; `vpnchecker stop` releases it.
    info!("exiting, leaving rules that pass only traffic sourced from vpn.subnets");
    d.apply_via(Some(&Via::Subnets(d.cfg.vpn_subnets())));
    d.save_cache();
    if d.proxy.is_some() && !dry_run {
        let _ = dnsproxy::remove_resolver_files();
    }
    let _ = std::fs::remove_file(socket);
    Ok(())
}

impl Daemon {
    fn ticks(&self) -> (Interval, Interval) {
        let mut check = interval(self.cfg.check.interval);
        check.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut resolve = interval(self.cfg.check.resolve_interval);
        resolve.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The first resolve already happened during startup / reload.
        resolve.reset();
        (check, resolve)
    }

    fn apply(&mut self) {
        let via = self.vpn.interface.clone().map(Via::Interface);
        self.apply_via(via.as_ref());
    }

    fn apply_via(&mut self, via: Option<&Via>) {
        let resolver = self.resolver.lock().unwrap();
        let mut allowed = self.cfg.allow_cidrs();
        allowed.extend(resolver.ips(&self.cfg.allow_keys()).into_iter().map(IpNet::from));
        let rules = pf::render(via, &allowed);
        match self.pf.apply(&rules) {
            Ok(true) => info!(?via, allowed = allowed.len(), "pf rules updated"),
            Ok(false) => {}
            Err(e) => error!("applying pf rules failed (will retry): {e:#}"),
        }
        drop(resolver);
        self.shared.lock().unwrap().allowed = allowed.len();
    }

    /// Routes allow.domains (with subdomains) through the DNS forwarder.
    fn sync_zones(&self) {
        let Some(proxy) = &self.proxy else {
            return;
        };
        let zones = &self.cfg.allow.domains;
        proxy.set_zones(zones);
        if self.dry_run {
            info!(?zones, "[dry-run] not writing {}/<zone> files", dnsproxy::RESOLVER_DIR);
        } else if dnsproxy::sync_resolver_files(zones) {
            info!(?zones, "resolver files updated");
            dnsproxy::flush_dns_cache();
        }
    }

    fn refresh_upstreams(&self) {
        if let Some(proxy) = &self.proxy {
            proxy.refresh_upstreams();
        }
    }

    async fn resolve(&mut self) {
        self.refresh_upstreams();
        let resolved = resolver::resolve_all(&self.cfg.allow.domains, self.cfg.check.timeout).await;
        self.resolver.lock().unwrap().learn_resolved(None, &resolved);
        if self.cfg.allow.globalprotect {
            let hosts = globalprotect::discover(self.user_home.as_deref());
            if hosts != self.gp_hosts {
                info!(?hosts, "GlobalProtect portal/gateway hosts");
                self.gp_hosts = hosts;
            }
            let hosts: Vec<&String> = self.gp_hosts.iter().collect();
            let resolved = resolver::resolve_all(&hosts, self.cfg.check.timeout).await;
            self.resolver.lock().unwrap().learn_resolved(Some(GLOBALPROTECT_HOSTS), &resolved);
        }
        self.save_cache();
    }

    /// While blocked, GlobalProtect logs each gateway it tries; allow it before the client retries.
    async fn follow_globalprotect_log(&mut self) {
        if !self.cfg.allow.globalprotect {
            return;
        }
        let mtime = globalprotect::event_log_mtime();
        if mtime != self.gp_log_mtime {
            self.gp_log_mtime = mtime;
            self.resolve().await;
            self.apply();
        }
    }

    fn save_cache(&self) {
        if let Some(path) = &self.cache
            && let Err(e) = self.resolver.lock().unwrap().save(path)
        {
            warn!("saving cache {} failed: {e:#}", path.display());
        }
    }

    fn learn_gateways(&mut self) {
        if !self.cfg.allow.learn_gateways {
            return;
        }
        let Ok(re) = regex::Regex::new(&self.cfg.vpn.interface_pattern) else {
            return;
        };
        let gateways = detect::gateway_routes(&re);
        let new = self.resolver.lock().unwrap().learn(LEARNED_GATEWAYS, gateways.iter().map(|(ip, _)| IpAddr::V4(*ip)));
        if !new.is_empty() {
            info!(?gateways, "learned VPN gateways");
            self.save_cache();
        }
    }

    async fn check(&mut self) {
        let status = detect::detect(&self.cfg).await;
        let previous = self.vpn.state;
        if status.state != previous || status.interface != self.vpn.interface {
            info!(state = ?status.state, interface = ?status.interface, checks = ?status.checks, "vpn status changed");
        }
        self.vpn = status;
        if self.vpn.state == VpnState::Up {
            self.learn_gateways();
        } else {
            self.follow_globalprotect_log().await;
        }
        self.apply();

        let changed = self.vpn.state != previous;
        if changed && self.vpn.state != VpnState::Up {
            self.pf.kill_states_from(&self.cfg.vpn_subnets());
            // DNS now answers off-VPN (split horizon), so the VPN client needs these addresses to reconnect.
            self.resolve().await;
            self.apply();
        }

        let now = sys::now_unix();
        let mut snap = self.shared.lock().unwrap();
        snap.vpn = self.vpn.clone();
        snap.last_check = now;
        if changed {
            snap.since = now;
        }
        drop(snap);

        if changed && self.cfg.notify && !(previous == VpnState::Unknown && self.vpn.state == VpnState::Up) {
            let msg = match self.vpn.state {
                VpnState::Up => "VPN is up: traffic is allowed",
                _ => "VPN is down: internet traffic is blocked",
            };
            notify::send(self.notify_uid, msg);
        }
    }

    async fn reload(&mut self) -> bool {
        match config::load(&self.config_path) {
            Ok(cfg) => {
                for w in cfg.warnings() {
                    warn!("{w}");
                }
                self.resolver.lock().unwrap().set_retain(cfg.check.resolve_retain);
                self.cfg = cfg;
                info!("config reloaded");
                self.sync_zones();
                self.resolve().await;
                self.check().await;
                true
            }
            Err(e) => {
                error!("config reload failed, keeping previous config: {e:#}");
                false
            }
        }
    }
}
