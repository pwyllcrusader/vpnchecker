use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, bail};
use ipnet::IpNet;
use nix::sys::signal::Signal;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Notify, mpsc};
use tokio::time::{Interval, MissedTickBehavior, interval};
use tracing::{debug, error, info, warn};

use crate::config::{
    self, Action, Config, GLOBALPROTECT_HOSTS, GP_GATEWAY, LEARNED_GATEWAYS, Mode, OBSERVED, PROTECTED_HOSTS,
};
use crate::detect::{self, VpnState, VpnStatus};
use crate::dnsproxy::{self, Proxy};
use crate::dnsshield::{self, DnsShield};
use crate::guard::{Change, Guard, Protection};
use crate::ipc::{self, Control, Shared, Snapshot};
use crate::pf::{self, Pf, Via};
use crate::procs::{self, Matcher};
use crate::resolver::{self, Resolver};
use crate::{globalprotect, launchd, notify, routewatch, sys, update};

// Survives restarts so exit rules and reconnects know addresses seen on and off the VPN.
const CACHE: &str = "/var/db/vpnchecker/cache.json";
// The first update check waits until the daemon has settled; afterwards `update.interval` applies. The poll only
// compares two instants, so it is frequent: it decides how punctual the first check is and how soon a check that
// was due while the VPN was down is caught up.
const FIRST_UPDATE_CHECK: Duration = Duration::from_secs(5 * 60);
const UPDATE_POLL: Duration = Duration::from_secs(60);

struct Daemon {
    config_path: PathBuf,
    cfg: Config,
    pf: Pf,
    // Shared with the DNS forwarder; held while the ruleset is reloaded.
    resolver: Arc<Mutex<Resolver>>,
    proxy: Option<Arc<Proxy>>,
    vpn: VpnStatus,
    shared: Shared,
    notify_uid: Option<u32>,
    user_home: Option<PathBuf>,
    cache: Option<PathBuf>,
    gp_hosts: BTreeSet<String>,
    gp_log_mtime: Option<SystemTime>,
    /// Gateway host GlobalProtect last reported; a change means a reconnect to another gateway.
    gp_gateway: Option<String>,
    dry_run: bool,
    guard: Guard,
    matcher: Matcher,
    shield: DnsShield,
    shield_ready: bool,
    frozen: usize,
    block_ticks: u32,
    last_tick: SystemTime,
    /// True between a block and the following resume, so "resumed" is only announced after a real block.
    announce_resume: bool,
    /// This process is the installed daemon and may replace its own binary.
    self_update: bool,
    next_update: Instant,
    updating: Arc<AtomicBool>,
    control: mpsc::Sender<Control>,
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

    // Only the installed daemon replaces itself: a foreground `run` from a build directory never does.
    let self_update = !dry_run && std::env::current_exe().is_ok_and(|exe| exe == Path::new(launchd::BIN));
    let shared: Shared = Arc::new(Mutex::new(Snapshot {
        pid: std::process::id(),
        config: config_path.display().to_string(),
        dry_run,
        since: sys::now_unix(),
        version: update::CURRENT.to_string(),
        auto_update: self_update && cfg.update.auto,
        update_confirm: cfg.update.confirm,
        ..Default::default()
    }));
    let (tx, mut rx) = mpsc::channel(8);
    if let Err(e) = ipc::serve(socket, shared.clone(), tx.clone(), notify_uid) {
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
    let matcher = Matcher::new(&cfg.protect.patterns())?;
    let shield = DnsShield::new(cfg.protect.domains.clone(), cfg.protect.dns_port, dry_run);
    let shield_ready = if cfg.protect.dns_shield && !dry_run {
        match dnsshield::serve(cfg.protect.dns_port).await {
            Ok(()) => true,
            Err(e) => {
                warn!("dns shield disabled: {e:#}");
                false
            }
        }
    } else {
        cfg.protect.dns_shield
    };
    let mut d = Daemon {
        config_path,
        cfg,
        pf,
        resolver,
        proxy,
        vpn: VpnStatus::default(),
        shared,
        notify_uid,
        user_home,
        cache,
        gp_hosts: BTreeSet::new(),
        gp_log_mtime: None,
        gp_gateway: None,
        dry_run,
        guard: Guard::default(),
        matcher,
        shield,
        shield_ready,
        frozen: 0,
        block_ticks: 0,
        last_tick: SystemTime::now(),
        announce_resume: false,
        self_update,
        next_update: Instant::now() + FIRST_UPDATE_CHECK,
        updating: Arc::new(AtomicBool::new(false)),
        control: tx,
    };
    info!(version = update::CURRENT, mode = ?d.cfg.mode, action = ?d.cfg.protect.action, "vpnchecker started");
    if d.cfg.update.auto && !self_update && !dry_run {
        info!("auto-update is inactive: this process does not run from {}", launchd::BIN);
    }

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
    let (mut check_tick, mut resolve_tick, mut protect_tick) = d.ticks();
    let mut update_tick = interval(UPDATE_POLL);
    update_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        let mut reconfigured = false;
        tokio::select! {
            _ = route_events.notified() => {
                debug!("routing change, rechecking");
                d.refresh_upstreams();
                d.check().await;
            }
            _ = check_tick.tick() => d.check().await,
            _ = protect_tick.tick() => d.protect_tick().await,
            _ = resolve_tick.tick() => {
                d.resolve().await;
                d.apply();
            }
            _ = update_tick.tick() => d.maybe_update(),
            Some(control) = rx.recv() => match control {
                Control::Reload => reconfigured = d.reload().await,
                Control::Recheck => d.check().await,
                Control::Updated(version) => {
                    // Leave like on SIGTERM: the exit rules stay, launchd starts the new binary.
                    d.notify(&format!("vpnchecker updated to {version}"));
                    break;
                }
            },
            _ = sighup.recv() => reconfigured = d.reload().await,
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
        }
        if reconfigured {
            (check_tick, resolve_tick, protect_tick) = d.ticks();
        }
    }

    // The pf token is kept so the exit rules stay active; `vpnchecker stop` releases it. Frozen apps and the
    // dns shield stay as they are too: launchd restarts the daemon, and `stop` releases everything.
    info!("exiting, leaving rules that pass only traffic sourced from vpn.subnets");
    d.apply_via(Some(&Via::Subnets(d.cfg.vpn_subnets())));
    d.save_cache();
    if d.proxy.is_some() && !dry_run {
        let _ = dnsproxy::remove_resolver_files();
    }
    let _ = std::fs::remove_file(socket);
    Ok(())
}

/// One update round of the installed daemon: find a newer release, ask the user unless told not to, install
/// it and request the restart. Nothing is downloaded before the user agreed.
async fn self_update(
    confirm: bool,
    uid: Option<u32>,
    config: &Path,
    shared: &Shared,
    control: &mpsc::Sender<Control>,
) -> Result<()> {
    let current = update::current();
    let latest = update::latest().await?;
    if latest <= current {
        debug!(%current, %latest, "no newer release");
        return Ok(());
    }
    if confirm {
        let skipped = Path::new(update::SKIPPED);
        if update::skipped(skipped) == Some(latest) {
            debug!(%latest, "this release was skipped by the user");
            return Ok(());
        }
        let question = format!(
            "vpnchecker {latest} is available (installed: {current}).\n\nUpdate now? The daemon restarts within \
             seconds and the protection stays in place meanwhile."
        );
        match notify::ask_update(uid, &question).await {
            Some(notify::Answer::Update) => info!(%latest, "update confirmed by the user"),
            Some(notify::Answer::Skip) => {
                update::skip(skipped, latest)?;
                info!(%latest, "release skipped by the user, not asking about it again");
                return Ok(());
            }
            Some(notify::Answer::Later) => {
                info!(%latest, "update postponed by the user, asking again after update.interval");
                return Ok(());
            }
            None => {
                info!(%latest, "a newer release is available but nobody could be asked, not installing it");
                return Ok(());
            }
        }
        // The answer can take minutes: only go on if the VPN is still up.
        let up = {
            let snap = shared.lock().unwrap();
            snap.vpn.state == VpnState::Up && snap.protection == Protection::Open
        };
        if !up {
            info!(%latest, "the VPN went down while waiting for the answer, update postponed");
            return Ok(());
        }
    }
    update::install(latest, config, Path::new(launchd::BIN)).await?;
    info!(from = %current, to = %latest, "new version installed, restarting");
    let _ = control.send(Control::Updated(latest.to_string())).await;
    Ok(())
}

impl Daemon {
    fn ticks(&self) -> (Interval, Interval, Interval) {
        let mut check = interval(self.cfg.check.interval);
        check.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut resolve = interval(self.cfg.check.resolve_interval);
        resolve.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The first resolve already happened during startup / reload.
        resolve.reset();
        let mut protect = interval(self.cfg.protect.interval);
        protect.set_missed_tick_behavior(MissedTickBehavior::Delay);
        (check, resolve, protect)
    }

    /// Looks for a newer release once `update.interval` has passed, in the background, and asks the user before
    /// installing it (`update.confirm`). Only with the VPN verified up: the download then leaves through the
    /// tunnel, and the restart never happens while the apps are blocked.
    fn maybe_update(&mut self) {
        if !self.self_update || !self.cfg.update.auto || Instant::now() < self.next_update {
            return;
        }
        if self.vpn.state != VpnState::Up || self.guard.state() != Protection::Open {
            debug!("update check postponed: the VPN is not up");
            return;
        }
        if self.updating.swap(true, Ordering::SeqCst) {
            return;
        }
        self.next_update = Instant::now() + self.cfg.update.interval;
        let (control, updating, config) = (self.control.clone(), self.updating.clone(), self.config_path.clone());
        let (confirm, uid, shared) = (self.cfg.update.confirm, self.notify_uid, self.shared.clone());
        tokio::spawn(async move {
            if let Err(e) = self_update(confirm, uid, &config, &shared, &control).await {
                warn!("update check failed, next try after update.interval: {e:#}");
            }
            updating.store(false, Ordering::SeqCst);
        });
    }

    fn allowed(&self) -> BTreeSet<IpNet> {
        let mut addrs = self.cfg.allow_cidrs();
        let keys = self.cfg.allow_keys();
        addrs.extend(self.resolver.lock().unwrap().ips(&keys).into_iter().map(IpNet::from));
        addrs
    }

    fn apply(&mut self) {
        let via = self.vpn.interface.clone().map(Via::Interface);
        self.apply_via(via.as_ref());
    }

    /// Claude / Cursor server addresses: resolved from `protect.hosts` and seen on their sockets while the VPN
    /// was up. VPN gateways are never in this set.
    fn protected_nets(&self) -> BTreeSet<IpNet> {
        let resolver = self.resolver.lock().unwrap();
        let gateways = resolver.ips(&[GLOBALPROTECT_HOSTS, LEARNED_GATEWAYS, GP_GATEWAY]);
        resolver
            .ips(&[PROTECTED_HOSTS, OBSERVED])
            .into_iter()
            .filter(|ip| procs::is_public(*ip) && !gateways.contains(ip))
            .map(IpNet::from)
            .collect()
    }

    fn apply_via(&mut self, via: Option<&Via>) {
        let allowed = self.allowed();
        let protected = self.protected_nets();
        let rules = match self.cfg.mode {
            Mode::Full => pf::render(via, &allowed),
            Mode::Scoped if self.cfg.protect.pf_block => pf::render_scoped(via, &protected),
            Mode::Scoped => String::new(),
        };
        match self.pf.apply(&rules) {
            Ok(true) => info!(?via, mode = ?self.cfg.mode, allowed = allowed.len(), protected = protected.len(), "pf rules updated"),
            Ok(false) => {}
            Err(e) => error!("applying pf rules failed (will retry): {e:#}"),
        }
        let mut snap = self.shared.lock().unwrap();
        snap.allowed = allowed.len();
        snap.protected_ips = protected.len();
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
        let timeout = self.cfg.check.timeout;
        let resolved = resolver::resolve_all(&self.cfg.allow.domains, timeout).await;
        self.resolver.lock().unwrap().learn_resolved(None, &resolved);
        if self.cfg.allow.globalprotect {
            let hosts = globalprotect::discover(self.user_home.as_deref(), &self.cfg.allow.gateway_suffixes);
            if hosts != self.gp_hosts {
                info!(?hosts, "GlobalProtect portal/gateway hosts");
                self.gp_hosts = hosts;
            }
            let hosts: Vec<&String> = self.gp_hosts.iter().collect();
            let resolved = resolver::resolve_all(&hosts, timeout).await;
            self.resolver.lock().unwrap().learn_resolved(Some(GLOBALPROTECT_HOSTS), &resolved);
        }
        // Never look the protected names up while the VPN is down: that lookup is the leak the dns shield closes.
        if self.guard.state() == Protection::Open {
            let resolved = resolver::resolve_all(&self.cfg.protect.hosts, timeout).await;
            self.resolver.lock().unwrap().learn_resolved(Some(PROTECTED_HOSTS), &resolved);
            if self.cfg.protect.observe_connections {
                let pids = procs::protected_pids(&self.matcher).await;
                let seen = procs::remote_endpoints(&pids).await;
                if !self.resolver.lock().unwrap().learn(OBSERVED, seen.iter().copied()).is_empty() {
                    debug!(count = seen.len(), "learned server addresses from protected sockets");
                }
            }
        }
        self.save_cache();
    }

    /// The gateway GlobalProtect itself reports (root-owned plist): allowed at once after every reconnect, without DNS.
    /// Returns true when it changed, so the caller re-resolves the other gateway names too.
    fn learn_globalprotect(&mut self) -> bool {
        let Some(conn) = self.vpn.globalprotect.clone() else {
            return false;
        };
        let mut changed = false;
        if let Some(ip) = conn.gateway_ip
            && !self.resolver.lock().unwrap().learn(GP_GATEWAY, [ip]).is_empty()
        {
            info!(gateway = ?conn.gateway_host, %ip, status = %conn.status, "GlobalProtect gateway");
            self.save_cache();
            changed = true;
        }
        if conn.gateway_host != self.gp_gateway {
            self.gp_gateway = conn.gateway_host;
            changed = true;
        }
        changed
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

        // Protection first: freezing must not wait for pf, DNS or the allowlist.
        let p = &self.cfg.protect;
        let stable = p.interval * p.resume_checks.saturating_sub(1);
        let change = self.guard.observe(self.vpn.state == VpnState::Up, Instant::now(), p.resume_checks, stable);
        self.enforce(change).await;

        let gp_changed = self.learn_globalprotect();
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
        } else if gp_changed {
            // GlobalProtect (re)connected, possibly to another gateway: refresh every gateway name now.
            self.resolve().await;
            self.apply();
        }

        let now = sys::now_unix();
        {
            let mut snap = self.shared.lock().unwrap();
            snap.last_check = now;
            if changed {
                snap.since = now;
            }
        }
        self.publish();
    }

    /// Wake detection and, while blocked, relaunch scanning. Runs every `protect.interval`.
    async fn protect_tick(&mut self) {
        let now = SystemTime::now();
        let gap = now.duration_since(self.last_tick).unwrap_or_default();
        self.last_tick = now;

        if gap >= self.cfg.protect.wake_gap {
            // The Mac slept or stalled: the VPN state we saw is stale and GlobalProtect may still show a dead tunnel as
            // up. Freeze first, verify afterwards.
            warn!(gap_secs = gap.as_secs(), "clock jumped (sleep/wake): protecting first, re-verifying the VPN");
            let change = self.guard.wake(Instant::now(), self.cfg.protect.wake_hold);
            if change == Change::None {
                self.freeze().await;
            } else {
                self.enforce(change).await;
            }
            self.check().await;
            return;
        }

        if self.guard.state() == Protection::Blocked {
            self.block_ticks = self.block_ticks.saturating_add(1);
            // Catch relaunches quickly for the first seconds, then re-scan less often to keep CPU low.
            if self.block_ticks <= 20 || self.block_ticks.is_multiple_of(4) {
                self.freeze().await;
            }
            // Lets `resume_checks` accumulate without waiting for the next routing event.
            self.check().await;
        }
    }

    async fn enforce(&mut self, change: Change) {
        match change {
            Change::None => {}
            Change::Blocked => {
                self.block_ticks = 0;
                self.announce_resume = true;
                self.freeze().await;
                if self.shield_ready && self.cfg.protect.dns_shield {
                    self.shield.enable();
                }
                self.notify(match self.cfg.mode {
                    Mode::Scoped => "VPN is down: Claude, Cursor and Rider are frozen",
                    Mode::Full => "VPN is down: internet traffic is blocked, Claude, Cursor and Rider are frozen",
                });
            }
            Change::Opened => {
                self.block_ticks = 0;
                self.shield.disable();
                self.resume().await;
                if std::mem::take(&mut self.announce_resume) {
                    self.notify("VPN is up: Claude, Cursor and Rider resumed");
                }
                // The protected server addresses are refreshed through the tunnel as soon as it is back.
                self.resolve().await;
                self.apply();
            }
        }
    }

    fn notify(&self, message: &str) {
        if self.cfg.notify {
            notify::send(self.notify_uid, message);
        }
    }

    async fn freeze(&mut self) {
        let pids = procs::protected_pids(&self.matcher).await;
        let previous = std::mem::replace(&mut self.frozen, pids.len());
        if pids.is_empty() {
            return;
        }
        if self.dry_run {
            if pids.len() != previous {
                info!(count = pids.len(), "[dry-run] would block protected processes");
            }
            return;
        }
        let sig = match self.cfg.protect.action {
            Action::Stop => Signal::SIGSTOP,
            Action::Kill if self.block_ticks <= 1 => Signal::SIGTERM,
            Action::Kill => Signal::SIGKILL,
        };
        let reached = procs::signal(&pids, sig);
        if pids.len() != previous {
            info!(count = pids.len(), reached, signal = ?sig, "blocked Claude / Cursor / Rider processes");
        }
    }

    async fn resume(&mut self) {
        self.frozen = 0;
        if self.cfg.protect.action == Action::Kill {
            return;
        }
        let pids = procs::protected_pids(&self.matcher).await;
        if pids.is_empty() || self.dry_run {
            return;
        }
        let reached = procs::signal(&pids, Signal::SIGCONT);
        info!(count = pids.len(), reached, "resumed Claude / Cursor / Rider processes");
    }

    /// Copies the current state into the snapshot served over the control socket.
    fn publish(&self) {
        let mut snap = self.shared.lock().unwrap();
        snap.vpn = self.vpn.clone();
        snap.mode = self.cfg.mode;
        snap.protection = self.guard.state();
        snap.frozen = self.frozen;
        snap.shield = self.shield.active();
        snap.auto_update = self.self_update && self.cfg.update.auto;
        snap.update_confirm = self.cfg.update.confirm;
    }

    async fn reload(&mut self) -> bool {
        match config::load(&self.config_path) {
            Ok(cfg) => {
                for w in cfg.warnings() {
                    warn!("{w}");
                }
                self.resolver.lock().unwrap().set_retain(cfg.check.resolve_retain);
                match Matcher::new(&cfg.protect.patterns()) {
                    Ok(matcher) => self.matcher = matcher,
                    Err(e) => warn!("keeping previous process patterns: {e:#}"),
                }
                self.shield.configure(cfg.protect.domains.clone(), cfg.protect.dns_port);
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
