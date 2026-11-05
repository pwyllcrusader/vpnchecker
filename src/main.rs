mod config;
mod daemon;
mod detect;
mod dnsproxy;
mod dnsshield;
mod globalprotect;
mod guard;
mod ipc;
mod launchd;
mod notify;
mod pf;
mod procs;
mod resolver;
mod routewatch;
mod sys;
mod update;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, ExitCode};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::detect::VpnState;
use crate::ipc::Request;

#[derive(Parser)]
#[command(version, about = "VPN kill switch for macOS: Claude, Cursor and Rider (optionally the whole machine) reach the internet only through the VPN")]
struct Cli {
    /// Config file [default: ~/.config/vpnchecker/config.yaml]
    #[arg(long, global = true, env = "VPNCHECKER_CONFIG")]
    config: Option<PathBuf>,
    /// Daemon control socket
    #[arg(long, global = true, default_value = ipc::DEFAULT_SOCKET)]
    socket: PathBuf,
    /// Increase log verbosity (-v debug, -vv trace)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon in the foreground (root)
    Run {
        /// Log pf rules instead of applying them (no root needed)
        #[arg(long)]
        dry_run: bool,
    },
    /// Check the VPN once: exit 0 = up, 1 = down, 2 = error
    Check {
        #[arg(short, long)]
        quiet: bool,
    },
    /// Show daemon status
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Ask the running daemon to reload its config
    Reload,
    /// Allow a domain and all its subdomains without the VPN (adds it to the config and reloads)
    Allow {
        /// Domain or URL, e.g. example.com, *.example.com, https://example.com/path
        mask: String,
    },
    /// Show interfaces, VPN checks, allowlist and detected VPN gateways
    Diagnose,
    /// List the Claude / Cursor / Rider processes the protection covers (STAT T = frozen)
    Procs,
    /// Install and start the launchd daemon (root)
    Install,
    /// Stop and remove the launchd daemon and pf rules (root)
    Uninstall,
    /// Start the installed daemon (root)
    Start,
    /// Stop the daemon, remove its pf rules, resume frozen apps and remove the dns shield (root)
    Stop {
        /// Keep the exit rules (pass only traffic sourced from vpn.subnets)
        #[arg(long)]
        keep_block: bool,
    },
    /// Restart the daemon (root)
    Restart,
    /// Install the latest release now and restart the daemon (root)
    Update {
        /// Only report whether a newer release exists (no root needed)
        #[arg(long)]
        check: bool,
    },
    /// Remove vpnchecker pf rules immediately (root)
    Flush,
    /// Show daemon log
    Logs {
        #[arg(short, long)]
        follow: bool,
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
    },
    /// Manage the config file
    #[command(subcommand)]
    Config(ConfigCommand),
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Write a default config
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Validate the config
    Validate,
    /// Print the config path
    Path,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level)))
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let config_path = match cli.config {
        Some(path) => path,
        None => sys::default_config_path()?,
    };
    let socket = cli.socket.as_path();
    match cli.command {
        Command::Run { dry_run } => daemon::run(config_path, socket, dry_run).await?,
        Command::Check { quiet } => return check(&config_path, quiet).await,
        Command::Status { json } => status(socket, json).await?,
        Command::Reload => {
            ipc::request(socket, &Request::Reload).await?;
            println!("reloaded");
        }
        Command::Allow { mask } => allow(&config_path, socket, &mask).await?,
        Command::Diagnose => diagnose(&config_path).await?,
        Command::Procs => procs_command(&config_path).await?,
        Command::Install => launchd::install(&config_path, socket)?,
        Command::Uninstall => launchd::uninstall(&config_path, socket).await?,
        Command::Start => launchd::start()?,
        Command::Stop { keep_block } => launchd::stop(&config_path, keep_block).await?,
        Command::Restart => launchd::restart()?,
        Command::Update { check } => update_command(&config_path, check).await?,
        Command::Flush => {
            sys::require_root()?;
            pf::flush()?;
            println!("pf anchor {} flushed", pf::ANCHOR);
        }
        Command::Logs { follow, lines } => logs(follow, lines)?,
        Command::Config(cmd) => config_command(cmd, &config_path)?,
    }
    Ok(ExitCode::SUCCESS)
}

async fn update_command(config_path: &Path, check: bool) -> Result<()> {
    let target = Path::new(launchd::BIN);
    // What counts is the installed daemon, not the binary this command happens to run from.
    let installed = if target.exists() { Some(update::binary_version(target).await?) } else { None };
    if check {
        let current = installed.unwrap_or_else(update::current);
        let latest = update::latest().await?;
        if latest > current {
            println!("update available: {current} -> {latest} (install it with: sudo vpnchecker update)");
        } else {
            println!("up to date: {current} (latest release {latest})");
        }
        return Ok(());
    }
    sys::require_root()?;
    let Some(current) = installed else {
        bail!("the daemon is not installed: run the installer or `sudo vpnchecker install` first");
    };
    match update::run(current, config_path, target).await? {
        update::Outcome::UpToDate { current, latest } => println!("up to date: {current} (latest release {latest})"),
        update::Outcome::Updated { from, to } => {
            println!("updated {from} -> {to}");
            launchd::restart()?;
            println!("daemon restarted");
        }
    }
    Ok(())
}

async fn allow(config_path: &Path, socket: &Path, mask: &str) -> Result<()> {
    let domain = config::normalize_mask(mask)?;
    let text = fs::read_to_string(config_path).with_context(|| format!("reading {}", config_path.display()))?;
    let cfg = config::parse(&text).with_context(|| format!("invalid config {}", config_path.display()))?;
    if let Some(zone) = config::covering_zone(&cfg.allow.domains, &domain) {
        println!("{domain} is already allowed by {zone}");
        return Ok(());
    }
    let updated = config::insert_allow_domain(&text, &domain)?;
    let check = config::parse(&updated).context("edited config does not parse, left unchanged")?;
    if !check.allow.domains.contains(&domain) {
        bail!("could not add {domain} to allow.domains, edit {} manually", config_path.display());
    }
    // Written in place: the daemon trusts the config owner, a rename could change it.
    fs::write(config_path, updated).with_context(|| format!("writing {}", config_path.display()))?;
    println!("allowed {domain} and its subdomains in {}", config_path.display());
    match ipc::request(socket, &Request::Reload).await {
        Ok(_) => println!("daemon reloaded"),
        Err(e) => println!("daemon not reloaded ({e:#}), the change applies on next start"),
    }
    Ok(())
}

async fn check(config_path: &Path, quiet: bool) -> Result<ExitCode> {
    let cfg = config::load(config_path)?;
    let status = detect::detect(&cfg).await;
    if !quiet {
        println!("vpn: {:?}", status.state);
        print_checks(&status.checks);
    }
    Ok(match status.state {
        VpnState::Up => ExitCode::SUCCESS,
        VpnState::Down => ExitCode::from(1),
        VpnState::Unknown => ExitCode::from(2),
    })
}

fn print_checks(checks: &[detect::CheckResult]) {
    for c in checks {
        println!("  [{}] {}: {}", if c.ok { "ok" } else { "FAIL" }, c.name, c.detail);
    }
}

async fn status(socket: &Path, json: bool) -> Result<()> {
    let resp = ipc::request(socket, &Request::Status).await?;
    let snap = resp.status.context("daemon returned no status")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&snap)?);
        return Ok(());
    }
    let ago = |ts: u64| {
        let secs = sys::now_unix().saturating_sub(ts);
        humantime::format_duration(Duration::from_secs(secs)).to_string()
    };
    let iface = snap.vpn.interface.as_deref().map(|i| format!(" ({i})")).unwrap_or_default();
    let traffic = match (snap.mode, snap.vpn.state) {
        (config::Mode::Full, VpnState::Up) => "through the VPN only (whole machine)",
        (config::Mode::Full, _) => "BLOCKED (allowlist only)",
        (config::Mode::Scoped, _) => "only Claude / Cursor / Rider are restricted",
    };
    println!("vpn:        {:?}{iface} for {}", snap.vpn.state, ago(snap.since));
    if let Some(gp) = &snap.vpn.globalprotect {
        let gateway = gp.gateway_host.as_deref().unwrap_or("?");
        let ip = gp.gateway_ip.map(|i| format!(" ({i})")).unwrap_or_default();
        println!("globalprot: {} via {gateway}{ip}", gp.status);
    }
    println!("mode:       {:?}: {traffic}{}", snap.mode, if snap.dry_run { " (dry-run)" } else { "" });
    println!(
        "protection: {:?}, {} processes frozen, dns shield {}, {} server addresses blocked outside the tunnel",
        snap.protection,
        snap.frozen,
        if snap.shield { "ON" } else { "off" },
        snap.protected_ips
    );
    println!("allowlist:  {} addresses", snap.allowed);
    println!("last check: {} ago", ago(snap.last_check));
    println!("config:     {}", snap.config);
    println!("pid:        {}", snap.pid);
    if !snap.version.is_empty() {
        let auto = if snap.auto_update { "on" } else { "off" };
        println!("version:    {}, auto-update {auto}", snap.version);
    }
    print_checks(&snap.vpn.checks);
    Ok(())
}

async fn diagnose(config_path: &Path) -> Result<()> {
    let cfg = config::load(config_path)?;
    for w in cfg.warnings() {
        println!("warning: {w}");
    }
    let re = regex::Regex::new(&cfg.vpn.interface_pattern)?;

    println!("Interfaces matching {:?} (* = address from vpn.subnets):", cfg.vpn.interface_pattern);
    for iface in if_addrs::get_if_addrs()? {
        if re.is_match(&iface.name) {
            let ip = iface.ip();
            let mark = if cfg.vpn.subnets.iter().any(|n| n.contains(&ip)) { "*" } else { " " };
            println!("  {mark} {} {ip}", iface.name);
        }
    }

    let status = detect::detect(&cfg).await;
    println!("\nVPN: {:?}", status.state);
    print_checks(&status.checks);

    println!("\nAllowlist domains (with subdomains):");
    for domain in &cfg.allow.domains {
        let via = dnsproxy::resolver_file_state(domain);
        match resolver::resolve(domain, cfg.check.timeout).await {
            Ok(ips) => println!("  {domain} [{via}] -> {ips:?}"),
            Err(e) => println!("  {domain} [{via}] -> {e}"),
        }
    }

    if cfg.allow.globalprotect {
        let home = sys::file_owner(config_path)
            .and_then(|uid| nix::unistd::User::from_uid(uid).ok().flatten())
            .map(|user| user.dir);
        println!("\nGlobalProtect hosts (settings + {}):", globalprotect::EVENT_LOG);
        match globalprotect::connection() {
            Some(c) => println!(
                "  connection: {} gateway {} {} tunnel {}",
                c.status,
                c.gateway_host.as_deref().unwrap_or("?"),
                c.gateway_ip.map(|i| i.to_string()).unwrap_or_default(),
                c.tunnel_ip.map(|i| i.to_string()).unwrap_or_default()
            ),
            None => println!("  connection: no GlobalProtect state found"),
        }
        let hosts = globalprotect::discover(home.as_deref(), &cfg.allow.gateway_suffixes);
        if hosts.is_empty() {
            println!("  none found");
        }
        for host in &hosts {
            match resolver::resolve(host, cfg.check.timeout).await {
                Ok(ips) => println!("  {host} -> {ips:?}"),
                Err(e) => println!("  {host} -> {e}"),
            }
        }
    }

    println!("\nProtected servers (mode {:?}; blocked outside the tunnel):", cfg.mode);
    for host in &cfg.protect.hosts {
        match resolver::resolve(host, cfg.check.timeout).await {
            Ok(ips) => println!("  {host} -> {ips:?}"),
            Err(e) => println!("  {host} -> {e}"),
        }
    }
    println!("dns shield domains: {}", cfg.protect.domains.join(", "));

    println!("\nVPN gateways (host routes outside the tunnel, learned automatically):");
    let gateways = detect::gateway_routes(&re);
    if gateways.is_empty() {
        println!("  none found{}", if status.state == VpnState::Up { "" } else { " (connect the VPN)" });
    }
    for (dest, iface) in gateways {
        println!("  {dest}/32 via {iface}");
    }
    Ok(())
}

async fn procs_command(config_path: &Path) -> Result<()> {
    let protect = config::protect_or_default(config_path);
    let matcher = procs::Matcher::new(&protect.patterns())?;
    let all = procs::list().await;
    let pids = procs::select(&all, &matcher, &[std::process::id() as i32]);
    if pids.is_empty() {
        println!("no Claude / Cursor / Rider processes running");
    }
    for pid in pids {
        let stat = Process::new("/bin/ps").args(["-o", "stat=", "-p", &pid.to_string()]).output().ok();
        let stat = stat.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
        let command = all.iter().find(|p| p.pid == pid).map(|p| p.command.as_str()).unwrap_or("?");
        println!("{pid:>7} {stat:<4} {}", command.chars().take(110).collect::<String>());
    }
    Ok(())
}

fn logs(follow: bool, lines: usize) -> Result<()> {
    let mut cmd = Process::new("/usr/bin/tail");
    cmd.args(["-n", &lines.to_string()]);
    if follow {
        cmd.arg("-F");
    }
    let exit = cmd.arg(launchd::LOG).status().context("running tail")?;
    if !exit.success() {
        bail!("tail exited with {exit}");
    }
    Ok(())
}

fn config_command(cmd: ConfigCommand, path: &Path) -> Result<()> {
    match cmd {
        ConfigCommand::Path => println!("{}", path.display()),
        ConfigCommand::Validate => {
            let cfg = config::load(path)?;
            for w in cfg.warnings() {
                println!("warning: {w}");
            }
            println!(
                "{} is valid: mode {:?}, {} vpn subnets, {} allow domains, {} allow cidrs (lan: {}), learn_gateways: {}, globalprotect: {}",
                path.display(),
                cfg.mode,
                cfg.vpn.subnets.len(),
                cfg.allow.domains.len(),
                cfg.allow.cidrs.len(),
                cfg.allow.lan,
                cfg.allow.learn_gateways,
                cfg.allow.globalprotect
            );
        }
        ConfigCommand::Init { force } => {
            if path.exists() && !force {
                bail!("{} already exists (use --force to overwrite)", path.display());
            }
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir)?;
            }
            fs::write(path, config::TEMPLATE)?;
            println!("wrote {}", path.display());
        }
    }
    Ok(())
}
