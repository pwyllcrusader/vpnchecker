mod config;
mod daemon;
mod detect;
mod globalprotect;
mod ipc;
mod launchd;
mod notify;
mod pf;
mod resolver;
mod routewatch;
mod sys;

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
#[command(version, about = "VPN kill switch for macOS: outbound traffic leaves only through the VPN (pf)")]
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
    /// Show interfaces, VPN checks, allowlist and detected VPN gateways
    Diagnose,
    /// Install and start the launchd daemon (root)
    Install,
    /// Stop and remove the launchd daemon and pf rules (root)
    Uninstall,
    /// Start the installed daemon (root)
    Start,
    /// Stop the daemon and remove its pf rules (root)
    Stop {
        /// Keep the exit rules (pass only traffic sourced from vpn.subnets)
        #[arg(long)]
        keep_block: bool,
    },
    /// Restart the daemon (root)
    Restart,
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
        Command::Diagnose => diagnose(&config_path).await?,
        Command::Install => launchd::install(&config_path, socket)?,
        Command::Uninstall => launchd::uninstall(socket)?,
        Command::Start => launchd::start()?,
        Command::Stop { keep_block } => launchd::stop(keep_block)?,
        Command::Restart => launchd::restart()?,
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
    let traffic = match snap.vpn.state {
        VpnState::Up => "through the VPN only",
        _ => "BLOCKED (allowlist only)",
    };
    println!("vpn:        {:?}{iface} for {}", snap.vpn.state, ago(snap.since));
    println!("traffic:    {traffic}{}", if snap.dry_run { " (dry-run)" } else { "" });
    println!("allowlist:  {} addresses", snap.allowed);
    println!("last check: {} ago", ago(snap.last_check));
    println!("config:     {}", snap.config);
    println!("pid:        {}", snap.pid);
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

    println!("\nAllowlist domains:");
    for domain in &cfg.allow.domains {
        match resolver::resolve(domain, cfg.check.timeout).await {
            Ok(ips) => println!("  {domain} -> {ips:?}"),
            Err(e) => println!("  {domain} -> {e}"),
        }
    }

    if cfg.allow.globalprotect {
        let home = sys::file_owner(config_path)
            .and_then(|uid| nix::unistd::User::from_uid(uid).ok().flatten())
            .map(|user| user.dir);
        println!("\nGlobalProtect hosts (settings + {}):", globalprotect::EVENT_LOG);
        let hosts = globalprotect::discover(home.as_deref());
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
                "{} is valid: {} vpn subnets, {} allow domains, {} allow cidrs (lan: {}), learn_gateways: {}, globalprotect: {}",
                path.display(),
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
