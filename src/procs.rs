use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use regex::RegexSet;
use tokio::process::Command;
use tokio::time::timeout;

/// Matches the full command line of the apps to protect (Claude, Cursor, Rider and their tooling).
pub struct Matcher {
    set: RegexSet,
}

impl Matcher {
    pub fn new(patterns: &[String]) -> Result<Self> {
        Ok(Self {
            set: RegexSet::new(patterns).context("protect.process_patterns")?,
        })
    }

    fn is_match(&self, command: &str) -> bool {
        self.set.is_match(command)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub pid: i32,
    pub ppid: i32,
    pub command: String,
}

pub async fn list() -> Vec<Proc> {
    match Command::new("/bin/ps").args(["-axww", "-o", "pid=,ppid=,command="]).output().await {
        Ok(out) => parse_ps(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => Vec::new(),
    }
}

pub fn parse_ps(out: &str) -> Vec<Proc> {
    out.lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, rest) = line.split_once(char::is_whitespace)?;
            let (ppid, command) = rest.trim_start().split_once(char::is_whitespace)?;
            Some(Proc {
                pid: pid.parse().ok()?,
                ppid: ppid.parse().ok()?,
                command: command.trim().to_string(),
            })
        })
        .collect()
}

/// Matching processes plus every descendant of theirs (MCP servers, extension hosts, terminals).
/// `exclude` (this daemon) and pid <= 1 are never selected.
pub fn select(procs: &[Proc], matcher: &Matcher, exclude: &[i32]) -> Vec<i32> {
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for p in procs {
        children.entry(p.ppid).or_default().push(p.pid);
    }
    let mut picked: BTreeSet<i32> = BTreeSet::new();
    let mut queue: Vec<i32> = procs
        .iter()
        .filter(|p| matcher.is_match(&p.command) && !exclude.contains(&p.pid))
        .map(|p| p.pid)
        .collect();
    while let Some(pid) = queue.pop() {
        if pid <= 1 || exclude.contains(&pid) || !picked.insert(pid) {
            continue;
        }
        queue.extend(children.get(&pid).into_iter().flatten().copied());
    }
    picked.into_iter().collect()
}

/// Returns how many processes the signal reached.
pub fn signal(pids: &[i32], sig: Signal) -> usize {
    pids.iter().filter(|&&pid| kill(Pid::from_raw(pid), sig).is_ok()).count()
}

pub async fn protected_pids(matcher: &Matcher) -> Vec<i32> {
    let me = std::process::id() as i32;
    select(&list().await, matcher, &[me])
}

/// Resumes everything that may have been frozen (used by `stop` / `uninstall`).
pub async fn resume_all(matcher: &Matcher) -> usize {
    signal(&protected_pids(matcher).await, Signal::SIGCONT)
}

/// Public remote addresses of the sockets owned by `pids`, from `lsof`.
pub async fn remote_endpoints(pids: &[i32]) -> Vec<IpAddr> {
    if pids.is_empty() {
        return Vec::new();
    }
    let csv = pids.iter().take(400).map(i32::to_string).collect::<Vec<_>>().join(",");
    let run = Command::new("/usr/sbin/lsof").args(["-nP", "-i", "-a", "-p", &csv, "-Fn"]).output();
    match timeout(Duration::from_secs(8), run).await {
        Ok(Ok(out)) => parse_lsof(&String::from_utf8_lossy(&out.stdout)),
        _ => Vec::new(),
    }
}

/// `n10.4.5.49:51234->160.79.104.10:443` and `n[2607::1]:5->[2606:4700::1]:443` lines.
pub fn parse_lsof(out: &str) -> Vec<IpAddr> {
    let found: BTreeSet<IpAddr> = out
        .lines()
        .filter_map(|l| l.strip_prefix('n'))
        .filter_map(|name| name.split_once("->").map(|(_, remote)| remote))
        .filter_map(|remote| {
            let (host, _port) = remote.rsplit_once(':')?;
            let host = host.trim_matches(['[', ']']).split('%').next()?;
            host.parse::<IpAddr>().ok()
        })
        .filter(|ip| is_public(*ip))
        .collect();
    found.into_iter().collect()
}

/// Global unicast only: private, loopback, link-local and multicast addresses are never learned.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> Matcher {
        Matcher::new(&crate::config::ProtectConfig::default().patterns()).unwrap()
    }

    const PS: &str = "\
    1     0 /sbin/launchd
  100     1 /Applications/Cursor.app/Contents/MacOS/Cursor
  101   100 /Applications/Cursor.app/Contents/Frameworks/Cursor Helper.app/Contents/MacOS/Cursor Helper --type=renderer
  102   101 /bin/zsh -il
  103   102 npm exec @supabase/mcp-server-supabase
  200     1 /Users/me/Library/Application Support/Claude/claude-code/2.1/abc/claude.app/Contents/MacOS/claude --print
  201   200 node mcp.js
  300     1 /Applications/Safari.app/Contents/MacOS/Safari
  301     1 /usr/bin/vim /tmp/notes-about-claude.txt
  400     1 /Users/me/Library/Caches/JetBrains/acp-agents/cursor/dist/cursor-agent
  500     1 /Library/PrivilegedHelperTools/vpnchecker --config /Users/me/.config/vpnchecker/config.yaml run
  600     1 /Applications/Rider.app/Contents/MacOS/rider
  601   600 /Applications/Rider.app/Contents/lib/ReSharperHost/macos-arm64/Rider.Backend --runtimeconfig /Applications/Rider.app/Contents/lib/ReSharperHost/Rider.Backend.runtimeconfig.json
  602   600 /Applications/Rider.app/Contents/bin/fsnotifier
  700     1 /Applications/JetBrains Toolbox.app/Contents/MacOS/jetbrains-toolbox
";

    #[test]
    fn parses_ps_output() {
        let procs = parse_ps(PS);
        assert_eq!(procs.len(), 15);
        assert_eq!(procs[2].ppid, 100);
        assert!(procs[2].command.ends_with("--type=renderer"));
        assert!(parse_ps("garbage\n\n  x y z\n").is_empty());
    }

    #[test]
    fn selects_apps_and_all_descendants_only() {
        let procs = parse_ps(PS);
        let picked = select(&procs, &defaults(), &[500]);
        assert_eq!(picked, vec![100, 101, 102, 103, 200, 201, 400, 600, 601, 602]);
        assert!(!picked.contains(&300), "Safari is not protected");
        assert!(!picked.contains(&700), "JetBrains Toolbox is not Rider");
        assert!(!picked.contains(&301), "a file name containing 'claude' is not a process match");
    }

    #[test]
    fn never_selects_excluded_or_init() {
        let procs = parse_ps(PS);
        let all = Matcher::new(&[".*".to_string()]).unwrap();
        let picked = select(&procs, &all, &[500, 300]);
        assert!(!picked.contains(&1) && !picked.contains(&500) && !picked.contains(&300));
    }

    /// Real signals on a child of the test process: no root needed.
    #[tokio::test]
    async fn freezes_and_resumes_a_real_process() {
        let mut child = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let stat = |pid: i32| {
            let out = std::process::Command::new("/bin/ps").args(["-o", "stat=", "-p", &pid.to_string()]).output().unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        // match by command line: "/bin/sleep 30" and this exact pid only
        let matcher = Matcher::new(&["^/bin/sleep 30$".to_string()]).unwrap();
        let picked: Vec<i32> = select(&list().await, &matcher, &[]).into_iter().filter(|p| *p == pid).collect();
        assert_eq!(picked, vec![pid], "the child is selected");

        assert_eq!(signal(&picked, Signal::SIGSTOP), 1);
        std::thread::sleep(Duration::from_millis(150));
        assert!(stat(pid).starts_with('T'), "frozen: {}", stat(pid));

        assert_eq!(signal(&picked, Signal::SIGCONT), 1);
        std::thread::sleep(Duration::from_millis(150));
        assert!(!stat(pid).starts_with('T'), "resumed: {}", stat(pid));

        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn parses_lsof_remote_endpoints() {
        let out = "p100\nf20\nn10.4.5.49:51234->160.79.104.10:443\nf21\nn*:8080\nf22\nn192.168.0.5:5->192.168.0.1:53\n\
                   f23\nn[2607:6bc0::10]:5->[2606:4700::6812:137d]:443\nf24\nn127.0.0.1:1->127.0.0.1:2\n";
        let ips = parse_lsof(out);
        assert_eq!(ips, vec!["160.79.104.10".parse::<IpAddr>().unwrap(), "2606:4700::6812:137d".parse().unwrap()]);
    }

    #[test]
    fn public_address_filter() {
        for ip in ["10.0.0.1", "172.20.1.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "fe80::1", "fd00::1", "::1"] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["160.79.104.10", "8.8.8.8", "2606:4700::1"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
