use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::process::{Child, Command};
use tracing::{info, warn};

use crate::config::AlwaysOnConfig;
use crate::procs::{self, Matcher};

/// How often the CPU of the watched processes is sampled.
pub const SAMPLE: Duration = Duration::from_secs(10);
const CAFFEINATE: &str = "/usr/bin/caffeinate";

/// Keeps the Mac from idle sleep while Claude / Cursor are busy (`always_on`).
pub struct Awake {
    matcher: Matcher,
    /// Cumulative CPU time per pid at the previous sample; `None` until the first one.
    last: Option<HashMap<i32, Duration>>,
    last_active: Option<Instant>,
    /// `caffeinate -i` holding the assertion; `Some` with no child in dry-run mode.
    hold: Option<Option<Child>>,
    /// CPU of the watched processes at the last sample, percent of one core.
    pub cpu: f64,
}

impl Awake {
    pub fn new(patterns: &[String]) -> Result<Self> {
        Ok(Self {
            matcher: Matcher::new(patterns)?,
            last: None,
            last_active: None,
            hold: None,
            cpu: 0.0,
        })
    }

    pub fn set_patterns(&mut self, patterns: &[String]) -> Result<()> {
        self.matcher = Matcher::new(patterns)?;
        Ok(())
    }

    pub fn active(&self) -> bool {
        self.hold.is_some()
    }

    /// One sample: holds the assertion while the watched processes were busy within `linger`, releases it after.
    pub async fn tick(&mut self, cfg: &AlwaysOnConfig, dry_run: bool) {
        if !cfg.enabled {
            self.last = None;
            self.last_active = None;
            self.cpu = 0.0;
            self.release().await;
            return;
        }
        let me = std::process::id() as i32;
        let pids = procs::select(&procs::list().await, &self.matcher, &[me]);
        let times = cpu_times().await;
        let watched = pids.iter().filter_map(|pid| times.get(pid).map(|t| (*pid, *t))).collect();
        // The first sample only sets the baseline: lifetime CPU time is not activity.
        let Some(prev) = self.last.replace(watched) else {
            return;
        };
        self.cpu = busy_cpu(&prev, &times, &pids, SAMPLE);

        let now = Instant::now();
        if self.cpu >= cfg.cpu {
            self.last_active = Some(now);
        }
        let busy = self.last_active.is_some_and(|t| now.duration_since(t) < cfg.linger);
        if busy {
            if !self.active() {
                info!(cpu = format!("{:.1}%", self.cpu), "Claude / Cursor busy: keeping the Mac awake");
            }
            self.hold(dry_run);
        } else if self.active() {
            info!(linger = ?cfg.linger, "Claude / Cursor idle: sleep allowed again");
            self.release().await;
        }
    }

    /// Starts `caffeinate`, or restarts it if it exited. `-w` ends it with this daemon, also on SIGKILL.
    fn hold(&mut self, dry_run: bool) {
        if let Some(Some(child)) = &mut self.hold
            && matches!(child.try_wait(), Ok(None))
        {
            return;
        }
        if dry_run {
            if self.hold.is_none() {
                info!("[dry-run] would keep the Mac awake");
            }
            self.hold = Some(None);
            return;
        }
        let pid = std::process::id().to_string();
        match Command::new(CAFFEINATE).args(["-i", "-w", &pid]).kill_on_drop(true).spawn() {
            Ok(child) => self.hold = Some(Some(child)),
            Err(e) => {
                warn!("starting {CAFFEINATE} failed: {e:#}");
                self.hold = None;
            }
        }
    }

    pub async fn release(&mut self) {
        if let Some(Some(mut child)) = self.hold.take() {
            let _ = child.kill().await;
        }
    }
}

async fn cpu_times() -> HashMap<i32, Duration> {
    match Command::new("/bin/ps").args(["-axo", "pid=,time="]).output().await {
        Ok(out) => parse_cpu_times(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => HashMap::new(),
    }
}

/// `  83750 791:12.99` lines: pid and cumulative CPU time as minutes:seconds.
pub fn parse_cpu_times(out: &str) -> HashMap<i32, Duration> {
    out.lines()
        .filter_map(|line| {
            let (pid, time) = line.trim().split_once(char::is_whitespace)?;
            let (min, sec) = time.trim().split_once(':')?;
            let secs = min.parse::<u64>().ok()? as f64 * 60.0 + sec.parse::<f64>().ok()?;
            Some((pid.parse().ok()?, Duration::try_from_secs_f64(secs).ok()?))
        })
        .collect()
}

/// CPU used by `pids` between two samples, in percent of one core over `period`. A pid new since the previous
/// sample counts with all of its time; one whose time went backwards (pid reused) counts as zero.
pub fn busy_cpu(prev: &HashMap<i32, Duration>, now: &HashMap<i32, Duration>, pids: &[i32], period: Duration) -> f64 {
    let used: Duration = pids
        .iter()
        .filter_map(|pid| {
            let t = now.get(pid)?;
            Some(t.saturating_sub(prev.get(pid).copied().unwrap_or_default()))
        })
        .sum();
    used.as_secs_f64() / period.as_secs_f64() * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ps_cpu_times() {
        let times = parse_cpu_times("  83750 791:12.99\n    1   0:00.05\ngarbage\n  12 x:1\n");
        assert_eq!(times.len(), 2);
        assert_eq!(times[&83750], Duration::from_millis(791 * 60_000 + 12_990));
        assert_eq!(times[&1], Duration::from_millis(50));
    }

    #[test]
    fn cpu_counts_watched_pids_only() {
        let secs = |s: f64| Duration::from_secs_f64(s);
        let prev = HashMap::from([(10, secs(5.0)), (11, secs(3.0)), (12, secs(9.0)), (99, secs(1.0))]);
        let now = HashMap::from([(10, secs(6.0)), (12, secs(2.0)), (13, secs(0.5)), (99, secs(100.0))]);
        // 10: +1s, 11: exited, 12: reused (0), 13: new (+0.5s), 99: not watched
        let cpu = busy_cpu(&prev, &now, &[10, 11, 12, 13], Duration::from_secs(10));
        assert!((cpu - 15.0).abs() < 1e-9, "{cpu}");
        assert_eq!(busy_cpu(&now, &now, &[10, 13], Duration::from_secs(10)), 0.0);
    }
}
