use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protection {
    #[default]
    Unknown,
    /// Protected apps run normally.
    Open,
    /// Protected apps are frozen / DNS-shielded.
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    None,
    Blocked,
    Opened,
}

/// Decides when the protected apps are blocked. Blocking is immediate; opening again needs the VPN to
/// stay up for `resume_checks` consecutive checks and any post-wake hold to have elapsed.
#[derive(Debug, Default)]
pub struct Guard {
    state: Protection,
    good: u32,
    /// When the current run of good checks began: routing events can fire many checks in a few milliseconds, so
    /// counting them is not enough, the VPN must also have stayed up for a while.
    good_since: Option<Instant>,
    hold_until: Option<Instant>,
}

impl Guard {
    pub fn state(&self) -> Protection {
        self.state
    }

    /// The Mac slept or stalled: whatever VPN state we last saw is stale, so block first.
    pub fn wake(&mut self, now: Instant, hold: Duration) -> Change {
        self.good = 0;
        self.good_since = None;
        self.hold_until = Some(now + hold);
        self.set(Protection::Blocked)
    }

    /// `stable_for`: how long the VPN must have been continuously up before the apps are resumed.
    pub fn observe(&mut self, vpn_up: bool, now: Instant, resume_checks: u32, stable_for: Duration) -> Change {
        if !vpn_up {
            self.good = 0;
            self.good_since = None;
            return self.set(Protection::Blocked);
        }
        self.good = self.good.saturating_add(1);
        let since = *self.good_since.get_or_insert(now);
        if self.hold_until.is_some_and(|until| now < until) {
            return self.set(Protection::Blocked);
        }
        self.hold_until = None;
        match self.state {
            Protection::Unknown => self.set(Protection::Open),
            Protection::Open => Change::None,
            Protection::Blocked if self.good >= resume_checks && now.duration_since(since) >= stable_for => {
                self.set(Protection::Open)
            }
            Protection::Blocked => Change::None,
        }
    }

    fn set(&mut self, new: Protection) -> Change {
        if self.state == new {
            return Change::None;
        }
        self.state = new;
        match new {
            Protection::Blocked => Change::Blocked,
            _ => Change::Opened,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOLD: Duration = Duration::from_secs(5);
const NO_WAIT: Duration = Duration::ZERO;

    #[test]
    fn opens_on_first_good_check_and_blocks_immediately() {
        let t = Instant::now();
        let mut g = Guard::default();
        assert_eq!(g.observe(true, t, 4, NO_WAIT), Change::Opened);
        assert_eq!(g.observe(true, t, 4, NO_WAIT), Change::None);
        assert_eq!(g.observe(false, t, 4, NO_WAIT), Change::Blocked);
        assert_eq!(g.observe(false, t, 4, NO_WAIT), Change::None);
        assert_eq!(g.state(), Protection::Blocked);
    }

    #[test]
    fn needs_consecutive_good_checks_to_resume() {
        let t = Instant::now();
        let mut g = Guard::default();
        g.observe(false, t, 4, NO_WAIT);
        for _ in 0..3 {
            assert_eq!(g.observe(true, t, 4, NO_WAIT), Change::None);
        }
        assert_eq!(g.observe(false, t, 4, NO_WAIT), Change::None, "a bad check resets the count");
        for _ in 0..3 {
            assert_eq!(g.observe(true, t, 4, NO_WAIT), Change::None);
        }
        assert_eq!(g.observe(true, t, 4, NO_WAIT), Change::Opened);
    }

    #[test]
    fn a_burst_of_checks_does_not_resume_before_the_vpn_was_stable() {
        let t = Instant::now();
        let stable = Duration::from_millis(750);
        let mut g = Guard::default();
        g.observe(false, t, 4, stable);
        for _ in 0..10 {
            assert_eq!(g.observe(true, t, 4, stable), Change::None, "ten checks in one instant");
        }
        assert_eq!(g.observe(true, t + Duration::from_millis(749), 4, stable), Change::None);
        assert_eq!(g.observe(true, t + stable, 4, stable), Change::Opened);
    }

    #[test]
    fn wake_blocks_even_when_the_vpn_looks_fine() {
        let t = Instant::now();
        let mut g = Guard::default();
        g.observe(true, t, 4, NO_WAIT);
        assert_eq!(g.wake(t, HOLD), Change::Blocked);
        // stale tunnel still reported as up: stays blocked during the hold, however many checks pass
        for _ in 0..10 {
            assert_eq!(g.observe(true, t + Duration::from_secs(2), 4, NO_WAIT), Change::None);
        }
        assert_eq!(g.state(), Protection::Blocked);
        // hold over and enough good checks accumulated
        assert_eq!(g.observe(true, t + HOLD, 4, NO_WAIT), Change::Opened);
    }

    #[test]
    fn wake_while_already_blocked_is_not_a_new_change() {
        let t = Instant::now();
        let mut g = Guard::default();
        g.observe(false, t, 4, NO_WAIT);
        assert_eq!(g.wake(t, HOLD), Change::None);
    }

    #[test]
    fn down_during_hold_keeps_blocking() {
        let t = Instant::now();
        let mut g = Guard::default();
        g.observe(true, t, 1, NO_WAIT);
        g.wake(t, HOLD);
        g.observe(false, t, 1, NO_WAIT);
        assert_eq!(g.observe(true, t + HOLD, 1, NO_WAIT), Change::Opened, "good=1 after the hold is enough for resume_checks=1");
    }
}
