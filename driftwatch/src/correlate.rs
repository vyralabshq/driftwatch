// One line (or JSON) per disk window, validator sample attached.
// Disk and lag are independent signals. Disk never triggers on its own.

use std::{
    collections::VecDeque,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use serde_json::json;
use tokio::sync::mpsc::Receiver;

use crate::{
    disk::{WindowStats, compact_stats},
    output,
    rpc::{Sample, ValidatorSample},
};

const HISTORY: usize = 20; // baseline memory (windows)
const MIN_HISTORY: usize = 5; // don't judge before this much normal history

/// Disk/lag elevation thresholds, set via CLI flags.
#[derive(Clone, Copy)]
pub struct Thresholds {
    pub elevation_factor: u64, // disk: multiple of baseline
    pub p99_floor_ns: u64,     // disk: minimum floor
    pub streak: u32,           // disk: consecutive windows required
    pub lag_delta: i64,        // lag: slots over norm
}

/// One output per disk window, carrying the latest validator sample.
pub async fn combine(
    mut disk_rx: Receiver<WindowStats>,
    mut rpc_rx: Receiver<Sample>,
    json_mode: bool,
    thresholds: Thresholds,
) {
    let started = Instant::now();
    let mut latest: Option<Sample> = None;
    let mut detector = DriftDetector::new(thresholds);
    loop {
        tokio::select! {
            s = rpc_rx.recv() => match s {
                Some(s) => latest = Some(s),
                None => return,
            },
            w = disk_rx.recv() => match w {
                Some(w) => {
                    let signals = detector.observe(&w, latest.as_ref());
                    emit(&w, latest.as_ref(), json_mode, started, &signals);
                }
                None => return,
            },
        }
    }
}

/// Disk telemetry, computed every window once a baseline exists. Context, not a verdict.
struct DriftInfo {
    p99_ns: u64,
    baseline_ns: u64,
    streak: u32,
    lag: i64,
    lag_norm: i64,
    lead_signal: Option<&'static str>, // "disk" iff disk_elevated this window
}

/// disk_elevated never appears in triggered_by: disk doesn't predict votes.
struct WindowSignals {
    disk_elevated: bool,
    lag_elevated: bool,
    drift: Option<DriftInfo>,
}

impl WindowSignals {
    fn triggered_by(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.lag_elevated {
            v.push("lag");
        }
        v
    }
}

struct DriftDetector {
    thresholds: Thresholds,
    p99_history: VecDeque<u64>, // disk baseline
    disk_streak: u32,
    lag_history: VecDeque<i64>, // lag norm
}

impl DriftDetector {
    fn new(thresholds: Thresholds) -> Self {
        Self {
            thresholds,
            p99_history: VecDeque::new(),
            disk_streak: 0,
            lag_history: VecDeque::new(),
        }
    }

    fn observe(&mut self, w: &WindowStats, v: Option<&Sample>) -> WindowSignals {
        let disk_elevated = self.observe_disk(w);

        let lag = match v {
            Some(Sample::Up(s)) => Some(s.vote_lag),
            Some(Sample::Down { .. }) => Some(i64::MAX), // down = worst case
            None => None,
        };
        let lag_elevated = lag.map(|l| self.observe_lag(l)).unwrap_or(false);

        let drift = (self.p99_history.len() >= MIN_HISTORY).then(|| {
            let baseline = median_u64(&self.p99_history).max(1);
            let lag_norm = median_i64(&self.lag_history);
            DriftInfo {
                p99_ns: w.p99_ns,
                baseline_ns: baseline,
                streak: self.disk_streak,
                lag: lag.unwrap_or(0),
                lag_norm,
                lead_signal: disk_elevated.then_some("disk"),
            }
        });

        WindowSignals {
            disk_elevated,
            lag_elevated,
            drift,
        }
    }

    /// Needs `streak` consecutive elevated windows. Idle windows: no data, no change.
    fn observe_disk(&mut self, w: &WindowStats) -> bool {
        if w.reqs == 0 {
            return false;
        }
        let baseline_ready = self.p99_history.len() >= MIN_HISTORY;
        let raw_elevated = baseline_ready && {
            let baseline = median_u64(&self.p99_history);
            w.p99_ns > baseline.saturating_mul(self.thresholds.elevation_factor)
                && w.p99_ns > self.thresholds.p99_floor_ns
        };
        if raw_elevated {
            self.disk_streak += 1;
        } else {
            self.disk_streak = 0;
            // don't remember elevated windows, would poison the baseline
            push_capped(&mut self.p99_history, w.p99_ns);
        }
        raw_elevated && self.disk_streak >= self.thresholds.streak
    }

    /// No streak requirement: most lag episodes last one window.
    fn observe_lag(&mut self, lag: i64) -> bool {
        let lag_norm = median_i64(&self.lag_history);
        let elevated = lag >= lag_norm + self.thresholds.lag_delta;
        if !elevated {
            push_capped(&mut self.lag_history, lag);
        }
        elevated
    }
}

fn push_capped<T>(q: &mut VecDeque<T>, v: T) {
    if q.len() == HISTORY {
        q.pop_front();
    }
    q.push_back(v);
}

fn median_u64(q: &VecDeque<u64>) -> u64 {
    let mut v: Vec<u64> = q.iter().copied().collect();
    v.sort_unstable();
    if v.is_empty() { 0 } else { v[v.len() / 2] }
}

fn median_i64(q: &VecDeque<i64>) -> i64 {
    let mut v: Vec<i64> = q.iter().copied().collect();
    v.sort_unstable();
    if v.is_empty() { 0 } else { v[v.len() / 2] }
}

fn emit(
    w: &WindowStats,
    v: Option<&Sample>,
    json_mode: bool,
    started: Instant,
    signals: &WindowSignals,
) {
    if json_mode {
        println!("{}", to_json(w, v, signals));
    } else {
        let val = match v {
            Some(s) => output::compact(s),
            None => "validator: no sample yet".into(),
        };
        let triggered = signals.triggered_by();
        let suffix = if triggered.is_empty() {
            String::new()
        } else {
            format!(" | !! {}", triggered.join(","))
        };
        println!(
            "{} | {} || {}{}",
            elapsed(started),
            compact_stats(w),
            val,
            suffix
        );
    }
}

fn to_json(w: &WindowStats, v: Option<&Sample>, signals: &WindowSignals) -> String {
    let validator = match v {
        Some(Sample::Up(s)) => up_json(s),
        Some(Sample::Down { reason }) => json!({ "state": "down", "reason": reason }),
        None => serde_json::Value::Null,
    };
    let drift = match &signals.drift {
        Some(d) => json!({
            "p99_us": d.p99_ns / 1_000,
            "baseline_us": d.baseline_ns / 1_000,
            "factor": d.p99_ns / d.baseline_ns.max(1),
            "windows": d.streak,
            "lag": if d.lag == i64::MAX { serde_json::Value::Null } else { json!(d.lag) },
            "lag_norm": d.lag_norm,
            "lead_signal": d.lead_signal,
        }),
        None => serde_json::Value::Null,
    };
    json!({
        "ts": epoch_secs(),
        "disk": {
            "window_secs": w.window_secs,
            "reqs": w.reqs,
            "writes": w.writes,
            "reads": w.reads,
            "others": w.others,
            "bytes": w.bytes,
            "errors": w.errors,
            "p50_us": w.p50_ns / 1_000,
            "p99_us": w.p99_ns / 1_000,
            "max_us": w.max_ns / 1_000,
        },
        "validator": validator,
        "drift": drift,
        "signals": {
            "disk_elevated": signals.disk_elevated,
            "lag_elevated": signals.lag_elevated,
            "triggered_by": signals.triggered_by(),
        },
    })
    .to_string()
}

fn up_json(s: &ValidatorSample) -> serde_json::Value {
    json!({
        "state": output::state(s).to_lowercase(),
        "epoch": s.epoch,
        "slot": s.network_slot,
        "last_vote": s.my_last_vote,
        "vote_lag": s.vote_lag,
        "credits": s.credits,
        "delinquent": s.delinquent,
        "healthy": s.healthy,
    })
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Time since start, like "+02:41".
fn elapsed(started: Instant) -> String {
    let secs = started.elapsed().as_secs();
    if secs >= 3600 {
        format!("+{}:{:02}:{:02}", secs / 3600, (secs / 60) % 60, secs % 60)
    } else {
        format!("+{:02}:{:02}", secs / 60, secs % 60)
    }
}
