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
    net::NetTracker,
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
    pub freeze_min_secs: f64,  // freeze: wall-clock seconds before it counts
    pub freeze_jump_bound: i64, // freeze: slot jump this big = discontinuity
}

/// One output per disk window, carrying the latest validator sample.
pub async fn combine(
    mut disk_rx: Receiver<WindowStats>,
    mut rpc_rx: Receiver<Sample>,
    json_mode: bool,
    thresholds: Thresholds,
    mut net: NetTracker,
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
                    let net_sample = net.sample();
                    emit(&w, latest.as_ref(), json_mode, started, &signals, &net_sample);
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
    slot_frozen: bool,
    drift: Option<DriftInfo>,
    slot_state: SlotState,
}

impl WindowSignals {
    fn triggered_by(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.lag_elevated {
            v.push("lag");
        }
        if self.slot_frozen {
            v.push("freeze");
        }
        v
    }
}

/// What observe_disk actually compared against, so drift can report the same
/// number it decided with (not a value recomputed after mutating history).
struct DiskObservation {
    elevated: bool,
    baseline_ns: u64,
}

struct LagObservation {
    elevated: bool,
    lag_norm: i64,
}

#[derive(Clone, Copy)]
struct SlotState {
    advance: i64,
    frozen: bool,
    freeze_windows: u32,
    freeze_duration_s: f64,
}

struct DriftDetector {
    thresholds: Thresholds,
    p99_history: VecDeque<u64>, // disk baseline
    disk_streak: u32,
    lag_history: VecDeque<i64>, // lag norm
    slot: SlotTracker,
}

struct SlotTracker {
    prev_slot: Option<u64>,
    freeze_windows: u32,
    freeze_started_at: Option<Instant>,
    freeze_announced: bool, // one-shot: already logged this episode's freeze
}

impl DriftDetector {
    fn new(thresholds: Thresholds) -> Self {
        Self {
            thresholds,
            p99_history: VecDeque::new(),
            disk_streak: 0,
            lag_history: VecDeque::new(),
            slot: SlotTracker {
                prev_slot: None,
                freeze_windows: 0,
                freeze_started_at: None,
                freeze_announced: false,
            },
        }
    }

    fn observe(&mut self, w: &WindowStats, v: Option<&Sample>) -> WindowSignals {
        let disk_obs = self.observe_disk(w);

        let lag = match v {
            Some(Sample::Up(s)) => Some(s.vote_lag),
            Some(Sample::Down { .. }) => Some(i64::MAX), // down = worst case
            None => None,
        };
        let lag_obs = lag.map(|l| self.observe_lag(l));

        // freeze tracking advances only on a real slot reading (Sample::Up);
        // an RPC outage pauses it rather than advancing or resetting it
        let up_slot = match v {
            Some(Sample::Up(s)) => Some(s.network_slot),
            _ => None,
        };
        let slot_state = self.observe_slot(up_slot);
        let slot_frozen = slot_state.freeze_duration_s >= self.thresholds.freeze_min_secs;
        if slot_frozen && !self.slot.freeze_announced {
            self.slot.freeze_announced = true;
            eprintln!(
                "!! FREEZE: slot has not advanced for {:.1}s ({} windows)",
                slot_state.freeze_duration_s, slot_state.freeze_windows
            );
        }

        let drift = (self.p99_history.len() >= MIN_HISTORY).then(|| DriftInfo {
            p99_ns: w.p99_ns,
            baseline_ns: disk_obs.baseline_ns.max(1),
            streak: self.disk_streak,
            lag: lag.unwrap_or(0),
            lag_norm: lag_obs.as_ref().map(|o| o.lag_norm).unwrap_or(0),
            lead_signal: disk_obs.elevated.then_some("disk"),
        });

        WindowSignals {
            disk_elevated: disk_obs.elevated,
            lag_elevated: lag_obs.map(|o| o.elevated).unwrap_or(false),
            slot_frozen,
            drift,
            slot_state,
        }
    }

    /// Needs `streak` consecutive elevated windows. Idle windows: no data, no change.
    /// Reports the baseline it actually compared against (pre-push), so drift
    /// never shows a number contaminated by this window's own value.
    fn observe_disk(&mut self, w: &WindowStats) -> DiskObservation {
        if w.reqs == 0 {
            return DiskObservation {
                elevated: false,
                baseline_ns: median_u64(&self.p99_history),
            };
        }
        let baseline = median_u64(&self.p99_history); // snapshot before any push
        let baseline_ready = self.p99_history.len() >= MIN_HISTORY;
        let raw_elevated = baseline_ready
            && w.p99_ns > baseline.saturating_mul(self.thresholds.elevation_factor)
            && w.p99_ns > self.thresholds.p99_floor_ns;
        if raw_elevated {
            self.disk_streak += 1;
        } else {
            self.disk_streak = 0;
            // don't remember elevated windows, would poison the baseline
            push_capped(&mut self.p99_history, w.p99_ns);
        }
        DiskObservation {
            elevated: raw_elevated && self.disk_streak >= self.thresholds.streak,
            baseline_ns: baseline,
        }
    }

    /// No streak requirement: most lag episodes last one window.
    /// Reports the norm it actually compared against (pre-push).
    fn observe_lag(&mut self, lag: i64) -> LagObservation {
        let lag_norm = median_i64(&self.lag_history); // snapshot before any push
        let elevated = lag >= lag_norm + self.thresholds.lag_delta;
        if !elevated {
            push_capped(&mut self.lag_history, lag);
        }
        LagObservation { elevated, lag_norm }
    }

    /// Slot advance + freeze tracking. Only called with a real slot (Sample::Up).
    fn observe_slot(&mut self, slot: Option<u64>) -> SlotState {
        let Some(slot) = slot else {
            // no fresh sample this window: pause, report last known state
            return SlotState {
                advance: 0,
                frozen: false,
                freeze_windows: self.slot.freeze_windows,
                freeze_duration_s: self
                    .slot
                    .freeze_started_at
                    .map(|t| t.elapsed().as_secs_f64())
                    .unwrap_or(0.0),
            };
        };

        let Some(prev) = self.slot.prev_slot else {
            self.slot.prev_slot = Some(slot);
            return SlotState {
                advance: 0,
                frozen: false,
                freeze_windows: 0,
                freeze_duration_s: 0.0,
            };
        };

        let advance = slot as i64 - prev as i64;
        self.slot.prev_slot = Some(slot);

        if advance < 0 || advance > self.thresholds.freeze_jump_bound {
            eprintln!("!! DISCONTINUITY: slot jumped by {advance} (restart or resync)");
            self.slot.freeze_windows = 0;
            self.slot.freeze_started_at = None;
            self.slot.freeze_announced = false;
            return SlotState {
                advance,
                frozen: false,
                freeze_windows: 0,
                freeze_duration_s: 0.0,
            };
        }

        if advance == 0 {
            self.slot.freeze_windows += 1;
            self.slot.freeze_started_at.get_or_insert_with(Instant::now);
        } else {
            self.slot.freeze_windows = 0;
            self.slot.freeze_started_at = None;
            self.slot.freeze_announced = false;
        }

        SlotState {
            advance,
            frozen: advance == 0,
            freeze_windows: self.slot.freeze_windows,
            freeze_duration_s: self
                .slot
                .freeze_started_at
                .map(|t| t.elapsed().as_secs_f64())
                .unwrap_or(0.0),
        }
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
    net: &Option<crate::net::NetSample>,
) {
    if json_mode {
        println!("{}", to_json(w, v, signals, net));
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

fn to_json(
    w: &WindowStats,
    v: Option<&Sample>,
    signals: &WindowSignals,
    net: &Option<crate::net::NetSample>,
) -> String {
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
    let net_json = match net {
        Some(n) => json!({
            "iface": &n.iface,
            "rx_packets": n.rx_packets, "rx_bytes": n.rx_bytes, "rx_errs": n.rx_errs,
            "rx_drop": n.rx_drop, "rx_fifo": n.rx_fifo,
            "tx_packets": n.tx_packets, "tx_drop": n.tx_drop,
            "softnet_processed": n.softnet_processed,
            "softnet_dropped": n.softnet_dropped,
            "softnet_time_squeeze": n.softnet_time_squeeze,
            "softnet_top_cpus": &n.softnet_top_cpus,
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
            "slot_frozen": signals.slot_frozen,
            "triggered_by": signals.triggered_by(),
        },
        "slot_state": {
            "advance": signals.slot_state.advance,
            "frozen": signals.slot_state.frozen,
            "freeze_windows": signals.slot_state.freeze_windows,
            "freeze_duration_s": signals.slot_state.freeze_duration_s,
        },
        "net": net_json,
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
