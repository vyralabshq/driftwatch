// One line (or JSON) per disk window, validator sample attached.
// Every alert is an independent static threshold. No composite alert, ever:
// AND-gating slow disk with high lag was the old design's actual defect,
// since disk latency does not reliably predict vote lag.

use std::{
    collections::VecDeque,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use libc::{RUSAGE_SELF, getrusage, rusage};

use serde_json::json;
use tokio::sync::mpsc::Receiver;

use crate::{
    disk::{WindowStats, compact_stats},
    net::{NetSample, NetTracker},
    output,
    rpc::{Sample, ValidatorSample},
    sockets::SocketSample,
};

const HISTORY: usize = 20; // depth of the informational disk-median window

/// Every alert threshold, set via CLI flags. Static: nothing here adapts.
#[derive(Clone, Copy)]
pub struct Thresholds {
    pub disk_latency_ns: u64,        // disk p99 over this = elevated
    pub disk_streak: u32,            // consecutive elevated windows required
    pub vote_lag: i64,               // absolute slots
    pub freeze_lookback: u32,        // windows, for freeze_in_last_n
    pub freeze_jump_bound: i64,      // slot jump this big = discontinuity
    pub ring_drop_threshold: u64,    // rx_missed_errors delta
    pub napi_squeeze_threshold: u64, // time_squeeze delta
    pub udp_rcvbuf_threshold: u64,   // RcvbufErrors delta
    pub socket_drop_threshold: u64,  // any single agave socket's drops delta
}

/// One output per disk window, carrying the latest validator sample.
/// dry_run: emit exactly one window then return, instead of looping forever.
/// self_metrics: attach driftwatch's own CPU time (user+sys) for that window.
pub async fn combine(
    mut disk_rx: Receiver<WindowStats>,
    mut rpc_rx: Receiver<Sample>,
    mut socket_rx: Receiver<SocketSample>,
    json_mode: bool,
    thresholds: Thresholds,
    mut net: NetTracker,
    dry_run: bool,
    self_metrics: bool,
) {
    let started = Instant::now();
    let mut latest: Option<Sample> = None;
    let mut latest_sockets: Option<SocketSample> = None;
    let mut engine = AlertEngine::new(thresholds);
    let mut cpu = self_metrics.then(SelfCpu::new);
    loop {
        tokio::select! {
            s = rpc_rx.recv() => match s {
                Some(s) => latest = Some(s),
                None => return,
            },
            s = socket_rx.recv() => match s {
                Some(s) => latest_sockets = Some(s),
                None => return,
            },
            w = disk_rx.recv() => match w {
                Some(w) => {
                    let disk = engine.observe_disk(&w);
                    let vote_lag_alert = engine.observe_lag(latest.as_ref());
                    let freeze = engine.observe_slot(latest.as_ref());
                    let net_sample = net.sample();
                    let alerts = build_alerts(&disk, vote_lag_alert, &freeze, &net_sample, latest_sockets.as_ref(), &thresholds);
                    let self_cpu_ms = cpu.as_mut().map(|c| c.delta_ms());
                    emit(&w, latest.as_ref(), json_mode, started, &disk, &freeze, &alerts, &net_sample, net.parse_errors(), self_cpu_ms, latest_sockets.as_ref());
                    if dry_run {
                        return;
                    }
                }
                None => return,
            },
        }
    }
}

/// Wraps getrusage(RUSAGE_SELF): real CPU time driftwatch itself burns,
/// not wall clock. Answers "is driftwatch perturbing the node."
struct SelfCpu {
    last_ms: i64,
}

impl SelfCpu {
    fn new() -> Self {
        Self { last_ms: total_cpu_ms() }
    }

    /// CPU ms consumed since the last call (or since new()).
    fn delta_ms(&mut self) -> u64 {
        let now = total_cpu_ms();
        let delta = (now - self.last_ms).max(0) as u64;
        self.last_ms = now;
        delta
    }
}

fn total_cpu_ms() -> i64 {
    let mut usage: rusage = unsafe { std::mem::zeroed() };
    unsafe { getrusage(RUSAGE_SELF, &mut usage) };
    let user_ms = usage.ru_utime.tv_sec * 1000 + usage.ru_utime.tv_usec / 1000;
    let sys_ms = usage.ru_stime.tv_sec * 1000 + usage.ru_stime.tv_usec / 1000;
    user_ms + sys_ms
}

/// Disk-side result: the alert decision plus the informational median.
/// The median is never a decision input itself, only a reported field.
struct DiskResult {
    alert: bool,
    median_us: Option<u64>,
}

struct FreezeState {
    freeze: bool,
    freeze_duration_ms: u64,
    freeze_in_last_n: u32,
}

struct AlertEngine {
    thresholds: Thresholds,
    disk_median_history: VecDeque<u64>, // informational only, no decisions branch on this
    disk_streak_count: u32,
    slot: SlotTracker,
}

struct SlotTracker {
    prev_slot: Option<u64>,
    freeze_started_at: Option<Instant>,
    recent_freezes: VecDeque<bool>,
    announced: bool, // one-shot stderr line per freeze episode
}

impl AlertEngine {
    fn new(thresholds: Thresholds) -> Self {
        Self {
            thresholds,
            disk_median_history: VecDeque::new(),
            disk_streak_count: 0,
            slot: SlotTracker {
                prev_slot: None,
                freeze_started_at: None,
                recent_freezes: VecDeque::new(),
                announced: false,
            },
        }
    }

    /// Idle windows (no requests): no new data, streak and median untouched.
    /// Non-elevated windows feed the median so it stays representative of
    /// "normal"; elevated windows don't (same reasoning as before, just no
    /// longer feeding a decision, only a reported field).
    fn observe_disk(&mut self, w: &WindowStats) -> DiskResult {
        if w.reqs == 0 {
            return DiskResult {
                alert: false,
                median_us: median_option(&self.disk_median_history),
            };
        }
        // snapshot before any push: the reported median must never include this window's own value
        let median_us = median_option(&self.disk_median_history);
        let over = w.p99_ns > self.thresholds.disk_latency_ns;
        if over {
            self.disk_streak_count += 1;
        } else {
            self.disk_streak_count = 0;
            push_capped(&mut self.disk_median_history, w.p99_ns, HISTORY);
        }
        DiskResult {
            alert: over && self.disk_streak_count >= self.thresholds.disk_streak.max(1),
            median_us,
        }
    }

    /// Absolute threshold, no baseline. Sample::Down counts as worst case.
    fn observe_lag(&self, v: Option<&Sample>) -> bool {
        let lag = match v {
            Some(Sample::Up(s)) => Some(s.vote_lag),
            Some(Sample::Down { .. }) => Some(i64::MAX),
            None => None,
        };
        lag.map(|l| l >= self.thresholds.vote_lag).unwrap_or(false)
    }

    fn observe_slot(&mut self, v: Option<&Sample>) -> FreezeState {
        let up_slot = match v {
            Some(Sample::Up(s)) => Some(s.network_slot),
            _ => None,
        };
        self.slot.observe(
            up_slot,
            self.thresholds.freeze_jump_bound,
            self.thresholds.freeze_lookback,
        )
    }
}

impl SlotTracker {
    /// Advances only on a real slot reading. An RPC outage pauses this
    /// (returns the last known state) rather than advancing or resetting it.
    fn observe(&mut self, slot: Option<u64>, jump_bound: i64, lookback: u32) -> FreezeState {
        let Some(slot) = slot else {
            return FreezeState {
                freeze: false,
                freeze_duration_ms: self.current_freeze_ms(),
                freeze_in_last_n: self.count_recent_freezes(),
            };
        };

        let Some(prev) = self.prev_slot else {
            self.prev_slot = Some(slot);
            return FreezeState {
                freeze: false,
                freeze_duration_ms: 0,
                freeze_in_last_n: 0,
            };
        };

        let advance = slot as i64 - prev as i64;
        self.prev_slot = Some(slot);

        if advance < 0 || advance > jump_bound {
            eprintln!("!! DISCONTINUITY: slot jumped by {advance} (restart or resync)");
            self.freeze_started_at = None;
            self.recent_freezes.clear();
            self.announced = false;
            return FreezeState {
                freeze: false,
                freeze_duration_ms: 0,
                freeze_in_last_n: 0,
            };
        }

        let frozen = advance == 0;
        if frozen {
            self.freeze_started_at.get_or_insert_with(Instant::now);
            if !self.announced {
                self.announced = true;
                eprintln!("!! FREEZE: slot stopped advancing");
            }
        } else {
            self.freeze_started_at = None;
            self.announced = false;
        }
        push_capped(&mut self.recent_freezes, frozen, lookback.max(1) as usize);

        FreezeState {
            freeze: frozen,
            freeze_duration_ms: self.current_freeze_ms(),
            freeze_in_last_n: self.count_recent_freezes(),
        }
    }

    fn current_freeze_ms(&self) -> u64 {
        self.freeze_started_at
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0)
    }

    fn count_recent_freezes(&self) -> u32 {
        self.recent_freezes.iter().filter(|&&f| f).count() as u32
    }
}

/// Independent alerts only. disk_latency/vote_lag/slot_freeze from the disk
/// window and validator sample; ring_drop/napi_squeeze/udp_rcvbuf from the
/// network layers (layers 1-3); socket_drop from layer 4, any single
/// agave-owned socket over threshold.
fn build_alerts(
    disk: &DiskResult,
    vote_lag_alert: bool,
    freeze: &FreezeState,
    net: &Option<NetSample>,
    sockets: Option<&SocketSample>,
    t: &Thresholds,
) -> Vec<&'static str> {
    let mut a = Vec::new();
    if disk.alert {
        a.push("disk_latency");
    }
    if vote_lag_alert {
        a.push("vote_lag");
    }
    if freeze.freeze {
        a.push("slot_freeze");
    }
    if let Some(n) = net {
        if n.ring.rx_missed_errors > t.ring_drop_threshold {
            a.push("ring_drop");
        }
        if n.softnet.time_squeeze > t.napi_squeeze_threshold {
            a.push("napi_squeeze");
        }
        if n.snmp_udp.rcvbuf_errors > t.udp_rcvbuf_threshold {
            a.push("udp_rcvbuf");
        }
    }
    if let Some(s) = sockets {
        if s.sockets.iter().any(|sock| sock.drops > t.socket_drop_threshold) {
            a.push("socket_drop");
        }
    }
    a
}

fn push_capped<T>(q: &mut VecDeque<T>, v: T, cap: usize) {
    let cap = cap.max(1);
    while q.len() >= cap {
        q.pop_front();
    }
    q.push_back(v);
}

fn median_option(q: &VecDeque<u64>) -> Option<u64> {
    if q.is_empty() {
        return None;
    }
    let mut v: Vec<u64> = q.iter().copied().collect();
    v.sort_unstable();
    Some(v[v.len() / 2] / 1_000) // convert nanoseconds to microseconds
}

fn emit(
    w: &WindowStats,
    v: Option<&Sample>,
    json_mode: bool,
    started: Instant,
    disk: &DiskResult,
    freeze: &FreezeState,
    alerts: &[&str],
    net: &Option<NetSample>,
    net_parse_errors: u64,
    self_cpu_ms: Option<u64>,
    sockets: Option<&SocketSample>,
) {
    if json_mode {
        println!("{}", to_json(w, v, disk, freeze, alerts, net, net_parse_errors, self_cpu_ms, sockets));
    } else {
        let val = match v {
            Some(s) => output::compact(s),
            None => "validator: no sample yet".into(),
        };
        let suffix = if alerts.is_empty() {
            String::new()
        } else {
            format!(" | !! {}", alerts.join(","))
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
    disk: &DiskResult,
    freeze: &FreezeState,
    alerts: &[&str],
    net: &Option<NetSample>,
    net_parse_errors: u64,
    self_cpu_ms: Option<u64>,
    sockets: Option<&SocketSample>,
) -> String {
    let validator = match v {
        Some(Sample::Up(s)) => up_json(s),
        Some(Sample::Down { reason }) => json!({ "state": "down", "reason": reason }),
        None => serde_json::Value::Null,
    };
    let sockets_json: Vec<_> = sockets
        .map(|s| {
            s.sockets
                .iter()
                .map(|sock| {
                    json!({
                        "port": sock.port,
                        "role": sock.role,
                        "drops": sock.drops,
                        "rx_queue": sock.rx_queue,
                        "tx_queue": sock.tx_queue,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let agave_pid = sockets.and_then(|s| s.pid);
    let net_json = match net {
        Some(n) => json!({
            "iface": &n.iface,
            "is_xdp": n.is_xdp,
            "ring": {
                "rx_missed_errors": n.ring.rx_missed_errors,
                "rx_dropped": n.ring.rx_dropped,
                "rx_errors": n.ring.rx_errors,
                "rx_fifo_errors": n.ring.rx_fifo_errors,
            },
            "softnet": {
                "processed": n.softnet.processed,
                "dropped": n.softnet.dropped,
                "time_squeeze": n.softnet.time_squeeze,
                "time_squeeze_max_cpu": n.softnet.time_squeeze_max_cpu,
                "max_cpu_id": n.softnet.max_cpu_id,
            },
            "snmp_udp": {
                "in_datagrams": n.snmp_udp.in_datagrams,
                "in_errors": n.snmp_udp.in_errors,
                "rcvbuf_errors": n.snmp_udp.rcvbuf_errors,
                "sndbuf_errors": n.snmp_udp.sndbuf_errors,
                "no_ports": n.snmp_udp.no_ports,
            },
            "sockets": sockets_json,
            "agave_pid": agave_pid,
            "ethtool": n.ethtool,
            "counters_reset": n.counters_reset,
            "parse_errors": net_parse_errors,
        }),
        None => serde_json::Value::Null,
    };
    json!({
        "ts": epoch_secs(),
        "schema_version": 2,
        "consensus": "towerbft",
        "self_cpu_ms": self_cpu_ms,
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
        "baseline": { "disk_p99_median_us": disk.median_us },
        "freeze": freeze.freeze,
        "freeze_duration_ms": freeze.freeze_duration_ms,
        "freeze_in_last_n": freeze.freeze_in_last_n,
        "alerts": alerts,
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
