// Network ingest counters: /proc/net/dev + /proc/net/softnet_stat, delta per
// window. Both are sub-millisecond synchronous reads, called straight from
// the disk-window cadence, no separate task needed.

use std::{collections::HashMap, fs};

pub struct NetTracker {
    iface: String,
    prev: Option<Raw>,
    last_err: Option<String>,
}

#[derive(Clone)]
struct Raw {
    dev: DevCounters,
    softnet: SoftnetCounters,
}

#[derive(Clone, Copy, Default)]
struct DevCounters {
    rx_bytes: u64,
    rx_packets: u64,
    rx_errs: u64,
    rx_drop: u64,
    rx_fifo: u64,
    tx_packets: u64,
    tx_drop: u64,
}

#[derive(Clone, Default)]
struct SoftnetCounters {
    processed: u64,
    dropped: u64,
    time_squeeze: u64,
    per_cpu_squeeze: HashMap<u32, u64>, // cpu id -> time_squeeze
}

/// One window's network deltas. None fields mean "couldn't compute this tick"
/// (first tick, wraparound, or a read/parse failure), never a fabricated 0.
#[derive(Default)]
pub struct NetSample {
    pub iface: String,
    pub rx_packets: Option<i64>,
    pub rx_bytes: Option<i64>,
    pub rx_errs: Option<i64>,
    pub rx_drop: Option<i64>,
    pub rx_fifo: Option<i64>,
    pub tx_packets: Option<i64>,
    pub tx_drop: Option<i64>,
    pub softnet_processed: Option<i64>,
    pub softnet_dropped: Option<i64>,
    pub softnet_time_squeeze: Option<i64>,
    pub softnet_top_cpus: Vec<(u32, u64)>, // top 3 by this-window squeeze delta
}

impl NetTracker {
    pub fn new(iface: String) -> Self {
        Self {
            iface,
            prev: None,
            last_err: None,
        }
    }

    /// One window's sample. Never panics: any failure logs once and returns None.
    pub fn sample(&mut self) -> Option<NetSample> {
        let raw = match self.read_raw() {
            Ok(r) => {
                self.last_err = None;
                r
            }
            Err(e) => {
                if self.last_err.as_deref() != Some(&e) {
                    eprintln!("WARN: net read failed: {e}");
                    self.last_err = Some(e);
                }
                return None;
            }
        };

        let prev = match self.prev.replace(raw.clone()) {
            Some(p) => p,
            None => return None, // first tick: no delta yet
        };

        let dev_delta = |cur: u64, prev: u64| -> Option<i64> {
            if cur < prev {
                None // wraparound: null this field, prev already replaced above
            } else {
                Some((cur - prev) as i64)
            }
        };

        let mut sample = NetSample {
            iface: self.iface.clone(),
            rx_packets: dev_delta(raw.dev.rx_packets, prev.dev.rx_packets),
            rx_bytes: dev_delta(raw.dev.rx_bytes, prev.dev.rx_bytes),
            rx_errs: dev_delta(raw.dev.rx_errs, prev.dev.rx_errs),
            rx_drop: dev_delta(raw.dev.rx_drop, prev.dev.rx_drop),
            rx_fifo: dev_delta(raw.dev.rx_fifo, prev.dev.rx_fifo),
            tx_packets: dev_delta(raw.dev.tx_packets, prev.dev.tx_packets),
            tx_drop: dev_delta(raw.dev.tx_drop, prev.dev.tx_drop),
            softnet_processed: dev_delta(raw.softnet.processed, prev.softnet.processed),
            softnet_dropped: dev_delta(raw.softnet.dropped, prev.softnet.dropped),
            softnet_time_squeeze: dev_delta(raw.softnet.time_squeeze, prev.softnet.time_squeeze),
            softnet_top_cpus: Vec::new(),
        };

        // per-CPU squeeze delta: only for CPUs present in both readings
        let mut per_cpu: Vec<(u32, u64)> = raw
            .softnet
            .per_cpu_squeeze
            .iter()
            .filter_map(|(&cpu, &cur)| {
                let prev_v = *prev.softnet.per_cpu_squeeze.get(&cpu)?;
                (cur >= prev_v).then_some((cpu, cur - prev_v))
            })
            .collect();
        per_cpu.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        per_cpu.truncate(3);
        sample.softnet_top_cpus = per_cpu;

        Some(sample)
    }

    fn read_raw(&self) -> Result<Raw, String> {
        Ok(Raw {
            dev: read_dev(&self.iface)?,
            softnet: read_softnet()?,
        })
    }
}

/// /proc/net/dev: "iface: rx_bytes rx_packets rx_errs rx_drop rx_fifo ... tx_bytes tx_packets tx_errs tx_drop ..."
fn read_dev(iface: &str) -> Result<DevCounters, String> {
    let text = fs::read_to_string("/proc/net/dev").map_err(|e| format!("/proc/net/dev: {e}"))?;
    for line in text.lines() {
        let Some((name, stats)) = line.split_once(':') else {
            continue; // header lines have no ':'
        };
        if name.trim() != iface {
            continue;
        }
        let f: Vec<u64> = stats
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();
        if f.len() < 12 {
            return Err(format!("{iface}: unexpected /proc/net/dev field count"));
        }
        return Ok(DevCounters {
            rx_bytes: f[0],
            rx_packets: f[1],
            rx_errs: f[2],
            rx_drop: f[3],
            rx_fifo: f[4],
            tx_packets: f[9],
            tx_drop: f[11],
        });
    }
    Err(format!("{iface}: not found in /proc/net/dev"))
}

/// /proc/net/softnet_stat: one line per CPU, hex fields, no header.
/// col 0 = processed, 1 = dropped, 2 = time_squeeze, last = cpu index (5.11+).
fn read_softnet() -> Result<SoftnetCounters, String> {
    let text =
        fs::read_to_string("/proc/net/softnet_stat").map_err(|e| format!("softnet_stat: {e}"))?;
    let mut out = SoftnetCounters::default();
    for (line_idx, line) in text.lines().enumerate() {
        let f: Vec<u64> = line
            .split_whitespace()
            .filter_map(|s| u64::from_str_radix(s, 16).ok())
            .collect();
        if f.len() < 3 {
            continue; // malformed line: skip it, don't fail the whole read
        }
        out.processed += f[0];
        out.dropped += f[1];
        out.time_squeeze += f[2];
        // prefer the explicit trailing CPU index (5.11+); fall back to line order
        let cpu = f.last().copied().unwrap_or(line_idx as u64) as u32;
        out.per_cpu_squeeze.insert(cpu, f[2]);
    }
    if out.per_cpu_squeeze.is_empty() {
        return Err("softnet_stat: no parsable rows".into());
    }
    Ok(out)
}
