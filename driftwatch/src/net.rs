// Network ingest, layers 1-3 (pure /proc + /sys reads, no eBPF). Layer 4
// (per-socket -> agave role attribution) is P1, not implemented here yet;
// `sockets` is always emitted empty until it lands.
//
// All counters are cumulative-since-boot: emit deltas over the window, and
// flag counters_reset when any counter went backwards (reboot / iface reset,
// delta meaningless that window).

use std::collections::HashMap;
use std::fs;

pub struct NetTracker {
    iface: String,
    prev: Option<Raw>,
    last_err: Option<String>,
    parse_errors: u64, // cumulative count of failed reads since start
}

#[derive(Clone, Default)]
struct Raw {
    ring: RingCounters,
    softnet: SoftnetCounters,
    snmp_udp: SnmpUdpCounters,
}

#[derive(Clone, Copy, Default)]
struct RingCounters {
    rx_missed_errors: u64,
    rx_dropped: u64,
    rx_errors: u64,
    rx_fifo_errors: u64,
}

#[derive(Clone, Default)]
struct SoftnetCounters {
    processed: u64,
    dropped: u64,
    time_squeeze: u64,
    per_cpu_time_squeeze: HashMap<u32, u64>,
}

#[derive(Clone, Copy, Default)]
struct SnmpUdpCounters {
    in_datagrams: u64,
    in_errors: u64,
    rcvbuf_errors: u64,
    sndbuf_errors: u64,
    no_ports: u64,
}

#[derive(Default)]
pub struct NetSample {
    pub iface: String,
    pub is_xdp: Option<bool>,
    pub counters_reset: bool,
    pub ring: RingDelta,
    pub softnet: SoftnetDelta,
    pub snmp_udp: SnmpUdpDelta,
}

#[derive(Default, Clone, Copy)]
pub struct RingDelta {
    pub rx_missed_errors: u64,
    pub rx_dropped: u64,
    pub rx_errors: u64,
    pub rx_fifo_errors: u64,
}

#[derive(Default, Clone, Copy)]
pub struct SoftnetDelta {
    pub processed: u64,
    pub dropped: u64,
    pub time_squeeze: u64,
    pub time_squeeze_max_cpu: u64, // highest single-CPU delta this window
    pub max_cpu_id: u32,
}

#[derive(Default, Clone, Copy)]
pub struct SnmpUdpDelta {
    pub in_datagrams: u64,
    pub in_errors: u64,
    pub rcvbuf_errors: u64,
    pub sndbuf_errors: u64,
    pub no_ports: u64,
}

impl NetTracker {
    pub fn new(iface: String) -> Self {
        Self {
            iface,
            prev: None,
            last_err: None,
            parse_errors: 0,
        }
    }

    /// Cumulative count of failed reads since start, regardless of which window.
    pub fn parse_errors(&self) -> u64 {
        self.parse_errors
    }

    /// One window's sample. Never panics: any failure logs once and returns None.
    pub fn sample(&mut self) -> Option<NetSample> {
        let raw = match self.read_raw() {
            Ok(r) => {
                self.last_err = None;
                r
            }
            Err(e) => {
                self.parse_errors += 1;
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

        let reset = raw.ring.rx_missed_errors < prev.ring.rx_missed_errors
            || raw.ring.rx_dropped < prev.ring.rx_dropped
            || raw.ring.rx_errors < prev.ring.rx_errors
            || raw.ring.rx_fifo_errors < prev.ring.rx_fifo_errors
            || raw.softnet.processed < prev.softnet.processed
            || raw.softnet.dropped < prev.softnet.dropped
            || raw.softnet.time_squeeze < prev.softnet.time_squeeze
            || raw.snmp_udp.in_datagrams < prev.snmp_udp.in_datagrams
            || raw.snmp_udp.in_errors < prev.snmp_udp.in_errors
            || raw.snmp_udp.rcvbuf_errors < prev.snmp_udp.rcvbuf_errors
            || raw.snmp_udp.sndbuf_errors < prev.snmp_udp.sndbuf_errors
            || raw.snmp_udp.no_ports < prev.snmp_udp.no_ports;
        if reset {
            return Some(NetSample {
                iface: self.iface.clone(),
                is_xdp: detect_is_xdp(&self.iface),
                counters_reset: true,
                ..Default::default()
            });
        }

        let mut max_cpu_delta = 0u64;
        let mut max_cpu_id = 0u32;
        for (&cpu, &cur) in &raw.softnet.per_cpu_time_squeeze {
            if let Some(&prev_v) = prev.softnet.per_cpu_time_squeeze.get(&cpu) {
                let delta = cur.saturating_sub(prev_v);
                if delta > max_cpu_delta {
                    max_cpu_delta = delta;
                    max_cpu_id = cpu;
                }
            }
        }

        Some(NetSample {
            iface: self.iface.clone(),
            is_xdp: detect_is_xdp(&self.iface),
            counters_reset: false,
            ring: RingDelta {
                rx_missed_errors: raw.ring.rx_missed_errors - prev.ring.rx_missed_errors,
                rx_dropped: raw.ring.rx_dropped - prev.ring.rx_dropped,
                rx_errors: raw.ring.rx_errors - prev.ring.rx_errors,
                rx_fifo_errors: raw.ring.rx_fifo_errors - prev.ring.rx_fifo_errors,
            },
            softnet: SoftnetDelta {
                processed: raw.softnet.processed - prev.softnet.processed,
                dropped: raw.softnet.dropped - prev.softnet.dropped,
                time_squeeze: raw.softnet.time_squeeze - prev.softnet.time_squeeze,
                time_squeeze_max_cpu: max_cpu_delta,
                max_cpu_id,
            },
            snmp_udp: SnmpUdpDelta {
                in_datagrams: raw.snmp_udp.in_datagrams - prev.snmp_udp.in_datagrams,
                in_errors: raw.snmp_udp.in_errors - prev.snmp_udp.in_errors,
                rcvbuf_errors: raw.snmp_udp.rcvbuf_errors - prev.snmp_udp.rcvbuf_errors,
                sndbuf_errors: raw.snmp_udp.sndbuf_errors - prev.snmp_udp.sndbuf_errors,
                no_ports: raw.snmp_udp.no_ports - prev.snmp_udp.no_ports,
            },
        })
    }

    fn read_raw(&self) -> Result<Raw, String> {
        Ok(Raw {
            ring: read_ring(&self.iface)?,
            softnet: read_softnet()?,
            snmp_udp: read_snmp_udp()?,
        })
    }
}

/// Layer 1: /sys/class/net/<iface>/statistics/* (NIC ring counters).
fn read_ring(iface: &str) -> Result<RingCounters, String> {
    let base = format!("/sys/class/net/{iface}/statistics");
    let read_one = |name: &str| -> Result<u64, String> {
        let path = format!("{base}/{name}");
        fs::read_to_string(&path)
            .map_err(|e| format!("{path}: {e}"))?
            .trim()
            .parse()
            .map_err(|e| format!("{path}: bad value: {e}"))
    };
    Ok(RingCounters {
        rx_missed_errors: read_one("rx_missed_errors")?,
        rx_dropped: read_one("rx_dropped")?,
        rx_errors: read_one("rx_errors")?,
        rx_fifo_errors: read_one("rx_fifo_errors")?,
    })
}

/// Layer 2: /proc/net/softnet_stat. One line per CPU, hex, no header.
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
        let cpu = f.last().copied().unwrap_or(line_idx as u64) as u32;
        out.per_cpu_time_squeeze.insert(cpu, f[2]);
    }
    if out.per_cpu_time_squeeze.is_empty() {
        return Err("softnet_stat: no parsable rows".into());
    }
    Ok(out)
}

/// Layer 3: /proc/net/snmp, "Udp:" section. Parsed by column name (from the
/// header line) not position, since the column set has grown across kernels.
fn read_snmp_udp() -> Result<SnmpUdpCounters, String> {
    let text = fs::read_to_string("/proc/net/snmp").map_err(|e| format!("snmp: {e}"))?;
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if !line.starts_with("Udp:") {
            continue;
        }
        let header: Vec<&str> = line.split_whitespace().skip(1).collect();
        let values: Vec<&str> = lines
            .next()
            .ok_or("snmp: Udp header with no values line")?
            .split_whitespace()
            .skip(1)
            .collect();
        let get = |name: &str| -> u64 {
            header
                .iter()
                .position(|&c| c == name)
                .and_then(|i| values.get(i))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
        };
        return Ok(SnmpUdpCounters {
            in_datagrams: get("InDatagrams"),
            in_errors: get("InErrors"),
            rcvbuf_errors: get("RcvbufErrors"),
            sndbuf_errors: get("SndbufErrors"),
            no_ports: get("NoPorts"),
        });
    }
    Err("snmp: no Udp: section found".into())
}

/// Is an XDP program attached to this interface right now. None if the
/// kernel doesn't expose the file (older kernel or driver).
fn detect_is_xdp(iface: &str) -> Option<bool> {
    let path = format!("/sys/class/net/{iface}/xdp/prog_id");
    let id = fs::read_to_string(path).ok()?;
    Some(id.trim() != "0" && !id.trim().is_empty())
}

/// Every path `--check` should verify is readable before a real run.
pub fn check_paths(iface: &str) -> Vec<String> {
    let mut paths = vec![
        format!("/sys/class/net/{iface}/statistics/rx_missed_errors"),
        format!("/sys/class/net/{iface}/statistics/rx_dropped"),
        format!("/sys/class/net/{iface}/statistics/rx_errors"),
        format!("/sys/class/net/{iface}/statistics/rx_fifo_errors"),
        "/proc/net/softnet_stat".to_string(),
        "/proc/net/snmp".to_string(),
    ];
    paths.sort();
    paths
}

/// Primary interface, from the kernel's default route. Used when --iface isn't given.
pub fn detect_iface() -> Result<String, String> {
    let text = fs::read_to_string("/proc/net/route").map_err(|e| format!("route: {e}"))?;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // col 0 = iface, col 1 = destination (hex); 00000000 = default route
        if cols.len() > 1 && cols[1] == "00000000" {
            return Ok(cols[0].to_string());
        }
    }
    Err("no default route found; pass --iface explicitly".into())
}
