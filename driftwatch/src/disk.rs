// Consume DiskEvents off the kernel ringbuf, emit one WindowStats per window.
// The caller decides what to do with them (print, or feed the correlator).
// --raw also prints every event.

use std::time::Duration;

use anyhow::Result;
use aya::maps::{MapData, PerCpuArray, RingBuf};
use driftwatch_common::{DiskEvent, RW_READ, RW_WRITE};
use tokio::{io::unix::AsyncFd, sync::mpsc::Sender};

/// Two wake sources: the kernel says data is ready, so drain it into the
/// window, or the ticker fires, so finish the window, send its stats,
/// and start fresh.
pub async fn consume(
    ring: RingBuf<MapData>,
    window_secs: u64,
    raw: bool,
    tx: Sender<WindowStats>,
) -> Result<()> {
    let mut ring_fd = AsyncFd::with_interest(ring, tokio::io::Interest::READABLE)?;
    let mut window = Window::default();
    let mut ticker = tokio::time::interval(Duration::from_secs(window_secs));
    // first tick fires instantly
    ticker.tick().await;

    loop {
        tokio::select! {
            guard = ring_fd.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    let ev = read_event(&item);
                    if raw {
                        println!("{}", format_event(&ev));
                    }
                    window.add(&ev);
                }
                // re-arm; without this the loop spins at 100% CPU
                guard.clear_ready();
            }
            _ = ticker.tick() => {
                let stats = std::mem::take(&mut window).finish(window_secs);
                if tx.send(stats).await.is_err() {
                    return Ok(()); // receiver gone, we're shutting down
                }
            }
        }
    }
}

/// One finished window, numbers precomputed.
#[derive(Debug, Clone)]
pub struct WindowStats {
    pub window_secs: u64,
    pub reqs: usize,
    pub writes: u64,
    pub reads: u64,
    pub others: u64,
    pub bytes: u64,
    pub errors: u64,
    pub dev: Option<u32>,
    pub p50_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
}

/// Full line for `watch`:
/// disk 253:16 | 5s | 81 reqs (81W/0R/0O) | p50 62µs | p99 4.2ms | max 4.2ms | 1.2 MB/s
pub fn format_stats(s: &WindowStats) -> String {
    let dev = match s.dev {
        Some(d) => format!("{}:{}", d >> 20, d & ((1 << 20) - 1)),
        None => String::new(),
    };
    if s.reqs == 0 {
        return format!("disk {dev} | {}s | idle", s.window_secs);
    }
    let mbps = s.bytes as f64 / (1024.0 * 1024.0) / s.window_secs as f64;
    let err = if s.errors > 0 {
        format!(" | ERRORS {}", s.errors)
    } else {
        String::new()
    };
    format!(
        "disk {dev} | {}s | {} reqs ({}W/{}R/{}O) | p50 {} | p99 {} | max {} | {mbps:.1} MB/s{err}",
        s.window_secs,
        s.reqs,
        s.writes,
        s.reads,
        s.others,
        human_latency(s.p50_ns),
        human_latency(s.p99_ns),
        human_latency(s.max_ns),
    )
}

/// Short form for the combined timeline:
/// disk p99 4.2ms | 81 reqs | 1.2 MB/s      (or "disk idle")
pub fn compact_stats(s: &WindowStats) -> String {
    if s.reqs == 0 {
        return "disk idle".into();
    }
    let mbps = s.bytes as f64 / (1024.0 * 1024.0) / s.window_secs as f64;
    let err = if s.errors > 0 {
        format!(" | ERR {}", s.errors)
    } else {
        String::new()
    };
    format!(
        "disk p99 {} | {} reqs | {mbps:.1} MB/s{err}",
        human_latency(s.p99_ns),
        s.reqs
    )
}

/// Events accumulated over one window.
#[derive(Default)]
struct Window {
    latencies_ns: Vec<u64>,
    reads: u64,
    writes: u64,
    others: u64,
    bytes: u64,
    errors: u64,
    dev: Option<u32>, // seen device
}

impl Window {
    fn add(&mut self, ev: &DiskEvent) {
        self.latencies_ns.push(ev.latency_ns);
        match ev.rw {
            RW_READ => self.reads += 1,
            RW_WRITE => self.writes += 1,
            _ => self.others += 1,
        }
        self.bytes += ev.bytes as u64;
        if ev.error != 0 {
            self.errors += 1;
        }
        self.dev.get_or_insert(ev.dev);
    }

    /// Close the window: sort once, take percentiles at 50% / 99%.
    fn finish(mut self, window_secs: u64) -> WindowStats {
        let n = self.latencies_ns.len();
        let (p50, p99, max) = if n == 0 {
            (0, 0, 0)
        } else {
            self.latencies_ns.sort_unstable();
            (
                self.latencies_ns[n / 2],
                self.latencies_ns[(n * 99 / 100).min(n - 1)],
                self.latencies_ns[n - 1],
            )
        };
        WindowStats {
            window_secs,
            reqs: n,
            writes: self.writes,
            reads: self.reads,
            others: self.others,
            bytes: self.bytes,
            errors: self.errors,
            dev: self.dev,
            p50_ns: p50,
            p99_ns: p99,
            max_ns: max,
        }
    }
}

/// Turn raw ringbuf bytes into a DiskEvent (kernel and daemon share the
/// same struct layout, so this is safe).
fn read_event(item: &[u8]) -> DiskEvent {
    unsafe { std::ptr::read_unaligned(item.as_ptr().cast()) }
}

/// Warn when the kernel's drop counter grows (events were lost).
pub async fn watch_drops(drops: PerCpuArray<MapData, u64>) {
    let mut last: u64 = 0;
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        ticker.tick().await;
        // one slot, one value per CPU — sum them
        let total: u64 = match drops.get(&0, 0) {
            Ok(per_cpu) => per_cpu.iter().sum(),
            Err(_) => continue,
        };
        if total > last {
            eprintln!(
                "WARN: ringbuf dropped {} events (total {total})",
                total - last
            );
            last = total;
        }
    }
}

/// Raw mode line, e.g: disk 253:16 W 4.0K 812µs
fn format_event(ev: &DiskEvent) -> String {
    let rw = match ev.rw {
        RW_READ => 'R',
        RW_WRITE => 'W',
        _ => 'O',
    };
    let major = ev.dev >> 20;
    let minor = ev.dev & ((1 << 20) - 1);
    let err = if ev.error != 0 {
        format!(" ERR={}", ev.error)
    } else {
        String::new()
    };
    format!(
        "disk {major}:{minor} {rw} {} {}{err}",
        size(ev.bytes),
        human_latency(ev.latency_ns),
    )
}

pub fn human_latency(ns: u64) -> String {
    if ns >= 1_000_000 {
        format!("{:.1}ms", ns as f64 / 1e6)
    } else {
        format!("{}µs", ns / 1_000)
    }
}

fn size(bytes: u32) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}K", bytes as f64 / 1024.0)
    }
}
