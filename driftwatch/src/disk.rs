// Consume DiskEvents off the kernel ringbuf, print one summary line per window.
// --raw also prints every event.

use std::time::Duration;

use anyhow::Result;
use aya::maps::{MapData, PerCpuArray, RingBuf};
use driftwatch_common::{DiskEvent, RW_READ, RW_WRITE};
use tokio::io::unix::AsyncFd;

/// Two wake sources: kernel says "data ready" -> drain into the window;
/// ticker fires -> print summary, start fresh window.
pub async fn consume(ring: RingBuf<MapData>, window_secs: u64, raw: bool) -> Result<()> {
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
                println!("{}", window.summary(window_secs));
                window = Window::default();
            }
        }
    }
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

    /// e.g: disk 253:16 | 5s | 81 reqs (81W/0R/0O) | p50 62µs | p99 4.2ms | max 4.2ms | 1.2 MB/s
    fn summary(&mut self, window_secs: u64) -> String {
        let n = self.latencies_ns.len();
        let dev = match self.dev {
            Some(d) => format!("{}:{}", d >> 20, d & ((1 << 20) - 1)),
            None => String::new(),
        };
        if n == 0 {
            return format!("disk {dev} | {window_secs}s | idle");
        }

        // percentiles = sort, index at 50% / 99%
        self.latencies_ns.sort_unstable();
        let p50 = self.latencies_ns[n / 2];
        let p99 = self.latencies_ns[(n * 99 / 100).min(n - 1)];
        let max = self.latencies_ns[n - 1];

        let mbps = self.bytes as f64 / (1024.0 * 1024.0) / window_secs as f64;
        let err = if self.errors > 0 {
            format!(" | ERRORS {}", self.errors)
        } else {
            String::new()
        };

        format!(
            "disk {dev} | {window_secs}s | {n} reqs ({}W/{}R/{}O) | p50 {} | p99 {} | max {} | {mbps:.1} MB/s{err}",
            self.writes,
            self.reads,
            self.others,
            latency(p50),
            latency(p99),
            latency(max),
        )
    }
}

/// Ringbuf bytes -> DiskEvent. Safe: both sides compile the same
/// #[repr(C)] struct from driftwatch-common.
fn read_event(item: &[u8]) -> DiskEvent {
    unsafe { std::ptr::read_unaligned(item.as_ptr().cast()) }
}

/// Warn when the kernel's drop counter grows (ringbuf overflowed = stats lied).
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
        latency(ev.latency_ns),
    )
}

fn latency(ns: u64) -> String {
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
