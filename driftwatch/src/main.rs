mod disk;
mod output;
mod rpc;

use std::time::Duration;

use anyhow::Result;
use aya::programs::TracePoint;
use clap::{Parser, Subcommand};
use log::debug;
use tokio::signal;

#[derive(Parser)]
#[command(
    name = "driftwatch",
    about = "eBPF disk profiler + validator RPC context"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Poll the validator's RPC and print a live status line. No eBPF.
    Poll {
        /// Validator JSON-RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        rpc: String,
        /// Vote account pubkey to track (auto-discovered on test-validator).
        #[arg(long)]
        vote: Option<String>,
        /// Seconds between polls.
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
    /// Run the eBPF disk-latency profiler (block_rq_issue -> block_rq_complete).
    /// Linux only, needs root.
    Watch {
        /// Only trace this block device, as "major:minor" (e.g. 259:0 — find
        /// yours with `lsblk`). Default: all devices.
        #[arg(long)]
        dev: Option<String>,
        /// Seconds per summary window.
        #[arg(long, default_value_t = 5)]
        window: u64,
        /// Also print every raw event (debug firehose).
        #[arg(long)]
        raw: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    match Cli::parse().cmd {
        Cmd::Poll {
            rpc,
            vote,
            interval,
        } => poll(rpc, vote, interval).await,
        Cmd::Watch { dev, window, raw } => watch(dev, window, raw).await,
    }
}

/// "259:0" -> kernel dev_t encoding (major << 20 | minor), same as the
/// tracepoint's dev field.
fn parse_dev(s: &str) -> Result<u32> {
    let (major, minor) = s
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("--dev wants major:minor, e.g. 259:0"))?;

    let major: u32 = major.trim().parse()?;
    let minor: u32 = minor.trim().parse()?;
    Ok((major << 20) | minor)
}

/// The RPC poll loop. Ask, print, repeat. Ctrl-C to stop.
async fn poll(rpc_url: String, vote: Option<String>, interval: u64) -> Result<()> {
    let mut poller = rpc::RpcPoller::new(&rpc_url);
    if let Some(pk) = vote {
        poller = poller.with_vote_pubkey(pk);
    }

    println!("driftwatch — polling {rpc_url} every {interval}s (Ctrl-C to stop)\n");
    let mut ticker = tokio::time::interval(Duration::from_secs(interval));

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Never fails: an unreachable RPC arrives as a DOWN sample,
                // same stream as OK ones — outages are data, not stderr noise.
                let sample = poller.sample().await;
                println!("{}", output::status_line(&sample));
            }
            _ = signal::ctrl_c() => {
                println!("\nstopping.");
                return Ok(());
            }
        }
    }
}

/// The profiler: load the eBPF program, attach both block tracepoints, stream
/// DiskEvents off the ringbuf.
async fn watch(dev: Option<String>, window: u64, raw: bool) -> Result<()> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // The eBPF object file is embedded at compile time. The volume filter is a
    // global in that object, patched before load — the kernel never sees other
    // devices' events at all.
    let target_dev = match &dev {
        Some(s) => parse_dev(s)?,
        None => 0, // accept all
    };
    let mut loader = aya::EbpfLoader::new();
    loader.override_global("TARGET_DEV", &target_dev, true);
    let mut ebpf = loader.load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/driftwatch"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // Expected: the kernel program has no log statements.
        debug!("no eBPF logger: {e}");
    }

    // Attach both hooks: issue stamps the stopwatch, complete emits the event.
    for name in ["block_rq_issue", "block_rq_complete"] {
        let program: &mut TracePoint = ebpf
            .program_mut(name)
            .ok_or_else(|| anyhow::anyhow!("program {name} not found in object"))?
            .try_into()?;
        program.load()?;
        program.attach("block", name)?;
    }

    let events = aya::maps::RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?,
    )?;
    let drops = aya::maps::PerCpuArray::try_from(
        ebpf.take_map("DROPS")
            .ok_or_else(|| anyhow::anyhow!("DROPS map not found"))?,
    )?;
    tokio::spawn(disk::watch_drops(drops));

    match &dev {
        Some(d) => println!("driftwatch — profiling block device {d} (Ctrl-C to stop)\n"),
        None => println!("driftwatch — profiling ALL block devices (Ctrl-C to stop)\n"),
    }

    tokio::select! {
        res = disk::consume(events, window, raw) => res,
        _ = signal::ctrl_c() => {
            println!("\nstopping.");
            Ok(())
        }
    }
}
