mod correlate;
mod disk;
mod net;
mod output;
mod rpc;
mod sockets;

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
        /// Vote account pubkey (auto-discovered on test-validator).
        #[arg(long)]
        vote: Option<String>,
        /// Seconds between polls.
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
    /// Disk profiler: windowed latency summaries. Linux only, needs root.
    Watch {
        /// Block device as "major:minor" (find it with lsblk). Default: all.
        #[arg(long)]
        dev: Option<String>,
        /// Seconds per window.
        #[arg(long, default_value_t = 3)]
        window: u64,
        /// Also print every raw event.
        #[arg(long)]
        raw: bool,
    },
    /// Profiler + poller together: one combined line (or JSON) per window.
    Run {
        /// Block device as "major:minor" (the ledger volume).
        #[arg(long)]
        dev: Option<String>,
        /// Seconds per window.
        #[arg(long, default_value_t = 3)]
        window: u64,
        /// Validator JSON-RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        rpc: String,
        /// Vote account pubkey (auto-discovered on test-validator).
        #[arg(long)]
        vote: Option<String>,
        /// Seconds between RPC polls.
        #[arg(long, default_value_t = 2)]
        interval: u64,
        /// Emit JSON objects instead of human lines.
        #[arg(long)]
        json: bool,
        /// disk_latency alert: p99 above this, in microseconds. Static, no baseline.
        #[arg(long, default_value_t = 1_500_000)]
        disk_latency_us: u64,
        /// disk_latency alert: consecutive windows over threshold required. 1 = no suppression.
        #[arg(long, default_value_t = 1)]
        disk_streak: u32,
        /// vote_lag alert: absolute slots behind tip.
        #[arg(long, default_value_t = 4)]
        vote_lag: i64,
        /// freeze_in_last_n: how many trailing windows to count freezes over.
        #[arg(long, default_value_t = 3)]
        freeze_lookback: u32,
        /// A slot jump bigger than this is a discontinuity, not a freeze.
        #[arg(long, default_value_t = 1000)]
        freeze_jump_bound: i64,
        /// ring_drop alert: rx_missed_errors delta above this.
        #[arg(long, default_value_t = 0)]
        ring_drop_threshold: u64,
        /// napi_squeeze alert: time_squeeze delta above this. Tune from your own baseline.
        #[arg(long, default_value_t = 100)]
        napi_squeeze_threshold: u64,
        /// udp_rcvbuf alert: RcvbufErrors delta above this.
        #[arg(long, default_value_t = 0)]
        udp_rcvbuf_threshold: u64,
        /// socket_drop alert: any single agave socket's drops delta above this.
        #[arg(long, default_value_t = 0)]
        socket_drop_threshold: u64,
        /// Network interface to read counters from. Default: kernel's default-route interface.
        #[arg(long)]
        iface: Option<String>,
        /// agave-validator PID. Default: auto-detect by matching argv[0].
        #[arg(long)]
        pid: Option<u32>,
        /// Ledger path, needed to reach the admin socket for socket role
        /// discovery (contact-info). Without it, layer 4 still tracks
        /// drops/queues but every socket's role shows as "unknown".
        #[arg(long)]
        ledger: Option<String>,
        /// Seconds between fd map / port role rebuilds. Slow on purpose.
        #[arg(long, default_value_t = 30)]
        fd_refresh: u64,
        /// Seconds between layer-4 socket samples. Decoupled from --window since
        /// the fd walk, proc scan, and admin socket role lookup are all heavier
        /// than layers 1-3.
        #[arg(long, default_value_t = 5)]
        socket_interval: u64,
        /// Emit exactly one window then exit, instead of running forever.
        #[arg(long)]
        dry_run: bool,
        /// Check eBPF load, network paths, and RPC reachability, print pass/fail, exit.
        #[arg(long)]
        check: bool,
        /// Attach driftwatch's own CPU time (user+sys) per window to the output.
        #[arg(long)]
        self_metrics: bool,
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
        Cmd::Run {
            dev,
            window,
            rpc,
            vote,
            interval,
            json,
            disk_latency_us,
            disk_streak,
            vote_lag,
            freeze_lookback,
            freeze_jump_bound,
            ring_drop_threshold,
            napi_squeeze_threshold,
            udp_rcvbuf_threshold,
            socket_drop_threshold,
            iface,
            pid,
            ledger,
            fd_refresh,
            socket_interval,
            dry_run,
            check,
            self_metrics,
        } => {
            let thresholds = correlate::Thresholds {
                disk_latency_ns: disk_latency_us * 1_000,
                disk_streak,
                vote_lag,
                freeze_lookback,
                freeze_jump_bound,
                ring_drop_threshold,
                napi_squeeze_threshold,
                udp_rcvbuf_threshold,
                socket_drop_threshold,
            };
            let iface = match iface {
                Some(i) => i,
                None => net::detect_iface()
                    .map_err(|e| anyhow::anyhow!("--iface not given and auto-detect failed: {e}"))?,
            };

            if check {
                return run_check(&dev, &rpc, vote, &iface, pid, ledger).await;
            }

            eprintln!("driftwatch: using interface {iface}");
            let mut socket_tracker = sockets::SocketTracker::new(pid, fd_refresh, ledger);
            let startup_sockets = socket_tracker.sample().await;
            log_active_layers(&iface, dry_run, self_metrics, &startup_sockets);
            let net = net::NetTracker::new(iface);
            run(
                dev,
                window,
                rpc,
                vote,
                interval,
                json,
                thresholds,
                net,
                socket_tracker,
                socket_interval,
                dry_run,
                self_metrics,
            )
            .await
        }
    }
}

/// Summarizes which layers are active vs skipped, and why, before the main loop starts.
fn log_active_layers(iface: &str, dry_run: bool, self_metrics: bool, startup_sockets: &sockets::SocketSample) {
    eprintln!("driftwatch: layers active:");
    eprintln!("  disk (eBPF block tracepoints): active");
    eprintln!("  rpc (vote lag / slot freeze): active");
    eprintln!("  net layer 1-3 (ring/softnet/snmp, iface {iface}): active");
    match startup_sockets.pid {
        Some(pid) => eprintln!(
            "  net layer 4 (per-socket agave attribution, pid {pid}): active, {} sockets found",
            startup_sockets.sockets.len()
        ),
        None => eprintln!(
            "  net layer 4 (per-socket agave attribution): active but agave process not found yet, sockets will be empty"
        ),
    }
    if startup_sockets.pid.is_some() && startup_sockets.sockets.is_empty() {
        eprintln!("  !! layer 4 found the agave process but zero sockets attributed to it, check --pid / port roles");
    }
    eprintln!(
        "  self_metrics (own CPU time): {}",
        if self_metrics { "active" } else { "skipped, --self-metrics not passed" }
    );
    if dry_run {
        eprintln!("  dry_run: exiting after one window");
    }
}

/// Validates eBPF load, network paths, and RPC reachability without entering the main loop.
async fn run_check(
    dev: &Option<String>,
    rpc_url: &str,
    vote: Option<String>,
    iface: &str,
    pid: Option<u32>,
    ledger: Option<String>,
) -> Result<()> {
    let mut ok = true;

    let found_pid = sockets::resolve_pid(pid);
    match found_pid {
        Some(found) => println!("[ok]   agave process found: pid {found}"),
        None => println!("[warn] agave process not found (--pid to override), layer 4 will report empty until it starts"),
    }

    match (found_pid, &ledger) {
        (Some(found), Some(l)) => {
            let result = sockets::agave_bin_path(found)
                .and_then(|bin| sockets::agave_uid(found).map(|uid| (bin, uid)))
                .and_then(|(bin, uid)| sockets::refresh_port_roles(&bin, l, uid));
            match result {
                Ok(roles) => println!("[ok]   socket role discovery (contact-info): {} ports mapped", roles.len()),
                Err(e) => {
                    println!("[FAIL] socket role discovery (contact-info): {e}");
                    ok = false;
                }
            }
        }
        (None, _) => println!("[warn] agave process not found, skipping socket role discovery"),
        (_, None) => println!("[warn] --ledger not given, socket roles will show as \"unknown\""),
    }

    match load_profiler(dev) {
        Ok(_profiler) => println!("[ok]   eBPF load + attach (block_rq_issue, block_rq_complete)"),
        Err(e) => {
            println!("[FAIL] eBPF load + attach: {e}");
            ok = false;
        }
    }

    for path in net::check_paths(iface) {
        match std::fs::read_to_string(&path) {
            Ok(_) => println!("[ok]   net path readable: {path}"),
            Err(e) => {
                println!("[FAIL] net path readable: {path}: {e}");
                ok = false;
            }
        }
    }

    let mut poller = rpc::RpcPoller::new(rpc_url);
    if let Some(pk) = vote {
        poller = poller.with_vote_pubkey(pk);
    }
    match poller.sample().await {
        rpc::Sample::Up(_) => println!("[ok]   rpc reachable: {rpc_url}"),
        rpc::Sample::Down { reason } => {
            println!("[FAIL] rpc reachable: {rpc_url}: {reason}");
            ok = false;
        }
    }

    if ok {
        println!("\ncheck passed");
        Ok(())
    } else {
        anyhow::bail!("check failed, see [FAIL] lines above");
    }
}

/// Turn "259:0" into the single number the kernel uses for that device.
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
                // a failed poll becomes a DOWN sample, not an error
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

/// Live eBPF handle + the two maps the daemon reads.
/// Keep the Ebpf alive: dropping it detaches the programs.
type Profiler = (
    aya::Ebpf,
    aya::maps::RingBuf<aya::maps::MapData>,
    aya::maps::PerCpuArray<aya::maps::MapData, u64>,
);

/// Load the eBPF object, patch the device filter, attach both block tracepoints.
fn load_profiler(dev: &Option<String>) -> Result<Profiler> {
    // raise the locked-memory limit so the kernel lets us create eBPF maps
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // patch the volume filter into the embedded object before load
    let target_dev = match dev {
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
        // expected: kernel program has no log statements
        debug!("no eBPF logger: {e}");
    }

    // attach both hooks: issue starts the stopwatch, complete emits the event
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
    Ok((ebpf, events, drops))
}

/// The profiler alone logs windowed disk summaries
async fn watch(dev: Option<String>, window: u64, raw: bool) -> Result<()> {
    let (_ebpf, events, drops) = load_profiler(&dev)?;
    tokio::spawn(disk::watch_drops(drops));

    match &dev {
        Some(d) => println!("driftwatch — profiling block device {d} (Ctrl-C to stop)\n"),
        None => println!("driftwatch — profiling ALL block devices (Ctrl-C to stop)\n"),
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let printer = async {
        while let Some(stats) = rx.recv().await {
            println!("{}", disk::format_stats(&stats));
        }
    };

    tokio::select! {
        res = disk::consume(events, window, raw, tx) => res,
        _ = printer => Ok(()),
        _ = signal::ctrl_c() => {
            println!("\nstopping.");
            Ok(())
        }
    }
    // dropping _ebpf detaches the programs
}

/// The joined tool: profiler + poller, one timeline, one line per window.
async fn run(
    dev: Option<String>,
    window: u64,
    rpc_url: String,
    vote: Option<String>,
    interval: u64,
    json: bool,
    thresholds: correlate::Thresholds,
    net: net::NetTracker,
    socket_tracker: sockets::SocketTracker,
    socket_interval: u64,
    dry_run: bool,
    self_metrics: bool,
) -> Result<()> {
    let (_ebpf, events, drops) = load_profiler(&dev)?;
    tokio::spawn(disk::watch_drops(drops));

    let mut poller = rpc::RpcPoller::new(&rpc_url);
    if let Some(pk) = vote {
        poller = poller.with_vote_pubkey(pk);
    }

    if !json {
        println!(
            "driftwatch — disk {} + validator {rpc_url}, {window}s windows (Ctrl-C to stop)\n",
            dev.as_deref().unwrap_or("ALL")
        );
    }

    let (disk_tx, disk_rx) = tokio::sync::mpsc::channel(64);
    let (rpc_tx, rpc_rx) = tokio::sync::mpsc::channel(16);
    let (socket_tx, socket_rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(rpc::poll_stream(poller, interval, rpc_tx));
    tokio::spawn(sockets::socket_stream(socket_tracker, socket_interval, socket_tx));

    tokio::select! {
        res = disk::consume(events, window, false, disk_tx) => res,
        _ = correlate::combine(disk_rx, rpc_rx, socket_rx, json, thresholds, net, dry_run, self_metrics) => Ok(()),
        _ = signal::ctrl_c() => {
            if !json {
                println!("\nstopping.");
            }
            Ok(())
        }
    }
}
