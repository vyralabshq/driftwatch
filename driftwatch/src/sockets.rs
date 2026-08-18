// Layer 4: per-socket drops attributed to an agave role (tvu, tpu, gossip,
// ...). The point of v2: layers 1-3 say the box dropped something, this
// says which socket, so shred ingest, transaction ingest, and gossip stop
// being indistinguishable.
//
// Runs on its own timer (--socket-interval), decoupled from the disk
// window: the fd walk, /proc/net/udp scan, and admin-socket role lookup
// are all heavier than layers 1-3 and don't need to run every window.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::Sender;

/// One tick's worth of layer-4 signal. Empty sockets + no pid means agave
/// wasn't found this refresh, not that nothing is happening.
pub struct SocketSample {
    pub pid: Option<u32>,
    pub sockets: Vec<SocketEntry>,
}

pub struct SocketEntry {
    pub port: u16,
    pub role: String,
    pub count: u32, // how many sockets share this port, agave uses SO_REUSEPORT for parallelism
    pub drops: u64, // summed across the group, delta since last sample, not cumulative
    pub rx_queue: u64, // summed across the group
    pub tx_queue: u64, // summed across the group
}

/// Accumulator for one port while grouping raw sockets that share it.
struct SocketGroup {
    role: String,
    count: u32,
    drops: u64,
    rx_queue: u64,
    tx_queue: u64,
}

/// Poll forever on its own interval, sending each SocketSample down the channel.
pub async fn socket_stream(mut tracker: SocketTracker, interval_secs: u64, tx: Sender<SocketSample>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    loop {
        ticker.tick().await;
        let sample = tracker.sample().await;
        if tx.send(sample).await.is_err() {
            return; // receiver gone, shutting down
        }
    }
}

pub struct SocketTracker {
    pid_override: Option<u32>,
    pid: Option<u32>,
    fd_inodes: HashSet<u64>,
    port_roles: HashMap<u16, String>,
    prev_drops: HashMap<u64, u64>, // socket inode mapped to its last cumulative drops seen
    fd_refresh_interval: Duration,
    last_fd_refresh: Option<Instant>,
    ledger: Option<String>, // needed to reach the admin socket for contact-info
    last_err: Option<String>,
}

impl SocketTracker {
    pub fn new(pid_override: Option<u32>, fd_refresh_secs: u64, ledger: Option<String>) -> Self {
        Self {
            pid_override,
            pid: None,
            fd_inodes: HashSet::new(),
            port_roles: HashMap::new(),
            prev_drops: HashMap::new(),
            fd_refresh_interval: Duration::from_secs(fd_refresh_secs.max(1)),
            last_fd_refresh: None,
            ledger,
            last_err: None,
        }
    }

    /// Rebuilds the pid, the fd to inode set, and the port to role map.
    /// Cheap parts always run; the admin socket role lookup only runs on
    /// the slow timer or when the pid changed, since a validator restart
    /// makes old roles suspect.
    async fn refresh(&mut self) {
        let found = resolve_pid(self.pid_override);
        let pid_changed = found != self.pid;
        if pid_changed {
            // restart: old cumulative counters no longer mean anything
            self.prev_drops.clear();
        }
        self.pid = found;

        self.fd_inodes = match self.pid {
            Some(pid) => walk_fd_inodes(pid),
            None => HashSet::new(),
        };

        if let (Some(pid), Some(ledger)) = (self.pid, &self.ledger) {
            let result = agave_bin_path(pid)
                .and_then(|bin| agave_uid(pid).map(|uid| (bin, uid)))
                .and_then(|(bin, uid)| refresh_port_roles(&bin, ledger, uid));
            match result {
                Ok(roles) => {
                    self.port_roles = roles;
                    self.last_err = None;
                }
                Err(e) => {
                    // keep the last known roles rather than blanking a working map
                    if self.last_err.as_deref() != Some(&e) {
                        eprintln!("WARN: socket role discovery failed: {e}");
                        self.last_err = Some(e);
                    }
                }
            }
        }
        self.last_fd_refresh = Some(Instant::now());
    }

    pub async fn sample(&mut self) -> SocketSample {
        let stale = self
            .last_fd_refresh
            .map(|t| t.elapsed() > self.fd_refresh_interval)
            .unwrap_or(true);
        if stale {
            self.refresh().await;
        }

        let Some(pid) = self.pid else {
            return SocketSample {
                pid: None,
                sockets: Vec::new(),
            };
        };

        let mut raw = Vec::new();
        if let Ok(v4) = parse_proc_net_udp("/proc/net/udp") {
            raw.extend(v4);
        }
        if let Ok(v6) = parse_proc_net_udp("/proc/net/udp6") {
            raw.extend(v6);
        }

        // agave binds many sockets to the same port with SO_REUSEPORT for
        // parallelism, shred ingest especially. Grouped by port so the output
        // shows one line per port with a count, not a dozen near-identical rows.
        let mut grouped: HashMap<u16, SocketGroup> = HashMap::new();
        for s in raw {
            // race: fd closed between the walk and this read, or not agave's
            if !self.fd_inodes.contains(&s.inode) {
                continue;
            }
            let prev = self.prev_drops.insert(s.inode, s.drops).unwrap_or(s.drops);
            let role = self
                .port_roles
                .get(&s.port)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let group = grouped.entry(s.port).or_insert(SocketGroup {
                role,
                count: 0,
                drops: 0,
                rx_queue: 0,
                tx_queue: 0,
            });
            group.count += 1;
            group.drops += s.drops.saturating_sub(prev);
            group.rx_queue += s.rx_queue;
            group.tx_queue += s.tx_queue;
        }

        let mut sockets: Vec<SocketEntry> = grouped
            .into_iter()
            .map(|(port, g)| SocketEntry {
                port,
                role: g.role,
                count: g.count,
                drops: g.drops,
                rx_queue: g.rx_queue,
                tx_queue: g.tx_queue,
            })
            .collect();
        sockets.sort_unstable_by_key(|s| s.port);

        SocketSample {
            pid: Some(pid),
            sockets,
        }
    }
}

/// --pid override wins; otherwise auto-detect. Exposed for `--check`.
pub fn resolve_pid(pid_override: Option<u32>) -> Option<u32> {
    pid_override.or_else(find_agave_pid)
}

/// Matches by argv[0] basename, not /proc/<pid>/comm: comm truncates at 15
/// bytes and "agave-validator" is 16, so comm matching silently misses it.
fn find_agave_pid() -> Option<u32> {
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue; // not a pid dir
        };
        let Ok(cmdline) = fs::read_to_string(format!("/proc/{pid}/cmdline")) else {
            continue; // race: process exited, or no permission
        };
        let Some(argv0) = cmdline.split('\0').next() else {
            continue;
        };
        let bin = argv0.rsplit('/').next().unwrap_or(argv0);
        if bin == "agave-validator" || bin == "solana-validator" {
            return Some(pid);
        }
    }
    None
}

fn walk_fd_inodes(pid: u32) -> HashSet<u64> {
    let mut out = HashSet::new();
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue; // race: fd closed between readdir and readlink
        };
        let Some(inner) = target
            .to_str()
            .and_then(|s| s.strip_prefix("socket:["))
            .and_then(|s| s.strip_suffix(']'))
        else {
            continue; // not a socket fd
        };
        if let Ok(inode) = inner.parse::<u64>() {
            out.insert(inode);
        }
    }
    out
}

struct RawUdpSocket {
    port: u16,
    inode: u64,
    rx_queue: u64,
    tx_queue: u64,
    drops: u64,
}

/// /proc/net/udp[6]: fixed column layout, stable across kernel versions.
/// local_address = idx 1, tx:rx queue (hex) = idx 4, inode (dec) = idx 9,
/// drops (dec) = idx 12. Malformed lines are skipped, not fatal.
fn parse_proc_net_udp(path: &str) -> Result<Vec<RawUdpSocket>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 13 {
            continue;
        }
        let Some((_, port_hex)) = f[1].rsplit_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        let Some((tx_hex, rx_hex)) = f[4].split_once(':') else {
            continue;
        };
        let tx_queue = u64::from_str_radix(tx_hex, 16).unwrap_or(0);
        let rx_queue = u64::from_str_radix(rx_hex, 16).unwrap_or(0);
        let Ok(inode) = f[9].parse::<u64>() else {
            continue;
        };
        let drops = f[12].parse::<u64>().unwrap_or(0);
        out.push(RawUdpSocket {
            port,
            inode,
            rx_queue,
            tx_queue,
            drops,
        });
    }
    Ok(out)
}

/// The actual binary the running validator was launched from, via
/// /proc/<pid>/exe. Not "agave-validator" resolved through PATH: driftwatch
/// usually runs under sudo/systemd with a minimal PATH that doesn't include
/// wherever the operator's solana-install put it, and this is exact anyway
/// regardless of PATH.
pub(crate) fn agave_bin_path(pid: u32) -> Result<String, String> {
    let path = format!("/proc/{pid}/exe");
    fs::read_link(&path)
        .map_err(|e| format!("{path}: {e}"))?
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{path}: not valid utf8"))
}

/// Real uid the validator runs as, from /proc/<pid>/status. The admin
/// socket enforces same-uid peer credentials, so even root gets EACCES
/// connecting from a different uid — the contact-info subprocess has to
/// run as this exact uid, not whatever driftwatch itself runs as.
pub(crate) fn agave_uid(pid: u32) -> Result<u32, String> {
    let path = format!("/proc/{pid}/status");
    let text = fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(real) = rest.split_whitespace().next() {
                return real
                    .parse::<u32>()
                    .map_err(|e| format!("{path}: bad Uid line: {e}"));
            }
        }
    }
    Err(format!("{path}: no Uid line found"))
}

/// `<bin> --ledger <path> contact-info` reads the local admin IPC socket,
/// not the public JSON-RPC port. That matters: getClusterNodes is gated
/// behind --full-rpc-api, which a production voting validator has every
/// reason to leave off, so the public RPC route was never reliable here.
/// The admin socket has no such gate, but does check the connecting
/// process's uid, hence `uid` here rather than inheriting driftwatch's own.
pub(crate) fn refresh_port_roles(bin: &str, ledger: &str, uid: u32) -> Result<HashMap<u16, String>, String> {
    let out = Command::new(bin)
        .args(["--ledger", ledger, "contact-info"])
        .uid(uid)
        .output()
        .map_err(|e| format!("{bin} contact-info: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(format!(
            "{bin} contact-info: {} stderr: {} stdout: {}",
            out.status,
            stderr.trim(),
            stdout.trim()
        ));
    }
    Ok(parse_contact_info(&String::from_utf8_lossy(&out.stdout)))
}

/// Output is "Label: value" lines, e.g. "TPU Votes: 1.2.3.4:8004". Any line
/// whose value doesn't end in ":<port>" (Identity, timestamps, ...) is
/// skipped automatically since the port parse just fails. Port 0 means the
/// socket is disabled (RPC/RPC Pubsub under --private-rpc); port 1 is
/// agave's sentinel for "no legacy socket, QUIC only" — neither is a real
/// bound port, so both are skipped.
fn parse_contact_info(text: &str) -> HashMap<u16, String> {
    let mut roles = HashMap::new();
    for line in text.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let Some((_, port_str)) = value.trim().rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };
        if port <= 1 {
            continue;
        }
        roles.insert(port, label_to_role(label.trim()));
    }
    roles
}

fn label_to_role(label: &str) -> String {
    match label {
        "Gossip" => "gossip",
        "TVU" => "tvu",
        "TVU QUIC" => "tvu_quic",
        "TPU" => "tpu",
        "TPU QUIC" => "tpu_quic",
        "TPU Forwards" => "tpu_forwards",
        "TPU Forwards QUIC" => "tpu_forwards_quic",
        "TPU Votes" => "tpu_vote",
        "TPU Votes QUIC" => "tpu_vote_quic",
        "Serve Repair" => "serve_repair",
        "Serve Repair QUIC" => "serve_repair_quic",
        "Repair" => "repair",
        "RPC" => "rpc",
        "RPC Pubsub" => "rpc_pubsub",
        other => return other.to_lowercase().replace(' ', "_"),
    }
    .to_string()
}
