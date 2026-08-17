// Layer 4: per-socket drops attributed to an agave role (tvu, tpu, gossip,
// ...). The point of v2: layers 1-3 say the box dropped something, this
// says which socket, so shred ingest, transaction ingest, and gossip stop
// being indistinguishable.
//
// Runs on its own timer (--socket-interval), decoupled from the disk
// window: the fd walk, /proc/net/udp scan, and RPC role lookup are all
// heavier than layers 1-3 and don't need to run every window.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::mpsc::Sender;

use crate::rpc::RpcPoller;

/// One tick's worth of layer-4 signal. Empty sockets + no pid means agave
/// wasn't found this refresh, not that nothing is happening.
pub struct SocketSample {
    pub pid: Option<u32>,
    pub sockets: Vec<SocketEntry>,
}

pub struct SocketEntry {
    pub port: u16,
    pub role: String,
    pub drops: u64, // delta since last sample, not cumulative
    pub rx_queue: u64,
    pub tx_queue: u64,
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
    prev_drops: HashMap<u64, u64>, // inode -> last cumulative drops seen
    fd_refresh_interval: Duration,
    last_fd_refresh: Option<Instant>,
    rpc: RpcPoller, // used only for getIdentity / getClusterNodes
    last_err: Option<String>,
}

impl SocketTracker {
    pub fn new(rpc_url: String, pid_override: Option<u32>, fd_refresh_secs: u64) -> Self {
        Self {
            pid_override,
            pid: None,
            fd_inodes: HashSet::new(),
            port_roles: HashMap::new(),
            prev_drops: HashMap::new(),
            fd_refresh_interval: Duration::from_secs(fd_refresh_secs.max(1)),
            last_fd_refresh: None,
            rpc: RpcPoller::new(rpc_url),
            last_err: None,
        }
    }

    /// Rebuilds pid, fd->inode set, and port->role map. Cheap parts always
    /// run; expensive parts (RPC role lookup) only on the slow timer or
    /// when the pid changed (a validator restart makes old roles suspect).
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

        match refresh_port_roles(&self.rpc).await {
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

        let mut sockets = Vec::new();
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
            sockets.push(SocketEntry {
                port: s.port,
                role,
                drops: s.drops.saturating_sub(prev),
                rx_queue: s.rx_queue,
                tx_queue: s.tx_queue,
            });
        }

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

/// getIdentity for our own pubkey, then getClusterNodes to find our own
/// ContactInfo entry, then every string field shaped like "ip:port" becomes
/// a port->role entry. Reading the schema generically instead of a fixed
/// field list means new fields (tpu_quic, tvu_quic, ...) get picked up
/// automatically as agave versions add them, no hardcoded port list.
async fn refresh_port_roles(rpc: &RpcPoller) -> Result<HashMap<u16, String>, String> {
    let identity = rpc
        .call("getIdentity", json!([]))
        .await
        .map_err(|e| format!("getIdentity: {e:#}"))?;
    let pubkey = identity
        .get("identity")
        .and_then(|v| v.as_str())
        .ok_or("getIdentity: no identity field")?
        .to_string();

    let nodes = rpc
        .call("getClusterNodes", json!([]))
        .await
        .map_err(|e| format!("getClusterNodes: {e:#}"))?;
    let nodes = nodes.as_array().ok_or("getClusterNodes: not an array")?;
    let me = nodes
        .iter()
        .find(|n| n.get("pubkey").and_then(|v| v.as_str()) == Some(pubkey.as_str()))
        .ok_or("getClusterNodes: own pubkey not present yet (still gossiping?)")?;

    let mut roles = HashMap::new();
    if let Some(obj) = me.as_object() {
        for (key, value) in obj {
            let Some(addr) = value.as_str() else { continue };
            let Some((_, port_str)) = addr.rsplit_once(':') else {
                continue;
            };
            let Ok(port) = port_str.parse::<u16>() else {
                continue;
            };
            roles.insert(port, camel_to_snake(key));
        }
    }
    Ok(roles)
}

fn camel_to_snake(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}
