# Setup

How to build and run driftwatch on your own validator. For what the tool is, see
[README.md](README.md).

## Requirements

- Linux
- A recent stable Rust toolchain
- `bpf-linker`: `cargo install bpf-linker`
- Root, to attach eBPF programs

## Build

```shell
cargo build --release -p driftwatch
```

## Usage

```shell
driftwatch poll                        # validator status only, no eBPF
driftwatch watch --dev 253:16          # disk stats only
driftwatch run   --dev 253:16          # both, with alerts
driftwatch run   --dev 253:16 --json   # both, as JSON
```

Find your ledger disk:

```shell
df -h /path/to/ledger        # which device, e.g. /dev/vdb1
lsblk -o NAME,MAJ:MIN        # major:minor of the parent disk, not the partition
```

Check everything works before running for real:

```shell
driftwatch run --dev 253:16 --ledger /path/to/ledger --check
```

## Flags

| flag                  | what it does                                              | default                 |
| --------------------- | --------------------------------------------------------- | ----------------------- |
| `--dev <major:minor>` | disk to watch                                             | all disks               |
| `--window <secs>`     | window size                                               | 3                       |
| `--rpc <url>`         | validator RPC endpoint                                    | `http://127.0.0.1:8899` |
| `--vote <pubkey>`     | vote account                                              | auto                    |
| `--interval <secs>`   | seconds between RPC polls                                 | 2                       |
| `--json`              | JSON output                                               | off                     |
| `--iface <name>`      | network interface                                         | auto                    |
| `--pid <pid>`         | agave process PID                                         | auto                    |
| `--ledger <path>`     | needed for socket role names, else they show as `unknown` | none                    |
| `--check`             | test the setup, don't run                                 | off                     |
| `--dry-run`           | one window then exit                                      | off                     |
| `--self-metrics`      | show driftwatch's own CPU cost                            | off                     |

Each alert also has its own threshold flag, e.g. `--vote-lag`, `--disk-latency-us`,
`--ring-drop-threshold`. Defaults are sane; tune them once you know your box's baseline.

`--fd-refresh <secs>` (default 30) and `--socket-interval <secs>` (default 5) tune how
often layer 4 rebuilds its socket map and samples, separately from `--window`, since
that work is heavier than the rest.

## Running as a service

```ini
[Unit]
Description=driftwatch
After=network-online.target

[Service]
Type=simple
User=root
ExecStart=/path/to/driftwatch run \
  --dev 259:0 \
  --rpc http://127.0.0.1:8899 \
  --ledger /path/to/ledger \
  --json
Restart=on-failure
RestartSec=5
CPUQuota=50%
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```

`CPUQuota`/`MemoryMax` keep it from ever competing with the validator for resources.

## JSON output

One object per window:

```json
{
  "ts": 1787067180,
  "schema_version": 2,
  "consensus": "towerbft",
  "self_cpu_ms": null,
  "disk": {
    "window_secs": 3,
    "reqs": 511,
    "writes": 250,
    "reads": 261,
    "others": 0,
    "bytes": 29028352,
    "errors": 0,
    "p50_us": 320,
    "p99_us": 17574,
    "max_us": 17896
  },
  "validator": {
    "state": "ok",
    "epoch": 1009,
    "slot": 430579083,
    "last_vote": 430579081,
    "vote_lag": 2,
    "credits": 3378181,
    "delinquent": false,
    "healthy": true
  },
  "baseline": { "disk_p99_median_us": 111 },
  "freeze": false,
  "freeze_duration_ms": 0,
  "freeze_in_last_n": 0,
  "alerts": [],
  "net": {
    "iface": "ens3f0np0",
    "is_xdp": false,
    "ring": {
      "rx_missed_errors": 0,
      "rx_dropped": 0,
      "rx_errors": 0,
      "rx_fifo_errors": 0
    },
    "softnet": {
      "processed": 42187,
      "dropped": 0,
      "time_squeeze": 0,
      "time_squeeze_max_cpu": 0,
      "max_cpu_id": 0
    },
    "snmp_udp": {
      "in_datagrams": 42143,
      "in_errors": 0,
      "rcvbuf_errors": 0,
      "sndbuf_errors": 0,
      "no_ports": 0
    },
    "sockets": [
      {
        "port": 8000,
        "role": "gossip",
        "drops": 0,
        "rx_queue": 0,
        "tx_queue": 0
      },
      { "port": 8001, "role": "tvu", "drops": 0, "rx_queue": 0, "tx_queue": 0 }
    ],
    "agave_pid": 2819333,
    "ethtool": {},
    "counters_reset": false,
    "parse_errors": 0
  }
}
```

`baseline.disk_p99_median_us` is informational only, it never decides an alert.
`alerts` lists whichever of the alert names fired that window, empty if none did.
