# driftwatch

An eBPF tool that watches a Solana validator's disk from inside the kernel and warns
when disk trouble starts costing votes. It names the cause instead of just reporting
the damage.

Built as a Turbin3 SVM cohort capstone under s0nar, now run in production on a live
Solana testnet validator at [Vyra Labs](https://vyralabs.fun).

```
+00:24 | disk p99 45µs | 10 reqs | 0.0 MB/s || slot 423,692,609 | lag 1 | credits 2,661,000 | OK
!! DRIFT: disk p99 2,689ms = 41,122x baseline 65µs for 4 windows, vote lag 9 vs norm 1. disk is the lead signal
```

(Both lines from a live Solana testnet validator. The baseline is real: ~50µs of steady
disk service time, then a multi-second stall that drags vote lag from 1 to 9.)

## The problem

When a validator degrades, the evidence lives in two different worlds. Box metrics
(disk latency, IOPS) sit in one set of tools. Chain outcomes (vote credits, delinquency)
sit in another. Different clocks, different granularity, different tabs. The operator is
the one stitching them together by hand, usually during an incident.

Disks are the classic silent killer here. Ledger write volume wears SSDs out in months,
and a dying disk announces itself as creeping request latency for weeks before SMART or
throughput numbers notice. Every existing alert fires at the outcome, after credits are
already bleeding. driftwatch watches the earliest signal and connects it to the effect,
on one timeline, continuously.

## How it works

Two signal layers joined on one clock:

```
kernel   block_rq_issue ──► stopwatch (LRU map) ──► block_rq_complete
         latency = pure device service time, per request
         DiskEvent (32 bytes) over a ringbuf to userspace

rpc      getVoteAccounts + getEpochInfo + getHealth
         vote lag = network slot minus last vote (the fast signal)
         credits, delinquency, balance (the slow outcome)

daemon   3 second windows: disk p50/p99/max/IOPS beside the latest validator sample
         one combined line per window, or one JSON object per window
```

The causal chain the tool is built around:

```
disk p99 rises  ──►  vote lag grows  ──►  credits slip
(eBPF, fast)         (RPC, fast)          (RPC, slow, the outcome)
```

Disk events move in microseconds and credits move per epoch, which makes them impossible
to correlate directly. Vote lag is the middle term: it moves fast like disk does, so the
correlation happens between two fast signals, and credits confirm the damage afterward.

### The drift rule

One deliberately simple rule, two conditions that must both hold:

- disk p99 above 4x its own rolling baseline (median of recent normal windows),
  above a 1ms floor, for 3 consecutive windows
- vote lag above its own norm by 3 or more slots (a dead RPC counts as worst case)

Then exactly one alert fires, naming disk as the lead signal, and re-arms only after
the disk returns to normal. A lone fsync spike with lag flat produces silence. Cause
without a victim is not drift.

## Usage

One binary, three modes:

```shell
driftwatch poll                        # validator layer only: live status line, no eBPF
driftwatch watch --dev 253:16          # disk layer only: windowed p50/p99/max summaries
driftwatch run   --dev 253:16          # the joined timeline plus the drift rule
driftwatch run   --dev 253:16 --json   # machine readable, one JSON object per window
```

Useful flags: `--window <secs>` (summary window, default 3), `--raw` (per event
firehose on watch), `--rpc <url>`, `--vote <pubkey>`, `--interval <secs>`.

Finding your ledger disk number:

```shell
df -h /path/to/ledger        # which device backs the path, e.g. /dev/vdb1
lsblk -o NAME,MAJ:MIN        # that device's major:minor, use the parent disk
```

Take the whole disk, not the partition. By the time a request reaches the block layer
the kernel has remapped it to the parent device. On the production box the ledger sits
on `nvme0n1` (major:minor `259:0`), so the flag is `--dev 259:0`. Confirm empirically by
enabling `block_rq_complete` tracing briefly and reading which `major,minor` the
validator's writes actually report; the partition you mounted is not always the device
the events carry.

## Workspace layout

| crate               | role                                                                   |
| ------------------- | ---------------------------------------------------------------------- |
| `driftwatch`        | userspace daemon: rpc poller, ringbuf consumer, correlator, drift rule |
| `driftwatch-ebpf`   | `no_std` kernel program: two tracepoints, three maps                   |
| `driftwatch-common` | shared `#[repr(C)]` types crossing the kernel boundary                 |
| `xtask`             | build and deploy loop into a Lima VM over SSH and rsync                |

Kernel side design: stamp, subtract, emit. All judgment lives in the daemon.

Maps: `INFLIGHT` (LRU hash, in flight request timestamps keyed by device and sector),
`EVENTS` (ringbuf to userspace), `DROPS` (per CPU overflow counter, so the daemon knows
when its own numbers are lying). The target device is a global patched into the object
before load, so the kernel filters foreign devices at the first instruction.

## Dev environment

Development happens on macOS with everything running inside a Lima VM (`client-run`):
the test validator, the eBPF program, and the daemon on one box, which mirrors how the
tool deploys in production (daemon on the validator machine).

```shell
cargo xtask setup                      # one time: toolchain + bpf-linker in the VM
cargo xtask build                      # sync + build inside the VM
cargo xtask run -- run --dev 253:16    # sync + build + run, args pass through
cargo xtask ssh                        # shell into the VM
```

The ledger lives on a dedicated virtual disk (Lima `additionalDisks`), and the
validator runs with `--ledger` pointed at it. That is not just test hygiene, it is
the production layout: serious operators give the ledger its own NVMe.

Generating load for testing:

```shell
fio --name=blast --rw=randwrite --bs=4k --size=200M --iodepth=32 --numjobs=2 \
    --ioengine=libaio --direct=1 --runtime=30 --time_based --directory=/mnt/lima-ledger
```

## Problems we hit and what they taught us

**Events kept flowing with the validator off.** The system disk is shared: journald,
build artifact writeback, everything. The obvious fix, filtering by PID, is impossible
at the block layer, because buffered writes are flushed later by kernel worker threads
and process identity is already gone when the tracepoint fires. Device identity is rock
solid. Hence the dedicated ledger disk plus the in kernel device filter: on the ledger
disk only the validator writes, so filtering by device becomes filtering by process.

**65,000 raw events per second is unreadable.** Windowing turns the firehose into one
line per 3 seconds with p50, p99 and max. Percentiles, not averages: a single 50ms
replay read disappears into an average of thousands of fast writes. The validator's
pain lives in the tail.

**A full I/O storm can produce zero alerts, and that is correct.** Disk p99 hitting tens
of milliseconds while the validator keeps voting at lag 1 is not drift. A threshold
alerter would page for it; the two condition rule stays silent because there is no
victim. Cause without a victim is not drift. Silence is a feature, and the production
run bore this out: 0.11% of windows alerted, and every one had a real vote-lag victim.

**An unreachable RPC is data, not noise.** A failed poll becomes a DOWN sample on the
same timeline as healthy ones, because a dead validator process is the strongest
validator-layer signal there is. Outages land next to disk events where the correlator
can see them.

**Verify before eBPF.** Tracepoints over kprobes (stable kernel ABI instead of functions
that inline away), and the field offsets read from
`/sys/kernel/tracing/events/block/*/format` on the target kernel before any code was
written. issue plus complete is the one hook pair that isolates device service time from
queue time.

## Scope cut on purpose

- SFDP threshold engine: the delegation program floor is cluster relative and needs
  peer credit data, which makes it meaningless on a single node test validator. The
  drift rule is threshold free and works for any operator; program specific policy can
  sit on top of the JSON stream.
- Statistical lead detection (cross correlation, inflection ordering): a research
  swamp with a false positive problem. One dumb explainable rule instead.
- Queue time (`block_rq_insert` to `block_rq_issue`): a deliberate v1 exclusion. It
  would distinguish a slow disk from an overfull queue, and is the first candidate for
  a second span.

## Proof

Run in production on a live Solana testnet validator (bare metal, EPYC, dedicated NVMe
for the ledger), managed by systemd alongside the node, resource capped at 50% CPU and
512MB so it can never contend with the validator.

- **82 hours continuous, ~100,000 windows, 110 drift alerts.** That is 0.11% of windows,
  roughly one alert every 45 minutes, in bursts rather than evenly spaced.
- **Zero false positives.** Every one of the 110 alerts had vote lag above its norm, and
  every one named disk as the lead signal. Not a single case where lag moved first.
- **Baseline p99 held at 40 to 120µs the entire run.** Alert windows ran a median of
  1,058ms and a max of 3,176ms. Half the alerts crossed a full second, two thirds crossed
  500ms. Severity ranged from 71x to 60,522x over baseline.
- **No harm at this stake.** Zero delinquency, zero unhealthy windows, no lost credits
  across every alert. The stalls degraded latency without costing votes, which is exactly
  what a leading indicator is supposed to catch: the problem while it is still latency,
  before it becomes an outcome.
- **Cause narrowed by elimination.** Drive health clean (SMART PASSED, 4% wear, zero media
  errors). Disk not full (SMART's reported utilization was untrimmed blocks, not live data,
  confirmed against `df` and a weekly `fstrim`). Snapshots ruled out (`total_snapshot_ms=0`
  in the validator's own metrics). Leading candidate: RocksDB compaction, confirmed running,
  with the blockstore index column family at 2.5GB of SST files and 137MB median writes per
  alert window.

Earlier capstone validation, on the Lima rig: 519,764 fio writes issued and 519,764 events
captured, zero lost at roughly 65k events per second, drop counter at zero. Chaos tested
with the validator killed mid poll, DOWN samples emitted, clean recovery.

## License

With the exception of eBPF code, driftwatch is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
