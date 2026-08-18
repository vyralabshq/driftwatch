# driftwatch

An eBPF tool that watches a Solana validator's disk and connects it to the validator's
own vote data. One binary. One timeline. JSON output.

Runs in production on a live Solana testnet validator at [Vyra Labs](https://vyralabs.fun).
Anyone can run this on their own validator. See [SETUP.md](SETUP.md) to get started.

```
+00:27 | disk p99 2,689ms | 512 reqs | 3.2 MB/s || slot 423,692,612 | lag 9 | credits 2,661,000 | OK | !! disk_latency,vote_lag
```

## What it watches

- Disk latency, from the kernel, using eBPF
- Vote lag, credits, and health, from the validator's RPC
- Network drops: NIC ring, NAPI, UDP buffers
- Which agave socket is dropping packets (gossip, tvu, tpu, and so on)

All four on one clock. One line, or one JSON object, per window.

## Alerts

Each alert checks its own thing. No alert waits on another one to also fire.

| alert          | fires when                                 |
| -------------- | ------------------------------------------ |
| `disk_latency` | disk p99 too high for too long             |
| `vote_lag`     | validator falling behind the network       |
| `slot_freeze`  | slot stops moving                          |
| `ring_drop`    | NIC dropping packets                       |
| `napi_squeeze` | CPU can't keep up with packets             |
| `udp_rcvbuf`   | UDP receive buffer overflowing             |
| `socket_drop`  | one specific agave socket dropping packets |

Flags to tune these: [SETUP.md](SETUP.md).

## Why alerts are independent

An earlier version of this tool only alerted when disk latency AND vote lag rose
together. That was a bug, not a feature. Disk latency does not reliably predict vote
lag, so a validator could take real damage on one and look fine on the other. Now every
alert is its own check, on its own signal.

## Proof

Ran 82 hours straight in production. 110 alerts, zero false positives. Every alert had
a real vote-lag rise behind it, and disk always moved first. Caught real disk trouble
(RocksDB compaction) while it was still just latency, before it cost any votes.

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
