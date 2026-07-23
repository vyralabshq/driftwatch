// driftwatch kernel side: stamp / subtract / emit. All judging happens in the daemon.
//
// block_rq_issue    -> stash issue timestamp keyed by (dev, sector)
// block_rq_complete -> lookup, latency = now - issue, push DiskEvent to ringbuf
//
// Field offsets come from /sys/kernel/tracing/events/block/*/format

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use driftwatch_common::{DiskEvent, DiskKey, RW_OTHER, RW_READ, RW_WRITE};

const DEV_OFF: usize = 8;
const SECTOR_OFF: usize = 16;
const NR_SECTOR_OFF: usize = 24;
const ERROR_OFF: usize = 28; // complete only
const RWBS_OFF: usize = 32;

/// issue timestamps of in-flight requests, keyed by (dev, sector)
#[map]
static INFLIGHT: LruHashMap<DiskKey, u64> = LruHashMap::with_max_entries(10240, 0);

/// completed DiskEvents, kernel -> daemon
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// count of events dropped when the ringbuf was full
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// device to trace, set by the daemon before load. 0 = all
#[unsafe(no_mangle)]
static TARGET_DEV: u32 = 0;

#[inline(always)]
fn target_dev() -> u32 {
    // read at runtime, not compile time (the daemon overwrites this value)
    unsafe { core::ptr::read_volatile(&TARGET_DEV) }
}

#[tracepoint]
pub fn block_rq_issue(ctx: TracePointContext) -> u32 {
    let _ = try_issue(&ctx);
    0
}

fn try_issue(ctx: &TracePointContext) -> Result<(), i64> {
    let dev: u32 = unsafe { ctx.read_at(DEV_OFF)? };
    let target = target_dev();
    if target != 0 && dev != target {
        return Ok(()); // not our device
    }
    let sector: u64 = unsafe { ctx.read_at(SECTOR_OFF)? };
    let key = DiskKey {
        sector,
        dev: dev as u64,
    };
    let now = unsafe { bpf_ktime_get_ns() };
    INFLIGHT.insert(&key, &now, 0)?;
    Ok(())
}

#[tracepoint]
pub fn block_rq_complete(ctx: TracePointContext) -> u32 {
    let _ = try_complete(&ctx);
    0
}

fn try_complete(ctx: &TracePointContext) -> Result<(), i64> {
    let dev: u32 = unsafe { ctx.read_at(DEV_OFF)? };
    let target = target_dev();
    if target != 0 && dev != target {
        return Ok(());
    }
    let sector: u64 = unsafe { ctx.read_at(SECTOR_OFF)? };
    let key = DiskKey {
        sector,
        dev: dev as u64,
    };

    // no stored issue time: skip
    let Some(issue_ns) = (unsafe { INFLIGHT.get(&key) }) else {
        return Ok(());
    };
    let issue_ns = *issue_ns;
    let _ = INFLIGHT.remove(&key);

    let now = unsafe { bpf_ktime_get_ns() };
    let nr_sector: u32 = unsafe { ctx.read_at(NR_SECTOR_OFF)? };
    let error: i32 = unsafe { ctx.read_at(ERROR_OFF)? };

    // rwbs = flag string like "WS"; find R or W
    let rwbs: [u8; 8] = unsafe { ctx.read_at(RWBS_OFF)? };
    let mut rw = RW_OTHER;
    for b in rwbs {
        match b {
            b'R' => {
                rw = RW_READ;
                break;
            }
            b'W' => {
                rw = RW_WRITE;
                break;
            }
            0 => break,
            _ => {}
        }
    }

    let event = DiskEvent {
        sector,
        latency_ns: now.saturating_sub(issue_ns),
        dev,
        bytes: nr_sector * 512,
        error,
        rw,
        _pad: [0; 3],
    };

    match EVENTS.reserve::<DiskEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {
            // ringbuf full: count the drop
            if let Some(drops) = DROPS.get_ptr_mut(0) {
                unsafe { *drops += 1 };
            }
        }
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
