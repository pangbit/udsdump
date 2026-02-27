#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    macros::{kprobe, map},
    maps::{Array, PerfEventArray},
    programs::ProbeContext,
    EbpfContext,
};
use udsdump_common::{Direction, FilterConfig, SockType, UdsEvent, MAX_PATH_LEN, MAX_PAYLOAD_SIZE};

#[map]
static EVENTS: PerfEventArray<UdsEvent> = PerfEventArray::new(0);

#[map]
static FILTER: Array<FilterConfig> = Array::with_max_entries(1, 0);

/// Read the socket path from unix_sock -> addr -> name -> sun_path.
///
/// Traverses kernel structures with hardcoded offsets for >= 5.4 kernels.
/// These offsets should be refined with BTF/CO-RE for full portability.
unsafe fn read_sock_path(sock_ptr: u64, path_buf: &mut [u8; MAX_PATH_LEN]) -> u32 {
    // struct socket { ..., struct sock *sk; } — sk at offset 32
    let sk_ptr: u64 = match bpf_probe_read_kernel((sock_ptr + 32) as *const u64) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if sk_ptr == 0 {
        return 0;
    }

    // struct unix_sock { struct sock sk; ...; struct unix_address *addr; }
    // addr offset ~880 on 5.15+ kernels
    let addr_ptr: u64 = match bpf_probe_read_kernel((sk_ptr + 880) as *const u64) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if addr_ptr == 0 {
        return 0;
    }

    // struct unix_address { atomic_t refcnt; int len; struct sockaddr_un name; }
    // sockaddr_un starts at offset 12, sun_path at +2 within it
    let sun_path_ptr = (addr_ptr + 12 + 2) as *const u8;

    match bpf_probe_read_kernel_str_bytes(sun_path_ptr, path_buf) {
        Ok(s) => s.len() as u32,
        Err(_) => 0,
    }
}

/// Check if the event should be filtered out.
/// Returns true if the event should be DROPPED.
unsafe fn should_filter(pid: u32, path: &[u8; MAX_PATH_LEN]) -> bool {
    if let Some(config) = FILTER.get(0) {
        // Filter by PID
        if config.target_pid != 0 && config.target_pid != pid {
            return true;
        }
        // Filter by path prefix
        let path_len = config.target_path_len as usize;
        if path_len > 0 && path_len <= MAX_PATH_LEN {
            let mut i = 0;
            while i < path_len {
                if i >= MAX_PATH_LEN {
                    break;
                }
                if path[i] != config.target_path[i] {
                    return true;
                }
                if config.target_path[i] == 0 {
                    break;
                }
                i += 1;
            }
        }
    }
    false
}

/// Core logic shared by all send/recv probes.
unsafe fn handle_msg(
    ctx: &ProbeContext,
    direction: Direction,
    sock_type: SockType,
) -> Result<u32, u32> {
    let pid = ctx.tgid();
    let tid = ctx.pid();

    let mut event = UdsEvent {
        timestamp_ns: bpf_ktime_get_ns(),
        pid,
        tid,
        comm: [0u8; 16],
        sock_inode: 0,
        peer_inode: 0,
        path: [0u8; MAX_PATH_LEN],
        direction: direction as u8,
        sock_type: sock_type as u8,
        _pad: [0u8; 2],
        data_len: 0,
        captured_len: 0,
        data: [0u8; MAX_PAYLOAD_SIZE],
    };

    // Get process name
    if let Ok(comm) = ctx.command() {
        event.comm = comm;
    }

    // Read socket path
    let sock_ptr: u64 = ctx.arg(0).ok_or(1u32)?;
    read_sock_path(sock_ptr, &mut event.path);

    // Apply kernel-side filter
    if should_filter(pid, &event.path) {
        return Ok(0);
    }

    // Read message size from the third argument (size_t len)
    let msg_len: u64 = ctx.arg(2).unwrap_or(0);
    event.data_len = msg_len as u32;

    // TODO: Read payload from msg_iter.iov->iov_base
    // This requires traversing the iov_iter structure which is complex in eBPF.
    // For now we capture metadata only; payload capture will be added in a follow-up.

    EVENTS.output(ctx, &event, 0);
    Ok(0)
}

// --- STREAM probes ---

#[kprobe]
pub fn udsdump_stream_sendmsg(ctx: ProbeContext) -> u32 {
    match unsafe { handle_msg(&ctx, Direction::Send, SockType::Stream) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kprobe]
pub fn udsdump_stream_recvmsg(ctx: ProbeContext) -> u32 {
    match unsafe { handle_msg(&ctx, Direction::Recv, SockType::Stream) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// --- DGRAM probes ---

#[kprobe]
pub fn udsdump_dgram_sendmsg(ctx: ProbeContext) -> u32 {
    match unsafe { handle_msg(&ctx, Direction::Send, SockType::Dgram) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kprobe]
pub fn udsdump_dgram_recvmsg(ctx: ProbeContext) -> u32 {
    match unsafe { handle_msg(&ctx, Direction::Recv, SockType::Dgram) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
