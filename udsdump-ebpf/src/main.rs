#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    macros::{kprobe, map},
    maps::{Array, PerCpuArray, PerfEventArray},
    programs::ProbeContext,
    EbpfContext,
};
use udsdump_common::{Direction, FilterConfig, SockType, UdsEvent, MAX_PATH_LEN, MAX_PAYLOAD_SIZE};

#[map]
static EVENTS: PerfEventArray<UdsEvent> = PerfEventArray::new(0);

#[map]
static FILTER: Array<FilterConfig> = Array::with_max_entries(1, 0);

/// Per-CPU scratch buffer for building events without blowing the eBPF stack.
/// UdsEvent is too large (~420 bytes) to allocate on the 512-byte eBPF stack.
#[map]
static EVENT_BUF: PerCpuArray<UdsEvent> = PerCpuArray::with_max_entries(1, 0);

// Kernel struct offsets for kernel 6.8 (verified with pahole):
// struct socket:    sk at offset 24
// struct unix_sock: addr at offset 760, peer at offset 848
// struct unix_address: name (sockaddr_un) at offset 8, sun_path at +2

const OFF_SOCKET_SK: u64 = 24;
const OFF_UNIX_SOCK_ADDR: u64 = 760;
const OFF_UNIX_SOCK_PEER: u64 = 848;
const OFF_UNIX_ADDR_SUN_PATH: u64 = 8 + 2; // sockaddr_un.sun_path

/// Read sun_path from a unix_sock's addr.
/// Returns path length, or 0 if no addr / no path.
unsafe fn read_path_from_sk(sk_ptr: u64, path_buf: &mut [u8; MAX_PATH_LEN]) -> u32 {
    let addr_ptr: u64 = match unsafe { bpf_probe_read_kernel((sk_ptr + OFF_UNIX_SOCK_ADDR) as *const u64) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if addr_ptr == 0 {
        return 0;
    }
    let sun_path_ptr = (addr_ptr + OFF_UNIX_ADDR_SUN_PATH) as *const u8;
    match unsafe { bpf_probe_read_kernel_str_bytes(sun_path_ptr, path_buf) } {
        Ok(s) => s.len() as u32,
        Err(_) => 0,
    }
}

/// Read the socket path from struct socket.
/// First tries the socket's own addr, then falls back to peer's addr.
unsafe fn read_sock_path(sock_ptr: u64, path_buf: &mut [u8; MAX_PATH_LEN]) -> u32 {
    let sk_ptr: u64 = match unsafe { bpf_probe_read_kernel((sock_ptr + OFF_SOCKET_SK) as *const u64) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if sk_ptr == 0 {
        return 0;
    }

    // Try own addr first
    let len = unsafe { read_path_from_sk(sk_ptr, path_buf) };
    if len > 0 {
        return len;
    }

    // Fall back to peer's addr
    let peer_ptr: u64 = match unsafe { bpf_probe_read_kernel((sk_ptr + OFF_UNIX_SOCK_PEER) as *const u64) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if peer_ptr == 0 {
        return 0;
    }
    unsafe { read_path_from_sk(peer_ptr, path_buf) }
}

/// Check if the event should be filtered out.
/// Returns true if the event should be DROPPED.
fn should_filter(pid: u32, path: &[u8; MAX_PATH_LEN]) -> bool {
    if let Some(config) = FILTER.get(0) {
        if config.target_pid != 0 && config.target_pid != pid {
            return true;
        }
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
/// Uses PerCpuArray scratch buffer to avoid stack overflow.
fn handle_msg(
    ctx: &ProbeContext,
    direction: Direction,
    sock_type: SockType,
) -> Result<u32, u32> {
    let pid = ctx.tgid();
    let tid = ctx.pid();

    // Get a mutable reference to the per-CPU event buffer
    let event = EVENT_BUF.get_ptr_mut(0).ok_or(1u32)?;
    let event = unsafe { &mut *event };

    // Zero out and populate the event
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.pid = pid;
    event.tid = tid;
    event.comm = [0u8; 16];
    event.sock_inode = 0;
    event.peer_inode = 0;
    event.path = [0u8; MAX_PATH_LEN];
    event.direction = direction as u8;
    event.sock_type = sock_type as u8;
    event._pad = [0u8; 2];
    event.data_len = 0;
    event.captured_len = 0;
    event.data = [0u8; MAX_PAYLOAD_SIZE];

    // Get process name
    if let Ok(comm) = ctx.command() {
        event.comm = comm;
    }

    // Read socket path
    let sock_ptr: u64 = ctx.arg(0).ok_or(1u32)?;
    unsafe { read_sock_path(sock_ptr, &mut event.path) };

    // Apply kernel-side filter
    if should_filter(pid, &event.path) {
        return Ok(0);
    }

    // Read message size from the third argument (size_t len)
    let msg_len: u64 = ctx.arg(2).unwrap_or(0);
    event.data_len = msg_len as u32;

    EVENTS.output(ctx, event, 0);
    Ok(0)
}

// --- STREAM probes ---

#[kprobe]
pub fn udsdump_stream_sendmsg(ctx: ProbeContext) -> u32 {
    match handle_msg(&ctx, Direction::Send, SockType::Stream) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kprobe]
pub fn udsdump_stream_recvmsg(ctx: ProbeContext) -> u32 {
    match handle_msg(&ctx, Direction::Recv, SockType::Stream) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// --- DGRAM probes ---

#[kprobe]
pub fn udsdump_dgram_sendmsg(ctx: ProbeContext) -> u32 {
    match handle_msg(&ctx, Direction::Send, SockType::Dgram) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kprobe]
pub fn udsdump_dgram_recvmsg(ctx: ProbeContext) -> u32 {
    match handle_msg(&ctx, Direction::Recv, SockType::Dgram) {
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
