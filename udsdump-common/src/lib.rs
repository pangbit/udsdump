#![no_std]

/// Direction of the UDS message.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Send = 0,
    Recv = 1,
}

/// Type of Unix socket.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SockType {
    Stream = 1,
    Dgram = 2,
    SeqPacket = 5,
    Unknown = 0,
}

/// Maximum captured payload bytes per event.
pub const MAX_PAYLOAD_SIZE: usize = 256;

/// Maximum socket path length (same as sockaddr_un.sun_path).
pub const MAX_PATH_LEN: usize = 108;

/// Event transmitted from eBPF probe to userspace via PerfEventArray.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdsEvent {
    /// Monotonic timestamp in nanoseconds (bpf_ktime_get_ns).
    pub timestamp_ns: u64,
    /// Process ID (thread group ID).
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Process command name (up to 16 bytes).
    pub comm: [u8; 16],
    /// Socket inode number.
    pub sock_inode: u64,
    /// Peer socket inode number.
    pub peer_inode: u64,
    /// Unix socket path (sun_path from sockaddr_un).
    pub path: [u8; MAX_PATH_LEN],
    /// Message direction: send or receive.
    pub direction: u8,
    /// Socket type (STREAM, DGRAM, SEQPACKET).
    pub sock_type: u8,
    /// Padding for alignment.
    pub _pad: [u8; 2],
    /// Total data length of the message.
    pub data_len: u32,
    /// Actually captured payload length (<= MAX_PAYLOAD_SIZE).
    pub captured_len: u32,
    /// Captured payload bytes.
    pub data: [u8; MAX_PAYLOAD_SIZE],
}

/// Filter configuration passed from userspace to eBPF via a map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FilterConfig {
    /// Filter by PID. 0 means no filter.
    pub target_pid: u32,
    /// Filter by socket path prefix. Empty means no filter.
    pub target_path: [u8; MAX_PATH_LEN],
    /// Length of the target_path prefix to match.
    pub target_path_len: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UdsEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FilterConfig {}
