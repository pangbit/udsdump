# udsdump Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Linux UDS packet capture and analysis tool using Rust + eBPF (Aya framework).

**Architecture:** Three-crate workspace: `udsdump-common` (shared types, no_std), `udsdump-ebpf` (kprobe probes, no_std), `udsdump` (userspace CLI with clap + tokio). eBPF probes hook into `unix_stream_sendmsg`/`recvmsg` and `unix_dgram_sendmsg`/`recvmsg` to capture UDS traffic, transmitting events via PerfEventArray to userspace for filtering and display.

**Tech Stack:** Rust 2024 edition, Aya (aya/aya-ebpf/aya-build), clap 4, tokio, nix, libc

---

## Task 1: Initialize workspace and build infrastructure

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `.cargo/config.toml`
- Create: `udsdump-common/Cargo.toml`
- Create: `udsdump-common/src/lib.rs`
- Create: `udsdump-ebpf/Cargo.toml`
- Create: `udsdump-ebpf/build.rs`
- Create: `udsdump-ebpf/src/lib.rs`
- Create: `udsdump-ebpf/src/main.rs`
- Create: `udsdump/Cargo.toml`
- Create: `udsdump/build.rs`
- Create: `udsdump/src/main.rs`

**Step 1: Create workspace root Cargo.toml**

```toml
[workspace]
resolver = "2"
members = [
    "udsdump",
    "udsdump-common",
    "udsdump-ebpf",
]
default-members = ["udsdump", "udsdump-common"]

[workspace.package]
license = "MIT OR Apache-2.0"
edition = "2024"

[workspace.dependencies]
aya = { git = "https://github.com/aya-rs/aya", default-features = false }
aya-build = { git = "https://github.com/aya-rs/aya", default-features = false }
aya-ebpf = { git = "https://github.com/aya-rs/aya", default-features = false }
aya-log = { git = "https://github.com/aya-rs/aya", default-features = false }
aya-log-ebpf = { git = "https://github.com/aya-rs/aya", default-features = false }

anyhow = { version = "1", default-features = false }
cargo_metadata = { version = "0.23.0", default-features = false }
clap = { version = "4.5", default-features = false, features = ["std", "derive"] }
env_logger = { version = "0.11", default-features = false }
libc = { version = "0.2", default-features = false }
log = { version = "0.4", default-features = false }
nix = { version = "0.29", default-features = false }
tokio = { version = "1", default-features = false }
which = { version = "6.0", default-features = false }
bytes = { version = "1", default-features = false }

[profile.release.package.udsdump-ebpf]
debug = 2
codegen-units = 1
```

**Step 2: Create `.cargo/config.toml`**

```toml
[target."cfg(all())"]
runner = "sudo -E"
```

**Step 3: Create udsdump-common crate**

`udsdump-common/Cargo.toml`:
```toml
[package]
name = "udsdump-common"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[features]
default = []
user = ["aya"]

[dependencies]
aya = { workspace = true, optional = true }

[lib]
path = "src/lib.rs"
```

`udsdump-common/src/lib.rs`:
```rust
#![no_std]
```

**Step 4: Create udsdump-ebpf crate**

`udsdump-ebpf/Cargo.toml`:
```toml
[package]
name = "udsdump-ebpf"
version = "0.1.0"
edition.workspace = true

[dependencies]
udsdump-common = { path = "../udsdump-common" }
aya-ebpf = { workspace = true }
aya-log-ebpf = { workspace = true }

[build-dependencies]
which = { workspace = true }

[[bin]]
name = "udsdump"
path = "src/main.rs"
```

`udsdump-ebpf/build.rs`:
```rust
use which::which;

fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
```

`udsdump-ebpf/src/lib.rs`:
```rust
#![no_std]
```

`udsdump-ebpf/src/main.rs` (minimal placeholder):
```rust
#![no_std]
#![no_main]

use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[kprobe]
pub fn udsdump_sendmsg(ctx: ProbeContext) -> u32 {
    match try_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
```

**Step 5: Create udsdump userspace crate**

`udsdump/Cargo.toml`:
```toml
[package]
name = "udsdump"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
udsdump-common = { path = "../udsdump-common", features = ["user"] }
anyhow = { workspace = true, default-features = true }
aya = { workspace = true }
aya-log = { workspace = true }
clap = { workspace = true, features = ["derive"] }
env_logger = { workspace = true }
libc = { workspace = true }
log = { workspace = true }
nix = { workspace = true, features = ["fs"] }
tokio = { workspace = true, features = ["macros", "rt", "rt-multi-thread", "net", "signal"] }
bytes = { workspace = true, default-features = true }

[build-dependencies]
anyhow = { workspace = true }
aya-build = { workspace = true }
cargo_metadata = { workspace = true }
udsdump-ebpf = { path = "../udsdump-ebpf" }

[[bin]]
name = "udsdump"
path = "src/main.rs"
```

`udsdump/build.rs`:
```rust
use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "udsdump-ebpf")
        .ok_or_else(|| anyhow!("udsdump-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
```

`udsdump/src/main.rs` (minimal placeholder):
```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "udsdump", about = "Unix Domain Socket packet capture and analysis tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Capture UDS traffic in real-time
    Capture,
    /// List current UDS connections
    List,
    /// Show UDS statistics
    Stats,
    /// Real-time sorted traffic view
    Top,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Capture => println!("capture: not implemented"),
        Commands::List => println!("list: not implemented"),
        Commands::Stats => println!("stats: not implemented"),
        Commands::Top => println!("top: not implemented"),
    }
    Ok(())
}
```

**Step 6: Verify build compiles**

Run: `cargo build 2>&1` (on a Linux machine with bpf-linker installed)
Expected: Build succeeds, or at least workspace structure is valid.

Note: eBPF compilation requires Linux with `bpf-linker`. On macOS, `cargo check --package udsdump-common` should work.

**Step 7: Commit**

```bash
git add -A
git commit -m "feat: initialize workspace with aya eBPF project structure

Three-crate workspace: udsdump (userspace CLI), udsdump-ebpf (kprobe probes),
udsdump-common (shared types). Uses aya-build for integrated eBPF compilation."
```

---

## Task 2: Define shared event types in udsdump-common

**Files:**
- Modify: `udsdump-common/src/lib.rs`

**Step 1: Define the UdsEvent struct and related types**

Replace `udsdump-common/src/lib.rs` with:

```rust
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
```

**Step 2: Verify common crate compiles in both modes**

Run: `cargo check --package udsdump-common`
Run: `cargo check --package udsdump-common --features user`
Expected: Both pass.

**Step 3: Commit**

```bash
git add udsdump-common/src/lib.rs
git commit -m "feat: define shared UdsEvent and FilterConfig types

Shared between eBPF probes and userspace. Includes event structure with
pid, comm, socket path, direction, payload, and a filter config for
kernel-side filtering by PID and path prefix."
```

---

## Task 3: Implement eBPF kprobe probes

**Files:**
- Modify: `udsdump-ebpf/src/main.rs`

**Step 1: Implement the full eBPF probe program**

Replace `udsdump-ebpf/src/main.rs` with:

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel},
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

/// Read the socket path from the unix_sock -> addr -> name -> sun_path.
/// This traverses: struct socket -> struct sock -> struct unix_sock ->
///   struct unix_address -> struct sockaddr_un -> sun_path
///
/// Since we can't include kernel headers, we use known offsets.
/// These offsets may vary by kernel version; CO-RE/BTF would be ideal
/// but for now we use conservative offsets for >= 5.4 kernels.
///
/// Returns the number of bytes read into `path_buf`.
unsafe fn read_sock_path(sock_ptr: u64, path_buf: &mut [u8; MAX_PATH_LEN]) -> u32 {
    // In the kernel, unix_stream_sendmsg receives struct socket *sock.
    // struct socket { ..., struct sock *sk; }
    // sk is at offset 32 in struct socket (may vary, but stable on 5.4+).
    let sk_ptr: u64 = match bpf_probe_read_kernel((sock_ptr + 32) as *const u64) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // struct unix_sock embeds struct sock at offset 0.
    // struct unix_sock { struct sock sk; ...; struct unix_address *addr; }
    // The addr field offset varies by kernel. On 5.4+ it's typically around
    // offset 888 but this needs BTF for portability. We'll use a best-effort
    // approach and this should be refined with BTF/CO-RE.
    //
    // For now, we try to read the path from the socket's associated
    // sockaddr_un via the unix_sock->addr pointer.
    // unix_sock->addr is at an offset that depends on the kernel.
    // A safer approach: read from unix_sock->path (struct path) or
    // use the addr->name.sun_path.
    //
    // Note: The exact offset needs to be determined per-kernel.
    // For the initial implementation, we'll attempt to read the addr field
    // at a common offset and gracefully handle failures.

    // Try to get the unix_address pointer from unix_sock.
    // This offset is kernel-version dependent. Common values:
    // - 5.4-5.10: ~888
    // - 5.15+: ~880
    // We'll try offset 880 first, which works on many modern kernels.
    let addr_ptr: u64 = match bpf_probe_read_kernel((sk_ptr + 880) as *const u64) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if addr_ptr == 0 {
        return 0;
    }

    // struct unix_address { ...; struct sockaddr_un name; }
    // sockaddr_un starts at offset 12 in unix_address (after refcount + len).
    // sun_path is at offset 2 within sockaddr_un (after sun_family).
    let sun_path_ptr = addr_ptr + 12 + 2;

    // Read up to MAX_PATH_LEN bytes of the path.
    match bpf_probe_read_kernel_str_bytes(sun_path_ptr as *const u8, path_buf) {
        Ok(s) => s.len() as u32,
        Err(_) => 0,
    }
}

use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;

/// Check if the event passes the filter.
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

    // Apply filter
    if should_filter(pid, &event.path) {
        return Ok(0);
    }

    // Read message size from msghdr.
    // Second argument to sendmsg/recvmsg is struct msghdr *.
    // struct msghdr { ...; struct iov_iter msg_iter; }
    // For now we capture the size argument (third arg) which is `size_t len`.
    let msg_len: u64 = ctx.arg(2).unwrap_or(0);
    event.data_len = msg_len as u32;

    // Try to read payload from the iov.
    // msghdr->msg_iter contains the I/O vectors.
    // This is complex to read in eBPF; for the initial version we'll
    // capture the data_len but leave payload capture for a follow-up
    // that reads from the iov_iter properly.
    // TODO: Read payload from msg_iter.iov->iov_base

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
```

**Step 2: Verify eBPF crate compiles**

Run: `cargo check --package udsdump-ebpf` (requires Linux with bpf-linker)
Expected: Compiles or reports known offset issues to fix.

Note: The kernel struct offsets (socket->sk, unix_sock->addr) are hardcoded and may need adjustment per kernel version. This is a known limitation that will be refined with BTF/CO-RE support later.

**Step 3: Commit**

```bash
git add udsdump-ebpf/src/main.rs
git commit -m "feat: implement eBPF kprobe probes for UDS send/recv

Hook unix_stream_sendmsg/recvmsg and unix_dgram_sendmsg/recvmsg.
Captures PID, comm, socket path, direction, message length.
Supports kernel-side filtering by PID and path prefix via Array map."
```

---

## Task 4: Implement CLI argument parsing with clap

**Files:**
- Modify: `udsdump/src/main.rs`

**Step 1: Define the full CLI structure with all subcommands and options**

Replace `udsdump/src/main.rs` with:

```rust
mod capture;
mod display;
mod filter;
mod list;
mod stats;
mod top;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "udsdump",
    version,
    about = "Unix Domain Socket packet capture and analysis tool"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Capture UDS traffic in real-time
    Capture(CaptureArgs),
    /// List current UDS connections
    List(ListArgs),
    /// Show UDS statistics
    Stats(StatsArgs),
    /// Real-time sorted traffic view
    Top(TopArgs),
}

#[derive(Parser)]
pub struct CaptureArgs {
    /// Filter by socket path (prefix match)
    #[arg(long)]
    pub path: Option<String>,

    /// Filter by process PID
    #[arg(long)]
    pub pid: Option<u32>,

    /// Filter by process name
    #[arg(long)]
    pub comm: Option<String>,

    /// Filter by socket type
    #[arg(long, value_enum)]
    pub r#type: Option<SocketTypeFilter>,

    /// Display payload as hex dump
    #[arg(long)]
    pub hex: bool,

    /// Display payload as ASCII (default)
    #[arg(long)]
    pub ascii: bool,

    /// Maximum payload bytes to display per packet
    #[arg(long, default_value = "256")]
    pub max_bytes: usize,

    /// Stop after capturing N packets
    #[arg(long)]
    pub count: Option<u64>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser)]
pub struct ListArgs {
    /// Filter by socket path
    #[arg(long)]
    pub path: Option<String>,

    /// Filter by process PID
    #[arg(long)]
    pub pid: Option<u32>,

    /// Filter by connection state
    #[arg(long)]
    pub state: Option<String>,

    /// Filter by socket type
    #[arg(long, value_enum)]
    pub r#type: Option<SocketTypeFilter>,

    /// Resolve inode to process information
    #[arg(long)]
    pub resolve: bool,
}

#[derive(Parser)]
pub struct StatsArgs {
    /// Filter by socket path
    #[arg(long)]
    pub path: Option<String>,

    /// Filter by process PID
    #[arg(long)]
    pub pid: Option<u32>,

    /// Refresh interval in seconds (0 = single snapshot)
    #[arg(long, default_value = "0")]
    pub interval: u64,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser)]
pub struct TopArgs {
    /// Sort field
    #[arg(long, value_enum, default_value = "bytes")]
    pub sort: SortField,

    /// Refresh interval in seconds
    #[arg(long, default_value = "1")]
    pub interval: u64,
}

#[derive(Clone, ValueEnum)]
pub enum SocketTypeFilter {
    Stream,
    Dgram,
}

#[derive(Clone, ValueEnum)]
pub enum SortField {
    Bytes,
    Msgs,
    Rate,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Capture(args) => capture::run(args),
        Commands::List(args) => list::run(args),
        Commands::Stats(args) => stats::run(args),
        Commands::Top(args) => top::run(args),
    }
}
```

**Step 2: Create stub modules**

Create `udsdump/src/capture.rs`:
```rust
use crate::CaptureArgs;

pub fn run(_args: CaptureArgs) -> anyhow::Result<()> {
    eprintln!("capture: not yet implemented");
    Ok(())
}
```

Create `udsdump/src/list.rs`:
```rust
use crate::ListArgs;

pub fn run(_args: ListArgs) -> anyhow::Result<()> {
    eprintln!("list: not yet implemented");
    Ok(())
}
```

Create `udsdump/src/stats.rs`:
```rust
use crate::StatsArgs;

pub fn run(_args: StatsArgs) -> anyhow::Result<()> {
    eprintln!("stats: not yet implemented");
    Ok(())
}
```

Create `udsdump/src/top.rs`:
```rust
use crate::TopArgs;

pub fn run(_args: TopArgs) -> anyhow::Result<()> {
    eprintln!("top: not yet implemented");
    Ok(())
}
```

Create `udsdump/src/display.rs`:
```rust
// Display formatting utilities - will be implemented in later tasks.
```

Create `udsdump/src/filter.rs`:
```rust
// Userspace filtering logic - will be implemented in later tasks.
```

**Step 3: Verify CLI parses correctly**

Run: `cargo run -- --help`
Run: `cargo run -- capture --help`
Run: `cargo run -- list --help`
Expected: Help text shows all options correctly.

**Step 4: Commit**

```bash
git add udsdump/src/
git commit -m "feat: implement CLI argument parsing with clap

Define subcommands: capture, list, stats, top with all planned options.
Create stub modules for each subcommand."
```

---

## Task 5: Implement the `list` subcommand (no eBPF needed)

**Files:**
- Modify: `udsdump/src/list.rs`
- Modify: `udsdump/Cargo.toml` (may need to add regex or glob dependency if needed)

This is the simplest subcommand — it reads `/proc/net/unix` and `/proc/*/fd` without needing eBPF.

**Step 1: Implement /proc/net/unix parser and process resolver**

Replace `udsdump/src/list.rs` with:

```rust
use crate::ListArgs;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Parsed entry from /proc/net/unix.
struct UnixSocketEntry {
    inode: u64,
    sock_type: &'static str,
    state: &'static str,
    path: String,
}

/// Process info resolved from /proc/*/fd.
struct ProcessInfo {
    pid: u32,
    comm: String,
}

/// Parse /proc/net/unix and return all socket entries.
fn parse_proc_net_unix() -> anyhow::Result<Vec<UnixSocketEntry>> {
    let content = fs::read_to_string("/proc/net/unix")?;
    let mut entries = Vec::new();

    for line in content.lines().skip(1) {
        // Format: Num RefCount Protocol Flags Type St Inode Path
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 {
            continue;
        }

        let sock_type = match fields[4] {
            "0001" => "STREAM",
            "0002" => "DGRAM",
            "0005" => "SEQPACKET",
            _ => "UNKNOWN",
        };

        let state = match fields[5] {
            "01" => "UNCONNECTED",
            "02" => "CONNECTING",
            "03" => "CONNECTED",
            "04" => "DISCONNECTING",
            "05" => "LISTEN",
            _ => "UNKNOWN",
        };

        let inode: u64 = fields[6].parse().unwrap_or(0);
        let path = if fields.len() > 7 {
            fields[7].to_string()
        } else {
            String::new()
        };

        entries.push(UnixSocketEntry {
            inode,
            sock_type,
            state,
            path,
        });
    }

    Ok(entries)
}

/// Build a map from inode -> ProcessInfo by scanning /proc/*/fd.
fn resolve_inodes_to_processes(inodes: &[u64]) -> HashMap<u64, ProcessInfo> {
    let mut map = HashMap::new();
    let inode_set: std::collections::HashSet<u64> = inodes.iter().copied().collect();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only process numeric directories (PIDs)
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = Path::new("/proc").join(&name_str).join("fd");
        let fd_entries = match fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_entry in fd_entries.flatten() {
            let link = match fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };

            let link_str = link.to_string_lossy();
            // fd links for sockets look like: socket:[12345]
            if let Some(inode_str) = link_str.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                if let Ok(inode) = inode_str.parse::<u64>() {
                    if inode_set.contains(&inode) {
                        // Read comm
                        let comm_path = Path::new("/proc").join(&name_str).join("comm");
                        let comm = fs::read_to_string(comm_path)
                            .unwrap_or_default()
                            .trim()
                            .to_string();

                        map.insert(inode, ProcessInfo { pid, comm });
                    }
                }
            }
        }
    }

    map
}

pub fn run(args: ListArgs) -> anyhow::Result<()> {
    let entries = parse_proc_net_unix()?;

    // Collect inodes for process resolution
    let inodes: Vec<u64> = entries.iter().map(|e| e.inode).collect();
    let proc_map = if args.resolve {
        resolve_inodes_to_processes(&inodes)
    } else {
        HashMap::new()
    };

    // Print header
    if args.resolve {
        println!(
            "{:<8} {:<12} {:<10} {:<8} {:<16} {}",
            "TYPE", "STATE", "INODE", "PID", "COMM", "PATH"
        );
    } else {
        println!(
            "{:<8} {:<12} {:<10} {}",
            "TYPE", "STATE", "INODE", "PATH"
        );
    }

    for entry in &entries {
        // Apply filters
        if let Some(ref filter_path) = args.path {
            if !entry.path.contains(filter_path.as_str()) {
                continue;
            }
        }
        if let Some(ref filter_state) = args.state {
            if !entry.state.eq_ignore_ascii_case(filter_state) {
                continue;
            }
        }
        if let Some(ref filter_type) = args.r#type {
            let type_str = match filter_type {
                crate::SocketTypeFilter::Stream => "STREAM",
                crate::SocketTypeFilter::Dgram => "DGRAM",
            };
            if entry.sock_type != type_str {
                continue;
            }
        }
        if let Some(filter_pid) = args.pid {
            if let Some(proc_info) = proc_map.get(&entry.inode) {
                if proc_info.pid != filter_pid {
                    continue;
                }
            } else {
                continue;
            }
        }

        if args.resolve {
            let (pid_str, comm_str) = if let Some(proc_info) = proc_map.get(&entry.inode) {
                (proc_info.pid.to_string(), proc_info.comm.as_str())
            } else {
                ("-".to_string(), "-")
            };
            println!(
                "{:<8} {:<12} {:<10} {:<8} {:<16} {}",
                entry.sock_type,
                entry.state,
                entry.inode,
                pid_str,
                comm_str,
                if entry.path.is_empty() { "-" } else { &entry.path }
            );
        } else {
            println!(
                "{:<8} {:<12} {:<10} {}",
                entry.sock_type,
                entry.state,
                entry.inode,
                if entry.path.is_empty() { "-" } else { &entry.path }
            );
        }
    }

    Ok(())
}
```

**Step 2: Test the list command on a Linux machine**

Run: `cargo run -- list`
Run: `cargo run -- list --resolve`
Run: `cargo run -- list --type stream --state listen`
Expected: Shows UDS connections from /proc/net/unix.

**Step 3: Commit**

```bash
git add udsdump/src/list.rs
git commit -m "feat: implement 'list' subcommand

Parses /proc/net/unix to show all Unix domain socket connections.
Supports --resolve to map socket inodes to processes via /proc/*/fd.
Supports filtering by --path, --pid, --state, --type."
```

---

## Task 6: Implement display formatting utilities

**Files:**
- Modify: `udsdump/src/display.rs`

**Step 1: Implement hex dump and event formatting**

Replace `udsdump/src/display.rs` with:

```rust
use udsdump_common::UdsEvent;

/// Format a UdsEvent as a human-readable one-line summary.
pub fn format_event_header(event: &UdsEvent) -> String {
    let timestamp = format_timestamp(event.timestamp_ns);
    let comm = core_str(&event.comm);
    let direction = if event.direction == 0 { "→" } else { "←" };
    let sock_type = match event.sock_type {
        1 => "STREAM",
        2 => "DGRAM",
        5 => "SEQPACKET",
        _ => "UNKNOWN",
    };
    let path = core_str(&event.path);
    let path_display = if path.is_empty() { "<anonymous>" } else { &path };

    format!(
        "{} {}({}) {} [{}] {} {}B",
        timestamp, comm, event.pid, direction, path_display, sock_type, event.data_len
    )
}

/// Format payload as ASCII with non-printable chars escaped.
pub fn format_payload_ascii(data: &[u8], max_bytes: usize) -> String {
    let len = data.len().min(max_bytes);
    let mut out = String::with_capacity(len * 2);
    for &b in &data[..len] {
        if b >= 0x20 && b < 0x7f {
            out.push(b as char);
        } else if b == b'\n' {
            out.push_str("\\n");
        } else if b == b'\r' {
            out.push_str("\\r");
        } else if b == b'\t' {
            out.push_str("\\t");
        } else {
            out.push_str(&format!("\\x{:02x}", b));
        }
    }
    if data.len() > max_bytes {
        out.push_str("...");
    }
    out
}

/// Format payload as hex dump (similar to `xxd` or `tcpdump -X`).
pub fn format_payload_hex(data: &[u8], max_bytes: usize) -> String {
    let len = data.len().min(max_bytes);
    let mut out = String::new();

    for (i, chunk) in data[..len].chunks(16).enumerate() {
        let offset = i * 16;
        // Offset
        out.push_str(&format!("  {:04x}  ", offset));

        // Hex bytes
        for (j, &b) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x} ", b));
            if j == 7 {
                out.push(' ');
            }
        }
        // Pad if less than 16 bytes
        let pad = 16 - chunk.len();
        for j in 0..pad {
            out.push_str("   ");
            if chunk.len() + j == 7 {
                out.push(' ');
            }
        }

        // ASCII representation
        out.push_str(" |");
        for &b in chunk {
            if b >= 0x20 && b < 0x7f {
                out.push(b as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }

    out
}

/// Format event as JSON.
pub fn format_event_json(event: &UdsEvent) -> String {
    let comm = core_str(&event.comm);
    let path = core_str(&event.path);
    let direction = if event.direction == 0 { "send" } else { "recv" };
    let sock_type = match event.sock_type {
        1 => "stream",
        2 => "dgram",
        5 => "seqpacket",
        _ => "unknown",
    };
    let payload_b64 = base64_encode(&event.data[..event.captured_len as usize]);

    format!(
        r#"{{"timestamp_ns":{},"pid":{},"tid":{},"comm":"{}","direction":"{}","sock_type":"{}","path":"{}","data_len":{},"captured_len":{},"payload":"{}"}}"#,
        event.timestamp_ns,
        event.pid,
        event.tid,
        comm,
        direction,
        sock_type,
        path,
        event.data_len,
        event.captured_len,
        payload_b64,
    )
}

/// Extract a null-terminated string from a byte array.
fn core_str(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

/// Format monotonic timestamp as HH:MM:SS.microseconds.
fn format_timestamp(ns: u64) -> String {
    let total_secs = ns / 1_000_000_000;
    let micros = (ns % 1_000_000_000) / 1_000;
    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    format!("{:02}:{:02}:{:02}.{:06}", hours, mins, secs, micros)
}

/// Simple base64 encoding (no external dependency).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3f) as usize] as char);

        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(CHARS[(n & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}
```

**Step 2: Commit**

```bash
git add udsdump/src/display.rs
git commit -m "feat: implement display formatting utilities

Hex dump, ASCII, and JSON output formats for UDS events.
Includes timestamp formatting and base64 encoding for JSON payload."
```

---

## Task 7: Implement userspace filter logic

**Files:**
- Modify: `udsdump/src/filter.rs`

**Step 1: Implement userspace event filtering**

Replace `udsdump/src/filter.rs` with:

```rust
use udsdump_common::UdsEvent;

/// Userspace filter criteria (applied after kernel-side filtering).
pub struct EventFilter {
    pub path: Option<String>,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub sock_type: Option<u8>,
}

impl EventFilter {
    /// Returns true if the event matches all filter criteria.
    pub fn matches(&self, event: &UdsEvent) -> bool {
        if let Some(pid) = self.pid {
            if event.pid != pid {
                return false;
            }
        }

        if let Some(ref comm) = self.comm {
            let event_comm = core_str(&event.comm);
            if !event_comm.contains(comm.as_str()) {
                return false;
            }
        }

        if let Some(ref path) = self.path {
            let event_path = core_str(&event.path);
            if !event_path.contains(path.as_str()) {
                return false;
            }
        }

        if let Some(sock_type) = self.sock_type {
            if event.sock_type != sock_type {
                return false;
            }
        }

        true
    }
}

/// Extract a null-terminated string from a byte array.
fn core_str(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}
```

**Step 2: Commit**

```bash
git add udsdump/src/filter.rs
git commit -m "feat: implement userspace event filter

Filters events by PID, process name, socket path, and socket type.
Applied after kernel-side filtering for finer-grained control."
```

---

## Task 8: Implement the `capture` subcommand

**Files:**
- Modify: `udsdump/src/capture.rs`

**Step 1: Implement eBPF loading, probe attachment, and event reading**

Replace `udsdump/src/capture.rs` with:

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use aya::maps::{Array, PerfEventArray};
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{Ebpf, include_bytes_aligned};
use bytes::BytesMut;
use log::{debug, warn};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use udsdump_common::{FilterConfig, UdsEvent, MAX_PATH_LEN};

use crate::{CaptureArgs, SocketTypeFilter};
use crate::display;
use crate::filter::EventFilter;

/// Load and attach eBPF probes, then read events.
pub fn run(args: CaptureArgs) -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(args))
}

async fn run_async(args: CaptureArgs) -> anyhow::Result<()> {
    // Bump memlock rlimit for older kernels
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load eBPF program
    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/udsdump"
    )))?;

    // Initialize eBPF logger
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => warn!("failed to initialize eBPF logger: {e}"),
        Ok(logger) => {
            let mut logger = AsyncFd::with_interest(logger, Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // Set up kernel-side filter
    setup_filter(&mut ebpf, &args)?;

    // Attach kprobes
    attach_probe(&mut ebpf, "udsdump_stream_sendmsg", "unix_stream_sendmsg")?;
    attach_probe(&mut ebpf, "udsdump_stream_recvmsg", "unix_stream_recvmsg")?;
    attach_probe(&mut ebpf, "udsdump_dgram_sendmsg", "unix_dgram_sendmsg")?;
    attach_probe(&mut ebpf, "udsdump_dgram_recvmsg", "unix_dgram_recvmsg")?;

    // Build userspace filter
    let user_filter = EventFilter {
        path: args.path.clone(),
        pid: args.pid,
        comm: args.comm.clone(),
        sock_type: args.r#type.as_ref().map(|t| match t {
            SocketTypeFilter::Stream => 1u8,
            SocketTypeFilter::Dgram => 2u8,
        }),
    };

    // Open perf event buffers
    let mut perf_array = PerfEventArray::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let cpus = online_cpus().map_err(|(_, e)| e)?;
    let mut async_fds = Vec::new();

    for cpu_id in cpus {
        let buf = perf_array.open(cpu_id, None)?;
        let async_fd = AsyncFd::with_interest(buf, Interest::READABLE)?;
        async_fds.push(async_fd);
    }

    // Event reading loop
    let running = Arc::new(AtomicBool::new(true));
    let count = Arc::new(AtomicU64::new(0));
    let max_count = args.count;
    let show_hex = args.hex;
    let show_json = args.json;
    let max_bytes = args.max_bytes;

    // Handle Ctrl+C
    let running_clone = running.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        running_clone.store(false, Ordering::Relaxed);
    });

    eprintln!("Capturing UDS traffic... Press Ctrl+C to stop.");

    let mut out_bufs = (0..16).map(|_| BytesMut::with_capacity(core::mem::size_of::<UdsEvent>() + 64)).collect::<Vec<_>>();

    while running.load(Ordering::Relaxed) {
        for async_fd in &mut async_fds {
            let mut guard = async_fd.readable_mut().await?;
            let buf = guard.get_inner_mut();

            match buf.read_events(&mut out_bufs) {
                Ok(events) => {
                    for i in 0..events.read {
                        let data = &out_bufs[i];
                        if data.len() < core::mem::size_of::<UdsEvent>() {
                            continue;
                        }
                        let event = unsafe { &*(data.as_ptr() as *const UdsEvent) };

                        if !user_filter.matches(event) {
                            continue;
                        }

                        if show_json {
                            println!("{}", display::format_event_json(event));
                        } else {
                            println!("{}", display::format_event_header(event));
                            let payload = &event.data[..event.captured_len as usize];
                            if !payload.is_empty() {
                                if show_hex {
                                    print!("{}", display::format_payload_hex(payload, max_bytes));
                                } else {
                                    println!("  {}", display::format_payload_ascii(payload, max_bytes));
                                }
                            }
                        }

                        let current = count.fetch_add(1, Ordering::Relaxed) + 1;
                        if let Some(max) = max_count {
                            if current >= max {
                                running.store(false, Ordering::Relaxed);
                                break;
                            }
                        }
                    }

                    if events.lost > 0 {
                        eprintln!("Warning: lost {} events", events.lost);
                    }
                }
                Err(e) => {
                    warn!("error reading perf events: {e}");
                }
            }

            guard.clear_ready();
        }
    }

    eprintln!("\nCaptured {} events.", count.load(Ordering::Relaxed));
    Ok(())
}

fn attach_probe(ebpf: &mut Ebpf, prog_name: &str, fn_name: &str) -> anyhow::Result<()> {
    let program: &mut KProbe = ebpf.program_mut(prog_name).unwrap().try_into()?;
    program.load()?;
    program.attach(fn_name, 0)?;
    debug!("attached kprobe: {} -> {}", prog_name, fn_name);
    Ok(())
}

fn setup_filter(ebpf: &mut Ebpf, args: &CaptureArgs) -> anyhow::Result<()> {
    let mut config = FilterConfig {
        target_pid: args.pid.unwrap_or(0),
        target_path: [0u8; MAX_PATH_LEN],
        target_path_len: 0,
    };

    if let Some(ref path) = args.path {
        let path_bytes = path.as_bytes();
        let len = path_bytes.len().min(MAX_PATH_LEN);
        config.target_path[..len].copy_from_slice(&path_bytes[..len]);
        config.target_path_len = len as u32;
    }

    let mut filter_map: Array<_, FilterConfig> =
        Array::try_from(ebpf.map_mut("FILTER").unwrap())?;
    filter_map.set(0, config, 0)?;

    Ok(())
}
```

**Step 2: Test on a Linux machine**

Run: `sudo cargo run -- capture`
Run: `sudo cargo run -- capture --path /var/run/docker.sock`
Run: `sudo cargo run -- capture --pid 1234 --hex`
Expected: Shows captured UDS events (or at least starts without error).

**Step 3: Commit**

```bash
git add udsdump/src/capture.rs
git commit -m "feat: implement 'capture' subcommand

Loads eBPF probes, attaches to unix_stream/dgram sendmsg/recvmsg.
Reads events via PerfEventArray, applies userspace filters, and
outputs in ASCII, hex, or JSON format. Supports Ctrl+C and --count."
```

---

## Task 9: Implement the `stats` subcommand

**Files:**
- Modify: `udsdump/src/stats.rs`

**Step 1: Implement stats with /proc snapshot and optional eBPF live stats**

Replace `udsdump/src/stats.rs` with:

```rust
use std::collections::HashMap;
use std::fs;
use std::thread;
use std::time::Duration;

use crate::StatsArgs;

/// Socket type counts.
struct TypeStats {
    stream: u32,
    dgram: u32,
    seqpacket: u32,
}

/// Socket state counts.
struct StateStats {
    listen: u32,
    connected: u32,
    unconnected: u32,
    connecting: u32,
    disconnecting: u32,
}

pub fn run(args: StatsArgs) -> anyhow::Result<()> {
    loop {
        print_stats(&args)?;

        if args.interval == 0 {
            break;
        }

        thread::sleep(Duration::from_secs(args.interval));
        // Clear screen for refresh
        print!("\x1B[2J\x1B[H");
    }

    Ok(())
}

fn print_stats(args: &StatsArgs) -> anyhow::Result<()> {
    let content = fs::read_to_string("/proc/net/unix")?;

    let mut type_stats = TypeStats {
        stream: 0,
        dgram: 0,
        seqpacket: 0,
    };
    let mut state_stats = StateStats {
        listen: 0,
        connected: 0,
        unconnected: 0,
        connecting: 0,
        disconnecting: 0,
    };
    let mut path_counts: HashMap<String, u32> = HashMap::new();
    let mut total: u32 = 0;

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 {
            continue;
        }

        let path = if fields.len() > 7 {
            fields[7].to_string()
        } else {
            String::new()
        };

        // Apply path filter
        if let Some(ref filter_path) = args.path {
            if !path.contains(filter_path.as_str()) {
                continue;
            }
        }

        total += 1;

        // Count by type
        match fields[4] {
            "0001" => type_stats.stream += 1,
            "0002" => type_stats.dgram += 1,
            "0005" => type_stats.seqpacket += 1,
            _ => {}
        }

        // Count by state
        match fields[5] {
            "01" => state_stats.unconnected += 1,
            "02" => state_stats.connecting += 1,
            "03" => state_stats.connected += 1,
            "04" => state_stats.disconnecting += 1,
            "05" => state_stats.listen += 1,
            _ => {}
        }

        // Count by path
        if !path.is_empty() {
            *path_counts.entry(path).or_insert(0) += 1;
        }
    }

    if args.json {
        print_stats_json(total, &type_stats, &state_stats, &path_counts);
    } else {
        print_stats_text(total, &type_stats, &state_stats, &path_counts);
    }

    Ok(())
}

fn print_stats_text(
    total: u32,
    type_stats: &TypeStats,
    state_stats: &StateStats,
    path_counts: &HashMap<String, u32>,
) {
    println!("=== UDS Statistics (snapshot) ===");
    println!("Total sockets:     {}", total);
    if total > 0 {
        println!(
            "  STREAM:          {:<6} ({:.0}%)",
            type_stats.stream,
            type_stats.stream as f64 / total as f64 * 100.0
        );
        println!(
            "  DGRAM:           {:<6} ({:.0}%)",
            type_stats.dgram,
            type_stats.dgram as f64 / total as f64 * 100.0
        );
        println!(
            "  SEQPACKET:       {:<6} ({:.0}%)",
            type_stats.seqpacket,
            type_stats.seqpacket as f64 / total as f64 * 100.0
        );
    }
    println!();
    println!("By state:");
    println!("  LISTEN:          {}", state_stats.listen);
    println!("  CONNECTED:       {}", state_stats.connected);
    println!("  UNCONNECTED:     {}", state_stats.unconnected);
    if state_stats.connecting > 0 {
        println!("  CONNECTING:      {}", state_stats.connecting);
    }
    if state_stats.disconnecting > 0 {
        println!("  DISCONNECTING:   {}", state_stats.disconnecting);
    }
    println!();

    // Top paths by socket count
    let mut sorted_paths: Vec<_> = path_counts.iter().collect();
    sorted_paths.sort_by(|a, b| b.1.cmp(a.1));

    println!("Top socket paths:");
    println!("  {:<6} {}", "COUNT", "PATH");
    for (path, count) in sorted_paths.iter().take(10) {
        println!("  {:<6} {}", count, path);
    }
}

fn print_stats_json(
    total: u32,
    type_stats: &TypeStats,
    state_stats: &StateStats,
    path_counts: &HashMap<String, u32>,
) {
    let mut sorted_paths: Vec<_> = path_counts.iter().collect();
    sorted_paths.sort_by(|a, b| b.1.cmp(a.1));

    let paths_json: Vec<String> = sorted_paths
        .iter()
        .take(10)
        .map(|(path, count)| format!(r#"{{"path":"{}","count":{}}}"#, path, count))
        .collect();

    println!(
        r#"{{"total":{},"by_type":{{"stream":{},"dgram":{},"seqpacket":{}}},"by_state":{{"listen":{},"connected":{},"unconnected":{}}},"top_paths":[{}]}}"#,
        total,
        type_stats.stream,
        type_stats.dgram,
        type_stats.seqpacket,
        state_stats.listen,
        state_stats.connected,
        state_stats.unconnected,
        paths_json.join(","),
    );
}
```

**Step 2: Test on Linux**

Run: `cargo run -- stats`
Run: `cargo run -- stats --json`
Run: `cargo run -- stats --interval 2`
Expected: Shows socket statistics.

**Step 3: Commit**

```bash
git add udsdump/src/stats.rs
git commit -m "feat: implement 'stats' subcommand

Shows UDS socket statistics from /proc/net/unix: type breakdown,
state breakdown, and top socket paths by count. Supports --interval
for periodic refresh and --json output."
```

---

## Task 10: Implement the `top` subcommand

**Files:**
- Modify: `udsdump/src/top.rs`

**Step 1: Implement real-time sorted view using eBPF events**

Replace `udsdump/src/top.rs` with:

```rust
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use aya::maps::{Array, PerfEventArray};
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{Ebpf, include_bytes_aligned};
use bytes::BytesMut;
use log::{debug, warn};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::time::{Duration, interval};

use udsdump_common::{FilterConfig, UdsEvent, MAX_PATH_LEN};
use crate::TopArgs;

struct ProcessStats {
    pid: u32,
    comm: String,
    bytes_sent: u64,
    bytes_recv: u64,
    msgs_sent: u64,
    msgs_recv: u64,
}

pub fn run(args: TopArgs) -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(args))
}

async fn run_async(args: TopArgs) -> anyhow::Result<()> {
    // Bump memlock rlimit
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    // Load eBPF
    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/udsdump"
    )))?;

    // No filter for top — capture everything
    let config = FilterConfig {
        target_pid: 0,
        target_path: [0u8; MAX_PATH_LEN],
        target_path_len: 0,
    };
    let mut filter_map: Array<_, FilterConfig> =
        Array::try_from(ebpf.map_mut("FILTER").unwrap())?;
    filter_map.set(0, config, 0)?;

    // Attach probes
    for (prog, func) in [
        ("udsdump_stream_sendmsg", "unix_stream_sendmsg"),
        ("udsdump_stream_recvmsg", "unix_stream_recvmsg"),
        ("udsdump_dgram_sendmsg", "unix_dgram_sendmsg"),
        ("udsdump_dgram_recvmsg", "unix_dgram_recvmsg"),
    ] {
        let program: &mut KProbe = ebpf.program_mut(prog).unwrap().try_into()?;
        program.load()?;
        program.attach(func, 0)?;
        debug!("attached kprobe: {} -> {}", prog, func);
    }

    // Open perf buffers
    let mut perf_array = PerfEventArray::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let cpus = online_cpus().map_err(|(_, e)| e)?;
    let mut async_fds = Vec::new();
    for cpu_id in cpus {
        let buf = perf_array.open(cpu_id, None)?;
        let async_fd = AsyncFd::with_interest(buf, Interest::READABLE)?;
        async_fds.push(async_fd);
    }

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        running_clone.store(false, Ordering::Relaxed);
    });

    let mut stats: HashMap<u32, ProcessStats> = HashMap::new();
    let mut tick = interval(Duration::from_secs(args.interval));
    let mut out_bufs: Vec<BytesMut> = (0..16)
        .map(|_| BytesMut::with_capacity(core::mem::size_of::<UdsEvent>() + 64))
        .collect();

    eprintln!("Monitoring UDS traffic... Press Ctrl+C to stop.\n");

    while running.load(Ordering::Relaxed) {
        tokio::select! {
            _ = tick.tick() => {
                print_top(&stats, &args);
            }
            _ = async {
                // Poll all CPUs for events
                for async_fd in &mut async_fds {
                    if let Ok(mut guard) = async_fd.readable_mut().await {
                        let buf = guard.get_inner_mut();
                        if let Ok(events) = buf.read_events(&mut out_bufs) {
                            for i in 0..events.read {
                                let data = &out_bufs[i];
                                if data.len() >= core::mem::size_of::<UdsEvent>() {
                                    let event = unsafe { &*(data.as_ptr() as *const UdsEvent) };
                                    update_stats(&mut stats, event);
                                }
                            }
                        }
                        guard.clear_ready();
                    }
                }
            } => {}
        }
    }

    Ok(())
}

fn update_stats(stats: &mut HashMap<u32, ProcessStats>, event: &UdsEvent) {
    let entry = stats.entry(event.pid).or_insert_with(|| {
        let comm = {
            let end = event.comm.iter().position(|&b| b == 0).unwrap_or(event.comm.len());
            String::from_utf8_lossy(&event.comm[..end]).to_string()
        };
        ProcessStats {
            pid: event.pid,
            comm,
            bytes_sent: 0,
            bytes_recv: 0,
            msgs_sent: 0,
            msgs_recv: 0,
        }
    });

    if event.direction == 0 {
        entry.bytes_sent += event.data_len as u64;
        entry.msgs_sent += 1;
    } else {
        entry.bytes_recv += event.data_len as u64;
        entry.msgs_recv += 1;
    }
}

fn print_top(stats: &HashMap<u32, ProcessStats>, args: &TopArgs) {
    // Clear screen
    print!("\x1B[2J\x1B[H");

    println!(
        "{:<8} {:<16} {:>12} {:>12} {:>10} {:>10}",
        "PID", "COMM", "BYTES_SENT", "BYTES_RECV", "MSGS_TX", "MSGS_RX"
    );
    println!("{}", "-".repeat(70));

    let mut sorted: Vec<&ProcessStats> = stats.values().collect();
    match args.sort {
        crate::SortField::Bytes => {
            sorted.sort_by(|a, b| {
                (b.bytes_sent + b.bytes_recv).cmp(&(a.bytes_sent + a.bytes_recv))
            });
        }
        crate::SortField::Msgs => {
            sorted.sort_by(|a, b| {
                (b.msgs_sent + b.msgs_recv).cmp(&(a.msgs_sent + a.msgs_recv))
            });
        }
        crate::SortField::Rate => {
            // For simplicity, sort by total bytes (rate requires time tracking)
            sorted.sort_by(|a, b| {
                (b.bytes_sent + b.bytes_recv).cmp(&(a.bytes_sent + a.bytes_recv))
            });
        }
    }

    for s in sorted.iter().take(20) {
        println!(
            "{:<8} {:<16} {:>12} {:>12} {:>10} {:>10}",
            s.pid,
            s.comm,
            format_bytes(s.bytes_sent),
            format_bytes(s.bytes_recv),
            s.msgs_sent,
            s.msgs_recv,
        );
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
```

**Step 2: Test on Linux**

Run: `sudo cargo run -- top`
Run: `sudo cargo run -- top --sort msgs --interval 2`
Expected: Shows real-time sorted UDS traffic view.

**Step 3: Commit**

```bash
git add udsdump/src/top.rs
git commit -m "feat: implement 'top' subcommand

Real-time sorted view of UDS traffic by process. Shows bytes sent/recv
and message counts, sorted by bytes, msgs, or rate. Refreshes at
configurable interval."
```

---

## Task 11: Add error handling and permission checks

**Files:**
- Modify: `udsdump/src/main.rs`

**Step 1: Add permission check helper and kernel version check**

Add to `udsdump/src/main.rs` before the `main()` function:

```rust
use nix::unistd::Uid;

/// Check if running as root or with required capabilities.
fn check_permissions(command: &str) -> anyhow::Result<()> {
    if command == "list" {
        // list only needs /proc access, no special permissions
        return Ok(());
    }

    if !Uid::effective().is_root() {
        anyhow::bail!(
            "udsdump {} requires root privileges or CAP_BPF + CAP_PERFMON capabilities.\n\
             Try: sudo udsdump {}",
            command,
            command
        );
    }
    Ok(())
}

/// Check minimum kernel version for eBPF support.
fn check_kernel_version() -> anyhow::Result<()> {
    let uname = nix::sys::utsname::uname()?;
    let release = uname.release().to_string_lossy();
    let parts: Vec<&str> = release.split('.').collect();
    if parts.len() >= 2 {
        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = parts[1].parse().unwrap_or(0);
        if major < 5 || (major == 5 && minor < 4) {
            anyhow::bail!(
                "udsdump requires Linux kernel >= 5.4 for BTF/CO-RE support.\n\
                 Current kernel: {}",
                release
            );
        }
    }
    Ok(())
}
```

Update the `main()` function:

```rust
fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let cmd_name = match &cli.command {
        Commands::Capture(_) => "capture",
        Commands::List(_) => "list",
        Commands::Stats(_) => "stats",
        Commands::Top(_) => "top",
    };

    check_permissions(cmd_name)?;

    // Only check kernel version for eBPF commands
    if cmd_name != "list" && cmd_name != "stats" {
        check_kernel_version()?;
    }

    match cli.command {
        Commands::Capture(args) => capture::run(args),
        Commands::List(args) => list::run(args),
        Commands::Stats(args) => stats::run(args),
        Commands::Top(args) => top::run(args),
    }
}
```

Update `nix` dependency in `udsdump/Cargo.toml` to include required features:

```toml
nix = { workspace = true, features = ["fs", "user"] }
```

And in the workspace root `Cargo.toml`, update nix:

```toml
nix = { version = "0.29", default-features = false, features = ["fs", "user"] }
```

**Step 2: Verify error messages**

Run: `cargo run -- capture` (without sudo)
Expected: "udsdump capture requires root privileges..."

Run: `cargo run -- list` (without sudo)
Expected: Works normally.

**Step 3: Commit**

```bash
git add udsdump/src/main.rs udsdump/Cargo.toml Cargo.toml
git commit -m "feat: add permission checks and kernel version validation

Check for root/CAP_BPF before running eBPF commands.
Check for kernel >= 5.4 before loading eBPF programs.
The 'list' command works without elevated privileges."
```

---

## Task 12: Add .gitignore and final cleanup

**Files:**
- Create: `.gitignore`
- Create: `README.md` (minimal)

**Step 1: Create .gitignore**

```
/target
**/*.rs.bk
*.swp
*.swo
.DS_Store
```

**Step 2: Final commit**

```bash
git add .gitignore
git commit -m "chore: add .gitignore"
```

---

## Summary

| Task | Description | eBPF? | Estimated Complexity |
|------|-------------|-------|---------------------|
| 1 | Workspace + build infrastructure | Yes | Medium |
| 2 | Shared event types | No | Low |
| 3 | eBPF kprobe probes | Yes | High |
| 4 | CLI argument parsing | No | Low |
| 5 | `list` subcommand | No | Medium |
| 6 | Display formatting | No | Low |
| 7 | Userspace filter | No | Low |
| 8 | `capture` subcommand | Yes | High |
| 9 | `stats` subcommand | No | Medium |
| 10 | `top` subcommand | Yes | High |
| 11 | Permission/kernel checks | No | Low |
| 12 | Cleanup | No | Low |

**Build dependencies:** Rust nightly (for eBPF target), `bpf-linker` (`cargo install bpf-linker`), Linux >= 5.4 with BTF support.

**Key risk:** Kernel struct offsets in Task 3 are hardcoded. The initial version should work on common 5.4+ kernels but will need BTF/CO-RE refinement for full portability.
