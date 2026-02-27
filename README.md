# udsdump

A Linux command-line tool for capturing, inspecting, and analyzing Unix Domain Socket (UDS) traffic in real-time. Think of it as `tcpdump` for Unix Domain Sockets.

Built with Rust and eBPF (via [Aya](https://aya-rs.dev)), `udsdump` hooks into kernel functions with zero overhead when not actively capturing.

## Features

- **Real-time capture** — Intercept UDS messages (STREAM / DGRAM) with metadata
- **Connection listing** — View all active UDS sockets and their states
- **Statistics** — Snapshot of socket type distribution, states, and top paths
- **Top view** — Live sorted display of per-process UDS traffic
- **Filtering** — Filter by PID, process name, socket path, or socket type
- **Multiple output formats** — Human-readable, hex dump, or JSON

## Requirements

- Linux kernel >= 5.4 (BTF support required)
- Root privileges or `CAP_BPF` + `CAP_PERFMON` capabilities
- Rust nightly toolchain (for eBPF compilation)
- [`bpf-linker`](https://github.com/aya-rs/bpf-linker) installed

## Installation

### From source

```bash
# Install bpf-linker (required for eBPF compilation)
cargo install bpf-linker

# Clone and build
git clone https://github.com/pangbit/udsdump.git
cd udsdump
cargo build --release

# Binary is at target/release/udsdump
sudo ./target/release/udsdump --help
```

## Usage

### Capture UDS traffic

```bash
# Capture all UDS traffic
sudo udsdump capture

# Filter by socket path
sudo udsdump capture --path /var/run/docker.sock

# Filter by process name, output as JSON
sudo udsdump capture --comm nginx --json

# Capture 100 packets and stop
sudo udsdump capture --count 100

# Show hex dump of payload
sudo udsdump capture --hex
```

Example output:
```
14:23:01.123456 nginx(1234) → [/var/run/php-fpm.sock] STREAM 128B
14:23:01.124789 php-fpm(5678) ← [/var/run/php-fpm.sock] STREAM 256B
```

### List UDS connections

```bash
# List all UDS sockets
udsdump list

# Resolve inode to process info
udsdump list --resolve

# Filter by socket type
udsdump list --type stream
```

Example output:
```
TYPE     STATE        INODE      PATH
STREAM   CONNECTED    12345      /run/dbus/system_bus_socket
STREAM   LISTEN       12346      /var/run/docker.sock
DGRAM    CONNECTED    12348      /run/systemd/notify
```

### Show statistics

```bash
# One-time snapshot
sudo udsdump stats

# Refresh every 5 seconds
sudo udsdump stats --interval 5

# JSON output
sudo udsdump stats --json
```

Example output:
```
=== UDS Statistics (snapshot) ===
Total sockets:     142
  STREAM:          98     (69%)
  DGRAM:           38     (27%)
  SEQPACKET:       6      (4%)

By state:
  LISTEN:          23
  CONNECTED:       89
  UNCONNECTED:     30

Top socket paths:
  COUNT  PATH
  21     /run/systemd/journal/stdout
  12     /run/dbus/system_bus_socket
```

### Real-time top view

```bash
# Default: sort by bytes
sudo udsdump top

# Sort by message count
sudo udsdump top --sort msgs

# Refresh every 2 seconds
sudo udsdump top --interval 2
```

Example output:
```
PID      COMM               BYTES_SENT   BYTES_RECV    MSGS_TX    MSGS_RX
----------------------------------------------------------------------
1234     nginx                  12.3 MB      8.7 MB      45230      38901
5678     php-fpm                 8.7 MB     12.3 MB      38901      45230
890      dockerd                 2.1 MB      1.8 MB      12034      11982
```

## Architecture

```
udsdump/
├── udsdump/                  # Userspace CLI (clap + tokio)
├── udsdump-ebpf/             # eBPF kprobe probes (no_std)
└── udsdump-common/           # Shared types between kernel and userspace
```

The tool works by attaching kprobes to four kernel functions:
- `unix_stream_sendmsg` / `unix_stream_recvmsg` — STREAM sockets
- `unix_dgram_sendmsg` / `unix_dgram_recvmsg` — DGRAM sockets

Events are transmitted from kernel to userspace via `PerfEventArray`, with per-CPU reader tasks for efficient multi-core event collection.

## Known Limitations

- Kernel struct offsets are currently hardcoded for kernel 6.8. Cross-kernel portability via BTF/CO-RE is planned.
- Payload data capture is not yet implemented (metadata only: process, path, direction, size).
- SEQPACKET socket probes are not yet implemented.

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
