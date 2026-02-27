# udsdump - Linux Unix Domain Socket 抓包与分析工具

## 概述

`udsdump` 是一个 Linux 下的 Unix Domain Socket (UDS) 抓包、连接查看和统计分析工具。通过 eBPF/kprobe 实现零侵入式的实时数据捕获，类似于 tcpdump 之于 TCP/UDP，udsdump 之于 Unix Domain Socket。

## 技术选型

- **语言**: Rust
- **eBPF 框架**: Aya（纯 Rust eBPF，使用 aya-build 构建）
- **抓包机制**: eBPF kprobe 挂载内核函数
- **最低内核版本**: >= 5.4（BTF/CO-RE 支持）
- **交互方式**: CLI 命令行
- **使用场景**: 开发调试 + 生产环境排查

## 子命令设计

```
udsdump capture    # 实时抓包，拦截 UDS 数据传输并显示 payload
udsdump list       # 列出当前系统所有 UDS 连接及其状态
udsdump stats      # 显示 UDS 统计信息（连接数、流量、错误等）
udsdump top        # 按流量/频率排序的实时统计视图
```

## 项目结构

```
udsdump/
├── udsdump/                  # 用户态程序
│   ├── Cargo.toml            # build-dependencies 包含 aya-build
│   ├── build.rs              # 调用 aya_build::build_ebpf()
│   └── src/
│       ├── main.rs           # 入口 + clap CLI 定义
│       ├── capture.rs        # capture 子命令实现
│       ├── list.rs           # list 子命令实现
│       ├── stats.rs          # stats 子命令实现
│       ├── top.rs            # top 子命令实现
│       ├── display.rs        # 输出格式化（hex dump, 表格等）
│       └── filter.rs         # 过滤表达式解析与匹配
├── udsdump-ebpf/             # eBPF 内核探针 (no_std)
│   ├── Cargo.toml            # 依赖 aya-ebpf
│   └── src/
│       └── main.rs           # kprobe 探针定义
├── udsdump-common/           # 内核态与用户态共享类型
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs            # 共享数据结构（事件类型等）
└── Cargo.toml                # workspace
```

## eBPF 探针设计

### 挂载的内核函数

```
kprobe:  unix_stream_sendmsg   → 捕获 STREAM 类型发送
kprobe:  unix_stream_recvmsg   → 捕获 STREAM 类型接收
kprobe:  unix_dgram_sendmsg    → 捕获 DGRAM 类型发送
kprobe:  unix_dgram_recvmsg    → 捕获 DGRAM 类型接收
```

### 共享事件结构

```rust
#[repr(C)]
pub struct UdsEvent {
    pub timestamp_ns: u64,       // 事件时间戳
    pub pid: u32,                // 进程 PID
    pub tid: u32,                // 线程 TID
    pub comm: [u8; 16],          // 进程名
    pub sock_inode: u64,         // socket inode
    pub peer_inode: u64,         // 对端 socket inode
    pub path: [u8; 108],         // socket 路径 (sun_path)
    pub direction: u8,           // 0=send, 1=recv
    pub sock_type: u8,           // STREAM / DGRAM / SEQPACKET
    pub data_len: u32,           // 数据总长度
    pub captured_len: u32,       // 实际捕获的长度
    pub data: [u8; 256],         // payload 前 256 字节
}
```

### 数据传输路径

```
内核探针 → PerfEventArray/RingBuffer → 用户态 → 过滤 → 格式化输出
```

- 使用 PerfEventArray（5.4 兼容）或 RingBuffer（>= 5.8，性能更好）
- 用户态通过异步 poll（tokio）读取事件

### 过滤机制

分两层：
1. **内核态过滤**（eBPF 中）：按 PID、socket 路径前缀过滤，减少无关事件传输
2. **用户态过滤**（Rust 中）：更复杂的条件，如正则匹配、payload 内容搜索

## 子命令详细设计

### `udsdump capture` — 实时抓包

```bash
udsdump capture [OPTIONS]

OPTIONS:
  --path <SOCKET_PATH>    按 socket 路径过滤（支持前缀匹配）
  --pid <PID>             按进程 PID 过滤
  --comm <NAME>           按进程名过滤
  --type <stream|dgram>   按 socket 类型过滤
  --hex                   以 hex dump 格式显示 payload
  --ascii                 以 ASCII 格式显示 payload（默认）
  --max-bytes <N>         每个包最多显示 N 字节 payload（默认 256）
  --count <N>             捕获 N 个包后退出
  --json                  以 JSON 格式输出（便于管道处理）
```

输出格式：
```
14:23:01.123456 nginx(1234) → php-fpm(5678) [/var/run/php-fpm.sock] STREAM 128B
  GET /api/health HTTP/1.1\r\nHost: localhost\r\n...

14:23:01.124789 php-fpm(5678) → nginx(1234) [/var/run/php-fpm.sock] STREAM 256B
  HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n...
```

### `udsdump list` — 连接状态查看

```bash
udsdump list [OPTIONS]

OPTIONS:
  --path <SOCKET_PATH>    按路径过滤
  --pid <PID>             按进程过滤
  --state <STATE>         按状态过滤（LISTEN/CONNECTED/...）
  --type <stream|dgram>   按类型过滤
  --resolve               解析 inode 到进程信息
```

输出格式：
```
TYPE    STATE       INODE    PID    COMM        PATH                      PEER
STREAM  LISTEN      12345    1234   nginx       /var/run/nginx.sock       -
STREAM  CONNECTED   12346    1234   nginx       /var/run/nginx.sock       php-fpm(5678)
DGRAM   UNCONNECTED 12348    890    syslog      /dev/log                  -
```

数据来源：解析 `/proc/net/unix` + `/proc/*/fd` 关联进程信息。

### `udsdump stats` — 统计信息

```bash
udsdump stats [OPTIONS]

OPTIONS:
  --path <SOCKET_PATH>    统计指定 socket 的信息
  --pid <PID>             统计指定进程的信息
  --interval <SECS>       每 N 秒刷新一次（默认不刷新，单次快照）
  --json                  JSON 格式输出
```

输出格式：
```
=== UDS Statistics (snapshot) ===
Total sockets:     142
  STREAM:          98  (69%)
  DGRAM:           38  (27%)
  SEQPACKET:       6   (4%)

By state:
  LISTEN:          23
  CONNECTED:       89
  UNCONNECTED:     30

Top talkers (since capture start):
  PID    COMM         BYTES_SENT    BYTES_RECV    MSGS
  1234   nginx        12.3 MB       8.7 MB        45230
  5678   php-fpm      8.7 MB        12.3 MB       45230
```

### `udsdump top` — 实时排序视图

```bash
udsdump top [OPTIONS]

OPTIONS:
  --sort <field>          排序字段：bytes/msgs/rate（默认 bytes）
  --interval <SECS>       刷新间隔（默认 1 秒）
```

每 N 秒刷新的表格，按流量/消息数排序。

## 关键依赖

| crate | 用途 |
|-------|------|
| `aya` | eBPF 用户态加载/管理 |
| `aya-ebpf` | eBPF 内核态程序编写（no_std） |
| `aya-build` | build.rs 中自动编译 eBPF 程序 |
| `aya-log` / `aya-log-ebpf` | eBPF 探针中的日志 |
| `cargo_metadata` | build.rs 中获取包信息 |
| `clap` | CLI 参数解析 |
| `tokio` | 异步运行时（读取 perf events） |
| `nix` | Linux 系统调用封装 |
| `libc` | 低层类型定义 |

## 构建方式

使用 `aya-build` 在 `build.rs` 中自动编译 eBPF 程序：

```bash
cargo build --release    # 自动编译 eBPF + 用户态
```

eBPF 编译目标：`bpfel-unknown-none`
最终产物：单个二进制文件

## 权限要求

- `capture` / `stats` / `top`：需要 `CAP_SYS_ADMIN` 或 `CAP_BPF` + `CAP_PERFMON`
- `list`：只需读取 `/proc`，无需特殊权限

## 错误处理

- 内核版本不支持时：给出明确错误提示和最低版本要求
- 权限不足时：提示所需的 capability
- eBPF 验证失败时：输出 verifier log 辅助调试
