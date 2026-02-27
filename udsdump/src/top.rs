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

    // No filter for top — capture everything
    let config = FilterConfig {
        target_pid: 0,
        target_path: [0u8; MAX_PATH_LEN],
        target_path_len: 0,
    };
    let mut filter_map: Array<_, FilterConfig> =
        Array::try_from(ebpf.map_mut("FILTER").unwrap())?;
    filter_map.set(0, config, 0)?;

    // Attach kprobes
    attach_probe(&mut ebpf, "udsdump_stream_sendmsg", "unix_stream_sendmsg")?;
    attach_probe(&mut ebpf, "udsdump_stream_recvmsg", "unix_stream_recvmsg")?;
    attach_probe(&mut ebpf, "udsdump_dgram_sendmsg", "unix_dgram_sendmsg")?;
    attach_probe(&mut ebpf, "udsdump_dgram_recvmsg", "unix_dgram_recvmsg")?;

    // Open perf event buffers
    let mut perf_array = PerfEventArray::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let cpus = online_cpus().map_err(|(_, e)| e)?;
    let mut async_fds = Vec::new();

    for cpu_id in cpus {
        let buf = perf_array.open(cpu_id, None)?;
        let async_fd = AsyncFd::with_interest(buf, Interest::READABLE)?;
        async_fds.push(async_fd);
    }

    // Handle Ctrl+C
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

fn attach_probe(ebpf: &mut Ebpf, prog_name: &str, fn_name: &str) -> anyhow::Result<()> {
    let program: &mut KProbe = ebpf.program_mut(prog_name).unwrap().try_into()?;
    program.load()?;
    program.attach(fn_name, 0)?;
    debug!("attached kprobe: {} -> {}", prog_name, fn_name);
    Ok(())
}

fn update_stats(stats: &mut HashMap<u32, ProcessStats>, event: &UdsEvent) {
    let entry = stats.entry(event.pid).or_insert_with(|| {
        let comm = {
            let end = event
                .comm
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(event.comm.len());
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
    // Clear screen and move cursor to top-left
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
