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

    let mut out_bufs: Vec<BytesMut> = (0..16)
        .map(|_| BytesMut::with_capacity(core::mem::size_of::<UdsEvent>() + 64))
        .collect();

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
