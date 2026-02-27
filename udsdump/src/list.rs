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

        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = Path::new("/proc").join(&*name_str).join("fd");
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
            if let Some(inode_str) = link_str.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                if let Ok(inode) = inode_str.parse::<u64>() {
                    if inode_set.contains(&inode) {
                        let comm_path = Path::new("/proc").join(&*name_str).join("comm");
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

    let inodes: Vec<u64> = entries.iter().map(|e| e.inode).collect();
    let proc_map = if args.resolve {
        resolve_inodes_to_processes(&inodes)
    } else {
        HashMap::new()
    };

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
                (proc_info.pid.to_string(), proc_info.comm.clone())
            } else {
                ("-".to_string(), "-".to_string())
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
