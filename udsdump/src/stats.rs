use std::collections::HashMap;
use std::fs;
use std::thread;
use std::time::Duration;

use crate::StatsArgs;

struct TypeStats {
    stream: u32,
    dgram: u32,
    seqpacket: u32,
}

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

        if let Some(ref filter_path) = args.path {
            if !path.contains(filter_path.as_str()) {
                continue;
            }
        }

        total += 1;

        match fields[4] {
            "0001" => type_stats.stream += 1,
            "0002" => type_stats.dgram += 1,
            "0005" => type_stats.seqpacket += 1,
            _ => {}
        }

        match fields[5] {
            "01" => state_stats.unconnected += 1,
            "02" => state_stats.connecting += 1,
            "03" => state_stats.connected += 1,
            "04" => state_stats.disconnecting += 1,
            "05" => state_stats.listen += 1,
            _ => {}
        }

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
