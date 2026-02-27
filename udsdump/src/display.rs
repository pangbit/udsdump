use udsdump_common::UdsEvent;

/// Format a UdsEvent as a human-readable one-line summary.
pub fn format_event_header(event: &UdsEvent) -> String {
    let timestamp = format_timestamp(event.timestamp_ns);
    let comm = core_str(&event.comm);
    let direction = if event.direction == 0 { "\u{2192}" } else { "\u{2190}" };
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

/// Format payload as hex dump (similar to xxd or tcpdump -X).
pub fn format_payload_hex(data: &[u8], max_bytes: usize) -> String {
    let len = data.len().min(max_bytes);
    let mut out = String::new();

    for (i, chunk) in data[..len].chunks(16).enumerate() {
        let offset = i * 16;
        out.push_str(&format!("  {:04x}  ", offset));

        for (j, &b) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x} ", b));
            if j == 7 {
                out.push(' ');
            }
        }
        let pad = 16 - chunk.len();
        for j in 0..pad {
            out.push_str("   ");
            if chunk.len() + j == 7 {
                out.push(' ');
            }
        }

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
