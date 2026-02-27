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
