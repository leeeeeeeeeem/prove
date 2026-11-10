//! Minimal native journald client: structured records over the journal datagram socket.

use std::os::unix::net::UnixDatagram;

use prove_common::user::JOURNAL_ID;

const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

pub struct Journal {
    sock: Option<UnixDatagram>,
}

impl Journal {
    pub fn new() -> Self {
        Journal { sock: UnixDatagram::unbound().ok() }
    }

    /// Send one record. `fields` are (NAME, value) pairs; NAME must be uppercase/underscore.
    /// Also mirrors the message to stderr when journald is unreachable.
    pub fn send(&self, priority: u8, message: &str, fields: &[(&str, String)]) {
        let mut buf = Vec::with_capacity(256);
        let mut put = |k: &str, v: &str| {
            buf.extend_from_slice(k.as_bytes());
            if v.contains('\n') {
                // Binary-safe framing: NAME\n<u64 le length><value>\n
                buf.push(b'\n');
                buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
            } else {
                buf.push(b'=');
            }
            buf.extend_from_slice(v.as_bytes());
            buf.push(b'\n');
        };
        put("MESSAGE", message);
        put("PRIORITY", &priority.to_string());
        put("SYSLOG_IDENTIFIER", JOURNAL_ID);
        for (k, v) in fields {
            put(k, v);
        }
        let sent = self.sock.as_ref().is_some_and(|s| s.send_to(&buf, JOURNAL_SOCKET).is_ok());
        if !sent {
            eprintln!("prove: {message}");
        }
    }

    pub fn info(&self, message: &str) {
        self.send(6, message, &[("PROVE_EVENT", "daemon".to_string())]);
    }

    pub fn warn(&self, message: &str) {
        self.send(4, message, &[("PROVE_EVENT", "daemon".to_string())]);
    }
}
