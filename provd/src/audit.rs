//! Ring-buffer reader: every kernel `AuditEvent` becomes a structured journald record.

use std::{
    collections::HashMap,
    os::fd::AsFd,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use anyhow::Result;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use prove_common::{
    AuditEvent, ExeId, NO_DEVICE, class, event,
    user::{comm_str, exe, from_bytes, maps, sysfs},
    verdict,
};

use crate::{allowlist::Lists, journal::Journal};

/// Denied writes arrive once per `write()`; log at most one per process per interval.
const WRITE_LOG_INTERVAL: Duration = Duration::from_secs(1);

fn describe_exe(lists: &RwLock<Lists>, id: &ExeId, tgid: u32) -> String {
    if id.is_unknown() {
        return "-".into();
    }
    if let Some(v) = lists.read().unwrap().describe(id) {
        return format!("{} sha256:{}", v.path.display(), v.sha256);
    }
    // Best effort: the process may be gone or the pid reused, so only trust a matching id.
    match exe::exe_of_pid(tgid) {
        Ok((live, path)) if live == *id => path,
        _ => exe::fmt_exe_id(id),
    }
}

pub fn run(lists: Arc<RwLock<Lists>>, journal: Arc<Journal>) -> Result<()> {
    let mut ring = maps::events()?;
    let mut last_write_log: HashMap<u32, (Instant, u64)> = HashMap::new();

    loop {
        while let Some(item) = ring.next() {
            let Some(ev) = from_bytes::<AuditEvent>(&item) else { continue };
            let a = &ev.actor;

            let mut suppressed = 0;
            if ev.kind == event::DENIED_WRITE {
                let now = Instant::now();
                let entry = last_write_log.entry(a.tgid).or_insert((now - WRITE_LOG_INTERVAL, 0));
                if now.duration_since(entry.0) < WRITE_LOG_INTERVAL {
                    entry.1 += 1;
                    continue;
                }
                suppressed = entry.1;
                *entry = (now, 0);
                if last_write_log.len() > 4096 {
                    last_write_log.clear();
                }
            }

            let exe = describe_exe(&lists, &a.exe, a.tgid);
            let comm = comm_str(&a.comm);
            let device = if ev.device == NO_DEVICE {
                match ev.rdev >> 20 {
                    10 if ev.rdev & 0xfffff == 223 => "/dev/uinput".to_string(),
                    10 if ev.rdev & 0xfffff == 239 => "/dev/uhid".to_string(),
                    _ => format!("char {}:{}", ev.rdev >> 20, ev.rdev & 0xfffff),
                }
            } else {
                format!("input{}", ev.device)
            };

            let (priority, message) = match ev.kind {
                event::DEVICE_REGISTERED => (
                    6,
                    format!(
                        "{device} registered: class={} name={:?} creator pid={} uid={} comm={comm} exe={exe}",
                        class::name(ev.class),
                        sysfs::input_name(ev.device),
                        a.tgid,
                        a.uid
                    ),
                ),
                event::DEVICE_UNREGISTERED => {
                    (6, format!("{device} unregistered: class={}", class::name(ev.class)))
                }
                event::DENIED_CREATE | event::DENIED_WRITE => {
                    let what = if ev.kind == event::DENIED_CREATE {
                        "device creation"
                    } else {
                        "write"
                    };
                    let how = if ev.verdict == verdict::DENIED { "denied" } else { "would deny" };
                    let more = if suppressed > 0 {
                        format!(" ({suppressed} similar suppressed)")
                    } else {
                        String::new()
                    };
                    (
                        if ev.verdict == verdict::DENIED { 4 } else { 5 },
                        format!(
                            "{how} {what} on {device}: pid={} uid={} comm={comm} exe={exe}{more}",
                            a.tgid, a.uid
                        ),
                    )
                }
                _ => (5, format!("unknown event kind {}", ev.kind)),
            };

            journal.send(
                priority,
                &message,
                &[
                    ("PROVE_EVENT", event::name(ev.kind).to_string()),
                    ("PROVE_CLASS", class::name(ev.class).to_string()),
                    ("PROVE_PID", a.tgid.to_string()),
                    ("PROVE_UID", a.uid.to_string()),
                    ("PROVE_COMM", comm),
                    ("PROVE_EXE", exe),
                    ("PROVE_EXE_ID", exe::fmt_exe_id(&a.exe)),
                    ("PROVE_CGROUP", a.cgroup_id.to_string()),
                    ("PROVE_DEVICE", device),
                    ("PROVE_VERDICT", verdict::name(ev.verdict).to_string()),
                    ("PROVE_KTIME_NS", ev.ts_ns.to_string()),
                ],
            );
        }

        let mut fds = [PollFd::new(ring.as_fd(), PollFlags::POLLIN)];
        let _ = poll(&mut fds, PollTimeout::from(1000u16));
    }
}
