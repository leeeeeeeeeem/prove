//! prove-consent: the headless evdev helper (SPEC 8.3).
//!
//! Spawned by `provd` for one prompt, as uid `prove-consent` with group `input`, with a
//! socketpair on fd 0. It is the only PROVE component that reads evdev, it never talks to a
//! display server, and it holds no BPF capability: device records are obtained by asking
//! `provd` over the socketpair. Every abnormal path reports (or implies) a non-approval.

mod evdev;

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, ErrorKind, Read},
    os::{
        fd::AsFd,
        unix::{fs::OpenOptionsExt, net::UnixStream},
    },
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use nix::{
    errno::Errno,
    fcntl::OFlag,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use prove_common::{
    class,
    user::{
        proto::{
            DeviceInfo, DeviceReply, GrabReply, HelperMsg, HelperParams, PromptMode, Verdict,
            parse_line, write_line,
        },
        sysfs::input_number_of_evdev,
    },
};
use serde::de::DeserializeOwned;

struct Provd {
    tx: UnixStream,
    rx: BufReader<UnixStream>,
}

impl Provd {
    fn ask<T: DeserializeOwned>(&mut self, msg: &HelperMsg) -> Result<T> {
        write_line(&mut self.tx, msg)?;
        let mut line = String::new();
        if self.rx.read_line(&mut line)? == 0 {
            bail!("provd closed the connection");
        }
        Ok(parse_line(&line)?)
    }

    fn device(&mut self, n: u64) -> Result<Option<DeviceInfo>> {
        Ok(self.ask::<DeviceReply>(&HelperMsg::Device { n })?.record)
    }

    fn done(&mut self, verdict: Verdict, reason: &str, device: Option<u64>) {
        let _ = write_line(
            &mut self.tx,
            &HelperMsg::Done { verdict, reason: reason.to_string(), device },
        );
    }
}

/// An evdev node accepted as a source of approval.
struct Accepted {
    file: File,
    n: u64,
    /// Record as it was when the device was accepted; any change invalidates the device.
    info: DeviceInfo,
}

enum Outcome {
    Approved(u64),
    Denied(String),
    Timeout,
}

fn open_keyboards(key_code: u16) -> Vec<(File, u64)> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/dev/input") else { return out };
    for entry in dir.filter_map(|e| e.ok()) {
        if !entry.file_name().to_string_lossy().starts_with("event") {
            continue;
        }
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_NONBLOCK | OFlag::O_CLOEXEC).bits())
            .open(entry.path())
        else {
            continue;
        };
        // Only devices that can emit the challenge key matter.
        let Ok(bits) = evdev::key_bits(&file) else { continue };
        if !evdev::has_key(&bits, key_code) {
            continue;
        }
        let Ok(n) = input_number_of_evdev(&file) else { continue };
        out.push((file, n));
    }
    out.sort_by_key(|(_, n)| *n);
    out
}

fn run(provd: &mut Provd, params: &HelperParams) -> Result<Outcome> {
    let deadline = Instant::now() + Duration::from_millis(params.timeout_ms);

    // Step 1: candidate devices and their records. Devices without a record are skipped.
    let mut hardware = Vec::new();
    let mut uinput = Vec::new();
    for (file, n) in open_keyboards(params.key_code) {
        match provd.device(n)? {
            Some(info) if info.class == class::HARDWARE => hardware.push(Accepted { file, n, info }),
            Some(info) if info.class == class::UINPUT => uinput.push(Accepted { file, n, info }),
            _ => {}
        }
    }

    // Step 2: grab every hardware keyboard so the compositor does not see the key.
    let mut accepted = Vec::new();
    let mut assistive_exes: Vec<(u32, u64)> = Vec::new();
    for dev in hardware {
        match evdev::grab(&dev.file) {
            Ok(()) => accepted.push(dev),
            Err(Errno::EBUSY) => {
                let holder = provd.ask::<GrabReply>(&HelperMsg::Grab { n: dev.n })?.holder;
                match holder {
                    None => {
                        return Ok(Outcome::Denied(format!(
                            "input{} is grabbed by an unknown holder",
                            dev.n
                        )));
                    }
                    Some(h) if h.assistive && params.mode == PromptMode::Assistive => {
                        assistive_exes.push(h.exe);
                    }
                    Some(_) => {
                        return Ok(Outcome::Denied(format!(
                            "input{} is grabbed by a process this prompt does not accept",
                            dev.n
                        )));
                    }
                }
            }
            // Unplugged between open and grab.
            Err(Errno::ENODEV) => {}
            Err(e) => return Ok(Outcome::Denied(format!("cannot grab input{}: {e}", dev.n))),
        }
    }
    // Assistive mode: the uinput device of the allow-listed tool that holds the grab.
    for dev in uinput {
        if !assistive_exes.contains(&dev.info.creator_exe) {
            continue;
        }
        match evdev::grab(&dev.file) {
            Ok(()) => accepted.push(dev),
            Err(e) => {
                return Ok(Outcome::Denied(format!("cannot grab assistive input{}: {e}", dev.n)));
            }
        }
    }
    if accepted.is_empty() {
        return Ok(Outcome::Denied("no trusted keyboard is available".into()));
    }

    // Step 3: re-validate before reading.
    for dev in &accepted {
        if provd.device(dev.n)? != Some(dev.info) {
            return Ok(Outcome::Denied(format!("record of input{} changed", dev.n)));
        }
    }

    // Step 4: wait for a key-down of exactly the challenge key.
    let mut buf = [0u8; evdev::EVENT_SIZE * 64];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(Outcome::Timeout);
        }
        if accepted.is_empty() {
            return Ok(Outcome::Denied("all trusted keyboards disappeared".into()));
        }
        let remaining = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let ready: Vec<bool> = {
            let mut fds: Vec<PollFd> = accepted
                .iter()
                .map(|d| PollFd::new(d.file.as_fd(), PollFlags::POLLIN))
                .collect();
            match poll(&mut fds, PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX)) {
                Ok(_) | Err(Errno::EINTR) => {}
                Err(e) => return Ok(Outcome::Denied(format!("poll failed: {e}"))),
            }
            fds.iter().map(|f| f.revents().is_some_and(|r| !r.is_empty())).collect()
        };

        let mut gone = Vec::new();
        for (i, dev) in accepted.iter_mut().enumerate() {
            if !ready[i] {
                continue;
            }
            loop {
                let len = match dev.file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(len) => len,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => {
                        gone.push(i); // unplugged or revoked
                        break;
                    }
                };
                for raw in buf[..len].chunks_exact(evdev::EVENT_SIZE) {
                    let ev = evdev::decode(raw);
                    if ev.kind == evdev::EV_KEY && ev.code == params.key_code && ev.value == 1 {
                        // Re-validate at the moment the key arrives.
                        return Ok(if provd.device(dev.n)? == Some(dev.info) {
                            Outcome::Approved(dev.n)
                        } else {
                            Outcome::Denied(format!("record of input{} changed", dev.n))
                        });
                    }
                    // Any other key is ignored.
                }
            }
        }
        for i in gone.into_iter().rev() {
            accepted.remove(i);
        }
    }
    // Step 5 (release grabs) happens when the files are dropped.
}

fn main() -> Result<()> {
    let sock = std::io::stdin().as_fd().try_clone_to_owned().context("fd 0")?;
    let sock = UnixStream::from(sock);
    let mut provd = Provd { tx: sock.try_clone()?, rx: BufReader::new(sock) };

    let mut line = String::new();
    provd.rx.read_line(&mut line)?;
    let params: HelperParams = parse_line(&line).context("reading parameters")?;

    match run(&mut provd, &params) {
        Ok(Outcome::Approved(n)) => provd.done(Verdict::Approved, "challenge key pressed", Some(n)),
        Ok(Outcome::Denied(reason)) => provd.done(Verdict::Denied, &reason, None),
        Ok(Outcome::Timeout) => provd.done(Verdict::Timeout, "no approval before the timeout", None),
        Err(e) => provd.done(Verdict::Error, &format!("{e:#}"), None),
    }
    Ok(())
}
