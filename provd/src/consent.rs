//! The consent contract (SPEC 8.2): authenticated requesters ask for a prompt, and only a
//! key press on a trusted device approves it. Every failure path ends in a non-approval.

use std::{
    io::{BufRead, BufReader, ErrorKind, Read},
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, RwLock},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, anyhow, bail};
use nix::{
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::socket::{getsockopt, sockopt::PeerPidfd},
    unistd::{Group, User},
};
use prove_common::{
    ExeId, allow, class,
    user::{
        CONSENT_SOCK, exe, maps,
        proto::{
            CHALLENGE_KEYS, ChallengeKey, ClientMsg, DeviceInfo, DeviceReply, GrabReply,
            HelperMsg, HelperParams, HolderInfo, MAX_ACTION_LEN, PromptMode, ServerMsg, Verdict,
            parse_line, read_msg, sha256_hex, valid_nonce, write_line, write_msg,
        },
    },
};

use crate::{allowlist::Lists, journal::Journal};

/// How long a requester may take to send its request after connecting.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Extra time the helper gets beyond the prompt timeout before it is killed.
const HELPER_GRACE: Duration = Duration::from_secs(3);
const HELPER_USER: &str = "prove-consent";
const HELPER_GROUP: &str = "input";

pub struct Consent {
    pub lists: Arc<RwLock<Lists>>,
    pub journal: Arc<Journal>,
    pub helper: PathBuf,
    pub timeout_ms: u64,
    /// One prompt at a time, system-wide.
    pub busy: Mutex<()>,
}

struct Peer {
    pidfd: OwnedFd,
    pid: u32,
    exe: ExeId,
    path: String,
}

fn pid_of_pidfd(pidfd: &OwnedFd) -> Result<u32> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?;
    let pid: i64 = info
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .ok_or_else(|| anyhow!("pidfd has no Pid field"))?
        .trim()
        .parse()?;
    if pid <= 0 {
        bail!("peer has exited");
    }
    Ok(pid as u32)
}

/// A pidfd becomes readable when its process exits.
fn alive(pidfd: &OwnedFd) -> bool {
    let mut fds = [PollFd::new(pidfd.as_fd(), PollFlags::POLLIN)];
    matches!(poll(&mut fds, PollTimeout::ZERO), Ok(0))
}

/// Identify the peer by pidfd. `SO_PEERCRED` would not do: the attacker shares the uid.
fn identify(stream: &UnixStream) -> Result<Peer> {
    let pidfd = getsockopt(stream, PeerPidfd).context("SO_PEERPIDFD")?;
    let pid = pid_of_pidfd(&pidfd)?;
    let (exe, path) = exe::exe_of_pid(pid)?;
    // The pid was not recycled while /proc was read if the process is still alive now.
    if !alive(&pidfd) {
        bail!("peer exited during identification");
    }
    Ok(Peer { pidfd, pid, exe, path })
}

fn pick_key() -> Result<&'static ChallengeKey> {
    let n = CHALLENGE_KEYS.len();
    let limit = (256 / n) * n; // rejection sampling keeps the draw uniform
    loop {
        let mut b = [0u8; 1];
        getrandom::fill(&mut b).map_err(|e| anyhow!("CSPRNG failure: {e}"))?;
        if (b[0] as usize) < limit {
            return Ok(&CHALLENGE_KEYS[b[0] as usize % n]);
        }
    }
}

impl Consent {
    pub fn serve(self: Arc<Self>) -> Result<()> {
        let _ = std::fs::remove_file(CONSENT_SOCK);
        let listener = UnixListener::bind(CONSENT_SOCK).context("binding consent socket")?;
        // Authentication is by peer identity, not by file permission.
        std::fs::set_permissions(CONSENT_SOCK, std::fs::Permissions::from_mode(0o666))?;
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let this = self.clone();
            let _ = thread::Builder::new().name("consent".into()).spawn(move || this.handle(stream));
        }
        Ok(())
    }

    fn log(&self, priority: u8, message: &str, verdict: &str, peer: Option<&Peer>) {
        let mut fields = vec![
            ("PROVE_EVENT", "consent".to_string()),
            ("PROVE_VERDICT", verdict.to_string()),
        ];
        if let Some(p) = peer {
            fields.push(("PROVE_PID", p.pid.to_string()));
            fields.push(("PROVE_EXE", p.path.clone()));
            fields.push(("PROVE_EXE_ID", exe::fmt_exe_id(&p.exe)));
        }
        self.journal.send(priority, message, &fields);
    }

    fn handle(&self, mut stream: UnixStream) {
        let reject = |stream: &mut UnixStream, nonce: &str, action: &str, reason: &str| {
            let _ = write_msg(
                stream,
                &ServerMsg::Result {
                    nonce: nonce.to_string(),
                    action_sha256: sha256_hex(action.as_bytes()),
                    verdict: Verdict::Error,
                    reason: reason.to_string(),
                },
            );
        };

        let peer = match identify(&stream) {
            Ok(p) => p,
            Err(e) => {
                self.log(4, &format!("consent: peer could not be identified: {e:#}"), "error", None);
                reject(&mut stream, "", "", "peer could not be identified");
                return;
            }
        };
        let requester = self.lists.read().unwrap().requesters.get(&peer.exe).map(|v| v.name.clone());
        let Some(requester) = requester else {
            self.log(
                4,
                &format!("consent: rejected non-listed requester pid={} exe={}", peer.pid, peer.path),
                "error",
                Some(&peer),
            );
            reject(&mut stream, "", "", "requester is not authorised");
            return;
        };

        let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
        let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
        let (nonce, action, mode) = match read_msg::<_, ClientMsg>(&mut stream) {
            Ok(ClientMsg::Request { nonce, action, mode }) => (nonce, action, mode),
            Err(e) => {
                self.log(4, &format!("consent: bad request from {requester}: {e}"), "error", Some(&peer));
                reject(&mut stream, "", "", "malformed request");
                return;
            }
        };
        if !valid_nonce(&nonce) || action.is_empty() || action.len() > MAX_ACTION_LEN {
            reject(&mut stream, "", "", "invalid nonce or action");
            return;
        }

        let Ok(_prompt) = self.busy.try_lock() else {
            self.log(5, &format!("consent: {requester} refused, another prompt is active"), "error", Some(&peer));
            reject(&mut stream, &nonce, &action, "busy");
            return;
        };

        let (verdict, reason) = match self.prompt(&mut stream, mode) {
            Ok(outcome) => outcome,
            Err(e) => (Verdict::Error, format!("{e:#}")),
        };

        let msg = format!(
            "consent: {} for {requester} (pid {}), mode={mode:?}, action={action:?}: {reason}",
            verdict.as_str(),
            peer.pid
        );
        self.log(if verdict == Verdict::Approved { 5 } else { 4 }, &msg, verdict.as_str(), Some(&peer));

        // The result goes only to the process that asked, and only if it is still there.
        if !alive(&peer.pidfd) {
            return;
        }
        let _ = write_msg(
            &mut stream,
            &ServerMsg::Result {
                nonce,
                action_sha256: sha256_hex(action.as_bytes()),
                verdict,
                reason,
            },
        );
    }

    fn spawn_helper(&self, sock: UnixStream) -> Result<Child> {
        let md = std::fs::metadata(&self.helper)
            .with_context(|| format!("consent helper {}", self.helper.display()))?;
        {
            use std::os::unix::fs::MetadataExt;
            if md.uid() != 0 || md.mode() & 0o022 != 0 {
                bail!("consent helper {} is not root-owned and read-only", self.helper.display());
            }
        }
        let user = User::from_name(HELPER_USER)?.ok_or_else(|| anyhow!("user {HELPER_USER} missing"))?;
        let group =
            Group::from_name(HELPER_GROUP)?.ok_or_else(|| anyhow!("group {HELPER_GROUP} missing"))?;
        // With uid set, std drops all supplementary groups; `input` becomes the only group.
        Command::new(&self.helper)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::from(OwnedFd::from(sock)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .uid(user.uid.as_raw())
            .gid(group.gid.as_raw())
            .spawn()
            .context("spawning consent helper")
    }

    /// Run one prompt. Returns the verdict and a human-readable reason.
    fn prompt(&self, requester: &mut UnixStream, mode: PromptMode) -> Result<(Verdict, String)> {
        let key = pick_key()?;
        let (ours, theirs) = UnixStream::pair()?;
        let mut child = self.spawn_helper(theirs)?;
        let outcome = self.drive_helper(requester, ours, key, mode);
        let _ = child.kill();
        let _ = child.wait();
        outcome
    }

    fn drive_helper(
        &self,
        requester: &mut UnixStream,
        mut helper: UnixStream,
        key: &ChallengeKey,
        mode: PromptMode,
    ) -> Result<(Verdict, String)> {
        let devices = maps::devices()?;
        let grabs = maps::grabs()?;
        let info = |n: u64| -> Option<DeviceInfo> {
            devices.get(&n, 0).ok().map(|r| DeviceInfo {
                class: r.class,
                registered_ns: r.registered_ns,
                inject_count: r.inject_count,
                creator_exe: (r.creator.exe.dev, r.creator.exe.ino),
            })
        };
        let assistive_exe = |id: &ExeId| -> bool {
            self.lists.read().unwrap().tools.get(id).is_some_and(|v| v.flags & allow::ASSISTIVE != 0)
        };

        write_line(
            &mut helper,
            &HelperParams { key_code: key.code, timeout_ms: self.timeout_ms, mode },
        )?;
        write_msg(
            requester,
            &ServerMsg::Challenge { key: key.name.to_string(), timeout_ms: self.timeout_ms },
        )?;

        let deadline = Instant::now() + Duration::from_millis(self.timeout_ms) + HELPER_GRACE;
        helper.set_read_timeout(Some(Duration::from_millis(200)))?;
        requester.set_nonblocking(true)?;
        let mut reader = BufReader::new(helper.try_clone()?);
        let mut line = String::new();

        let result = loop {
            if Instant::now() >= deadline {
                break (Verdict::Timeout, "helper did not answer in time".to_string());
            }
            // A requester that hangs up (or talks out of turn) cancels its prompt.
            let mut probe = [0u8; 1];
            match requester.read(&mut probe) {
                Ok(0) => break (Verdict::Error, "requester disconnected".to_string()),
                Ok(_) => break (Verdict::Error, "unexpected data from requester".to_string()),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(_) => break (Verdict::Error, "requester connection failed".to_string()),
            }

            match reader.read_line(&mut line) {
                Ok(0) => break (Verdict::Error, "consent helper exited without a verdict".to_string()),
                Ok(_) if line.ends_with('\n') => {}
                Ok(_) => continue,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
                Err(e) => break (Verdict::Error, format!("consent helper: {e}")),
            }
            let msg: HelperMsg = match parse_line(&line) {
                Ok(m) => m,
                Err(_) => break (Verdict::Error, "consent helper sent garbage".to_string()),
            };
            line.clear();

            match msg {
                HelperMsg::Device { n } => write_line(&mut helper, &DeviceReply { record: info(n) })?,
                HelperMsg::Grab { n } => {
                    let holder = grabs.get(&n, 0).ok().map(|g| HolderInfo {
                        exe: (g.holder.exe.dev, g.holder.exe.ino),
                        assistive: assistive_exe(&g.holder.exe),
                    });
                    write_line(&mut helper, &GrabReply { holder })?;
                }
                HelperMsg::Done { verdict: Verdict::Approved, device, .. } => {
                    // Never take the helper's word alone: the approving device must still
                    // be trusted according to the kernel records.
                    let trusted = device.and_then(|n| devices.get(&n, 0).ok()).is_some_and(|r| {
                        r.class == class::HARDWARE
                            || (mode == PromptMode::Assistive
                                && r.class == class::UINPUT
                                && assistive_exe(&r.creator.exe))
                    });
                    break if trusted {
                        let n = device.unwrap_or_default();
                        (Verdict::Approved, format!("{} pressed on input{n}", key.name))
                    } else {
                        (Verdict::Denied, "approving device failed validation".to_string())
                    };
                }
                HelperMsg::Done { verdict, reason, .. } => break (verdict, reason),
            }
        };
        requester.set_nonblocking(false)?;
        Ok(result)
    }
}
