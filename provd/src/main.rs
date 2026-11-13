//! provd: the PROVE root daemon. See SPEC.md section 8.1.

mod allowlist;
mod audit;
mod bpf;
mod consent;
mod journal;
mod offsets;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    thread,
};

use anyhow::{Context as _, Result, bail};
use prove_common::{
    Creator, DeviceRecord, class, mode,
    user::{CONSENT_SOCK, ETC_DIR, PID_FILE, RUN_DIR, exe, maps, sysfs},
};
use serde::Deserialize;
use signal_hook::{
    consts::{SIGHUP, SIGINT, SIGTERM},
    iterator::Signals,
};

use crate::{allowlist::Lists, journal::Journal};

#[derive(Deserialize, Debug)]
#[serde(default, deny_unknown_fields)]
struct DaemonConfig {
    /// "audit" (default) or "enforce".
    mode: String,
    allow_inject: PathBuf,
    requesters: PathBuf,
    consent_helper: PathBuf,
    consent_timeout_ms: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            mode: "audit".into(),
            allow_inject: Path::new(ETC_DIR).join("allow-inject.toml"),
            requesters: Path::new(ETC_DIR).join("requesters.toml"),
            consent_helper: "/usr/libexec/prove/prove-consent".into(),
            consent_timeout_ms: 30_000,
        }
    }
}

fn load_daemon_config(path: &Path) -> Result<DaemonConfig> {
    match fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DaemonConfig::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn bpf_lsm_active() -> bool {
    fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.trim().split(',').any(|l| l == "bpf"))
        .unwrap_or(false)
}

/// Insert records for devices that were registered before the hooks existed (SPEC 8.1
/// step 3). Existing records are never overwritten.
fn record_preexisting(journal: &Journal) -> Result<()> {
    const BPF_NOEXIST: u64 = 1;
    let mut devices = maps::devices()?;
    for dev in sysfs::list_inputs()? {
        let class = if dev.is_virtual() { class::PREEXISTING } else { class::HARDWARE };
        let rec = DeviceRecord {
            class,
            _pad: 0,
            creator: Creator::UNKNOWN,
            registered_ns: 0,
            inject_count: 0,
        };
        if devices.insert(dev.number, rec, BPF_NOEXIST).is_ok() {
            journal.send(
                6,
                &format!(
                    "input{} existed before PROVE: class={} name={:?}",
                    dev.number,
                    class::name(class),
                    dev.name
                ),
                &[
                    ("PROVE_EVENT", "device-preexisting".to_string()),
                    ("PROVE_CLASS", class::name(class).to_string()),
                    ("PROVE_DEVICE", format!("input{}", dev.number)),
                ],
            );
        }
    }
    Ok(())
}

fn reload_lists(cfg: &DaemonConfig, lists: &RwLock<Lists>, journal: &Journal) -> Result<()> {
    let new = allowlist::load(&cfg.allow_inject, &cfg.requesters, &mut |m| journal.warn(&m));
    allowlist::sync_kernel(&new)?;
    journal.info(&format!(
        "allow-lists loaded: {} tool(s), {} requester(s)",
        new.tools.len(),
        new.requesters.len()
    ));
    *lists.write().unwrap() = new;
    Ok(())
}

fn set_mode(wanted: u32) -> Result<()> {
    let mut cfg = maps::read_config()?;
    cfg.mode = wanted;
    maps::write_config(cfg)
}

fn main() -> Result<()> {
    let mut config_path = Path::new(ETC_DIR).join("provd.toml");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => config_path = args.next().context("--config needs a path")?.into(),
            _ => bail!("usage: provd [--config PATH]"),
        }
    }
    if !nix::unistd::geteuid().is_root() {
        bail!("provd must run as root");
    }

    let journal = Arc::new(Journal::new());
    let cfg = load_daemon_config(&config_path)?;
    let wanted_mode = match cfg.mode.as_str() {
        "audit" => mode::AUDIT,
        "enforce" => mode::ENFORCE,
        other => bail!("{}: unknown mode {other:?}", config_path.display()),
    };

    // 1. Environment.
    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        bail!("kernel BTF (/sys/kernel/btf/vmlinux) is missing");
    }
    let lsm_active = bpf_lsm_active();
    if !lsm_active {
        if wanted_mode == mode::ENFORCE {
            bail!("BPF LSM is not active (add lsm=...,bpf to the kernel command line); refusing to start in enforce mode");
        }
        journal.warn("BPF LSM is not active: provenance is recorded but nothing can be denied");
    }

    // 2. Programs and maps.
    let offsets = offsets::resolve().context("resolving kernel offsets from BTF")?;
    if offsets.hid_device_dev == 0 {
        journal.warn("hid module BTF not found: uhid creators will be unknown");
    }
    let self_exe = exe::exe_id_of_path(Path::new("/proc/self/exe"))?;
    match bpf::ensure_loaded(&offsets, self_exe)? {
        bpf::Loaded::Fresh => journal.info("eBPF programs loaded and pinned"),
        bpf::Loaded::Reused => journal.info("reusing pinned eBPF programs"),
    }

    // 3. Devices that predate the hooks.
    record_preexisting(&journal)?;

    // 4. Allow-lists.
    let lists = Arc::new(RwLock::new(Lists::default()));
    reload_lists(&cfg, &lists, &journal)?;

    // 5. Mode.
    set_mode(wanted_mode)?;
    journal.info(&format!("mode: {}", cfg.mode));

    // 6. Runtime directory, audit reader, consent socket.
    fs::create_dir_all(RUN_DIR)?;
    fs::set_permissions(RUN_DIR, fs::Permissions::from_mode(0o755))?;
    fs::write(PID_FILE, format!("{}\n", std::process::id()))?;

    {
        let (lists, journal) = (lists.clone(), journal.clone());
        thread::Builder::new().name("audit".into()).spawn(move || {
            if let Err(e) = audit::run(lists, journal.clone()) {
                journal.warn(&format!("audit reader stopped: {e:#}"));
            }
        })?;
    }

    {
        let consent = Arc::new(consent::Consent {
            lists: lists.clone(),
            journal: journal.clone(),
            helper: cfg.consent_helper.clone(),
            timeout_ms: cfg.consent_timeout_ms.clamp(1_000, 300_000),
            busy: Mutex::new(()),
        });
        // Without the socket there is no consent, which fails closed; enforcement still runs.
        match consent::Consent::bind() {
            Ok(listener) => {
                thread::Builder::new()
                    .name("consent-listener".into())
                    .spawn(move || consent.serve(listener))?;
            }
            Err(e) => journal.warn(&format!("consent socket unavailable: {e:#}")),
        }
    }
    journal::notify_ready();

    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT])?;
    for sig in signals.forever() {
        match sig {
            SIGHUP => {
                if let Err(e) = reload_lists(&cfg, &lists, &journal) {
                    journal.warn(&format!("reload failed: {e:#}"));
                }
            }
            _ => break,
        }
    }
    // Pinned programs and maps stay: enforcement outlives the daemon.
    let _ = fs::remove_file(PID_FILE);
    let _ = fs::remove_file(CONSENT_SOCK);
    journal.info("provd exiting; pinned enforcement remains active");
    Ok(())
}
