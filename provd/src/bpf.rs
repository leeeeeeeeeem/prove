//! Loading, attaching and pinning the eBPF side.
//!
//! `provd` never keeps the loaded object around: it loads, attaches, pins everything under
//! `/sys/fs/bpf/prove` and drops its handles. From then on the kernel objects live through
//! their pins, and every component (including `provd` itself) reaches the maps through the
//! pins. Enforcement therefore does not depend on `provd` staying alive.

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use anyhow::{Context as _, Result, bail};
use aya::{
    Btf, EbpfLoader,
    programs::{FEntry, FExit, KProbe, Lsm, links::FdLink},
};
use prove_common::{
    ABI_VERSION, Config, ExeId, Offsets, PIN_DIR, mode,
    user::maps::{self, pin_path, pins_present, unload},
};

static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/prove"));

enum Kind {
    FEntry(&'static str),
    FExit(&'static str),
    Lsm(&'static str),
    KProbe(&'static str),
}

/// Program name in the object -> attach point. LSM programs come last so that provenance
/// is being recorded before anything can be denied.
const PROGRAMS: &[(&str, Kind, bool)] = &[
    ("dev_register", Kind::FExit("input_register_device"), true),
    ("dev_unregister", Kind::FEntry("input_unregister_device"), true),
    ("grab", Kind::FExit("input_grab_device"), true),
    ("release", Kind::FEntry("input_release_device"), true),
    // hid.ko may be absent; then there are no HID devices to attribute either.
    ("inject_count", Kind::FEntry("input_inject_event"), true),
    ("hid_alloc", Kind::KProbe("hid_allocate_device"), false),
    ("hid_destroy", Kind::KProbe("hid_destroy_device"), false),
    ("ioctl_guard_native", Kind::Lsm("file_ioctl"), true),
    ("ioctl_guard_compat", Kind::Lsm("file_ioctl_compat"), true),
    ("write_guard", Kind::Lsm("file_permission"), true),
];

pub enum Loaded {
    Reused,
    Fresh,
}

/// Make sure the programs are loaded, attached and pinned. Reuses compatible pins.
pub fn ensure_loaded(offsets: &Offsets, provd_exe: ExeId) -> Result<Loaded> {
    if pins_present() {
        match maps::read_config() {
            Ok(cfg) if cfg.abi == ABI_VERSION => return Ok(Loaded::Reused),
            Ok(cfg) => eprintln!(
                "provd: pinned objects have ABI {} (want {ABI_VERSION}); reloading",
                cfg.abi
            ),
            Err(e) => eprintln!("provd: pinned objects unreadable ({e:#}); reloading"),
        }
        unload()?;
    } else if Path::new(PIN_DIR).exists() {
        // Leftovers of an interrupted load.
        unload()?;
    }

    if let Err(e) = load_fresh(offsets, provd_exe) {
        let _ = unload();
        return Err(e);
    }
    Ok(Loaded::Fresh)
}

fn load_fresh(offsets: &Offsets, provd_exe: ExeId) -> Result<()> {
    fs::create_dir_all(PIN_DIR).with_context(|| format!("creating {PIN_DIR} (is bpffs mounted?)"))?;
    fs::set_permissions(PIN_DIR, fs::Permissions::from_mode(0o700))?;

    let mut ebpf = EbpfLoader::new()
        .override_global("OFFSETS", offsets, true)
        .load(OBJECT)
        .context("loading eBPF object")?;

    // Maps first: the configuration must be in place before any program runs.
    for (name, map) in ebpf.maps() {
        if name.starts_with('.') || name.contains(".rodata") || name.contains(".data") {
            continue;
        }
        map.pin(pin_path(name)).with_context(|| format!("pinning map {name}"))?;
    }
    maps::write_config(Config { mode: mode::AUDIT, abi: ABI_VERSION, provd_exe })?;

    let btf = Btf::from_sys_fs().context("reading kernel BTF")?;
    for (name, kind, required) in PROGRAMS {
        let res = attach_and_pin(&mut ebpf, name, kind, &btf);
        match res {
            Ok(()) => {}
            Err(e) if !required => eprintln!("provd: optional program {name} not attached: {e:#}"),
            Err(e) => return Err(e.context(format!("program {name}"))),
        }
    }
    Ok(())
}

fn attach_and_pin(ebpf: &mut aya::Ebpf, name: &str, kind: &Kind, btf: &Btf) -> Result<()> {
    let Some(prog) = ebpf.program_mut(name) else { bail!("not found in object") };
    let link: FdLink = match kind {
        Kind::FEntry(f) => {
            let p: &mut FEntry = prog.try_into()?;
            p.load(f, btf)?;
            let id = p.attach()?;
            p.take_link(id)?.into()
        }
        Kind::FExit(f) => {
            let p: &mut FExit = prog.try_into()?;
            p.load(f, btf)?;
            let id = p.attach()?;
            p.take_link(id)?.into()
        }
        Kind::Lsm(hook) => {
            let p: &mut Lsm = prog.try_into()?;
            p.load(hook, btf)?;
            let id = p.attach()?;
            p.take_link(id)?.into()
        }
        Kind::KProbe(f) => {
            let p: &mut KProbe = prog.try_into()?;
            p.load()?;
            let id = p.attach(f, 0)?;
            p.take_link(id)?.try_into().map_err(|_| anyhow::anyhow!("kprobe link is not a bpf_link"))?
        }
    };
    link.pin(pin_path(&format!("link_{name}"))).context("pinning link")?;
    ebpf.program_mut(name).unwrap().pin(pin_path(&format!("prog_{name}"))).context("pinning program")?;
    Ok(())
}
