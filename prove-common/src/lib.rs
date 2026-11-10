//! Types shared between the eBPF programs and userspace.
//!
//! Everything in the top level of this crate is `no_std`, `#[repr(C)]` and free of implicit
//! padding, because the same bytes are written by the kernel side and read by userspace.
//! The `user` feature adds std-only helpers (pinned map access, executable identity, the
//! consent wire protocol).
#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(feature = "user")]
pub mod user;

/// Bumped whenever a map layout or program set changes. `provd` refuses to reuse pins
/// whose `Config::abi` differs.
pub const ABI_VERSION: u32 = 1;

/// Directory in bpffs holding every pinned program, link and map.
pub const PIN_DIR: &str = "/sys/fs/bpf/prove";

/// Kernel `dev_t` encoding: `major << 20 | minor`.
pub const fn kdev(major: u32, minor: u32) -> u32 {
    (major << 20) | minor
}
pub const MISC_MAJOR: u32 = 10;
pub const UINPUT_RDEV: u32 = kdev(MISC_MAJOR, 223);
pub const UHID_RDEV: u32 = kdev(MISC_MAJOR, 239);
pub const INPUT_MAJOR: u32 = 13;

/// `_IO('U', 1)`; identical for native and compat callers (SPEC F5).
pub const UI_DEV_CREATE: u32 = 0x5501;
pub const MAY_WRITE: u32 = 0x2;
pub const S_IFMT: u32 = 0o170000;
pub const S_IFCHR: u32 = 0o020000;
pub const EPERM: i32 = 1;

/// Identity of an executable: inode number plus the kernel-encoded `s_dev` of its superblock.
/// The all-zero value means "unknown" (kernel thread, or the read failed).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct ExeId {
    pub ino: u64,
    pub dev: u32,
    pub _pad: u32,
}

impl ExeId {
    pub const UNKNOWN: ExeId = ExeId { ino: 0, dev: 0, _pad: 0 };
    pub const fn new(dev: u32, ino: u64) -> Self {
        ExeId { ino, dev, _pad: 0 }
    }
    pub fn is_unknown(&self) -> bool {
        self.ino == 0 && self.dev == 0
    }
}

/// The process responsible for a device, a grab or a denied action.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Creator {
    pub tgid: u32,
    pub uid: u32,
    /// Disambiguates pid reuse.
    pub start_boottime_ns: u64,
    pub exe: ExeId,
    pub cgroup_id: u64,
    /// Audit only, never used for decisions.
    pub comm: [u8; 16],
}

impl Creator {
    pub const UNKNOWN: Creator = Creator {
        tgid: 0,
        uid: 0,
        start_boottime_ns: 0,
        exe: ExeId::UNKNOWN,
        cgroup_id: 0,
        comm: [0; 16],
    };
    pub fn is_unknown(&self) -> bool {
        self.tgid == 0 && self.exe.is_unknown()
    }
}

/// Device classes. Stored as `u32` in records so that any bit pattern is a valid value.
pub mod class {
    pub const HARDWARE: u32 = 0;
    pub const UINPUT: u32 = 1;
    pub const UHID: u32 = 2;
    /// Parentless device that was not created through a `UI_DEV_CREATE` we observed.
    pub const UNKNOWN_VIRTUAL: u32 = 3;
    /// Virtual device that existed before the hooks were attached.
    pub const PREEXISTING: u32 = 4;

    pub fn name(c: u32) -> &'static str {
        match c {
            HARDWARE => "hardware",
            UINPUT => "uinput",
            UHID => "uhid",
            UNKNOWN_VIRTUAL => "unknown-virtual",
            PREEXISTING => "preexisting",
            _ => "invalid",
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DeviceRecord {
    pub class: u32,
    pub _pad: u32,
    pub creator: Creator,
    /// `bpf_ktime_get_boot_ns()` at registration; identifies this incarnation of `inputN`.
    pub registered_ns: u64,
    /// Events injected through evdev writes (stretch S2).
    pub inject_count: u64,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct GrabRecord {
    pub holder: Creator,
    pub grabbed_ns: u64,
}

pub mod allow {
    /// May create uinput devices and write to uinput fds.
    pub const INJECT: u32 = 1 << 0;
    /// Its uinput device may satisfy an assistive-mode prompt.
    pub const ASSISTIVE: u32 = 1 << 1;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AllowEntry {
    pub flags: u32,
}

pub mod mode {
    pub const AUDIT: u32 = 0;
    pub const ENFORCE: u32 = 1;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Config {
    pub mode: u32,
    pub abi: u32,
    pub provd_exe: ExeId,
}

pub mod event {
    pub const DEVICE_REGISTERED: u32 = 1;
    pub const DEVICE_UNREGISTERED: u32 = 2;
    /// A non-allow-listed `UI_DEV_CREATE`.
    pub const DENIED_CREATE: u32 = 3;
    /// A non-allow-listed write to a guarded character device.
    pub const DENIED_WRITE: u32 = 4;

    pub fn name(k: u32) -> &'static str {
        match k {
            DEVICE_REGISTERED => "device-registered",
            DEVICE_UNREGISTERED => "device-unregistered",
            DENIED_CREATE => "denied-create",
            DENIED_WRITE => "denied-write",
            _ => "invalid",
        }
    }
}

pub mod verdict {
    /// Informational event, no decision involved.
    pub const NONE: u32 = 0;
    /// The action was blocked (`-EPERM`).
    pub const DENIED: u32 = 1;
    /// The action would have been blocked in enforce mode.
    pub const AUDIT_ONLY: u32 = 2;

    pub fn name(v: u32) -> &'static str {
        match v {
            NONE => "none",
            DENIED => "denied",
            AUDIT_ONLY => "audit-only",
            _ => "invalid",
        }
    }
}

/// Ring-buffer record. Never carries key codes or event values (SPEC 7.2).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AuditEvent {
    pub kind: u32,
    pub class: u32,
    pub verdict: u32,
    /// For denials: kernel-encoded rdev of the guarded character device.
    pub rdev: u32,
    /// Input number for device events, `u64::MAX` when not applicable.
    pub device: u64,
    pub ts_ns: u64,
    pub actor: Creator,
}

pub const NO_DEVICE: u64 = u64::MAX;

/// Field offsets inside kernel structures, resolved by `provd` from the running kernel's BTF
/// and patched into the eBPF object's read-only data before load. This plays the role of
/// CO-RE relocations, which Rust eBPF programs cannot emit.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Offsets {
    pub task_mm: u32,
    pub task_start_boottime: u32,
    pub mm_exe_file: u32,
    pub file_f_inode: u32,
    pub inode_i_mode: u32,
    pub inode_i_rdev: u32,
    pub inode_i_ino: u32,
    pub inode_i_sb: u32,
    pub sb_s_dev: u32,
    /// `offsetof(struct input_dev, dev)`.
    pub input_dev_dev: u32,
    pub device_parent: u32,
    pub device_devt: u32,
    /// `offsetof(struct device, kobj) + offsetof(struct kobject, name)`.
    pub device_kobj_name: u32,
    pub input_handle_dev: u32,
    /// `offsetof(struct hid_device, dev)`; 0 when the hid module's BTF was unavailable.
    pub hid_device_dev: u32,
    pub _pad: u32,
}
