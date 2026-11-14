//! The only module in this crate that contains `unsafe`.
//!
//! It wraps three things: reads of kernel memory at offsets resolved from BTF by `provd`
//! (`Offsets`), raw hook-argument extraction, and map lookups that hand out references.

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_task, bpf_get_current_uid_gid, bpf_ktime_get_boot_ns,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
    },
    programs::{FEntryContext, FExitContext, LsmContext, ProbeContext, RetProbeContext},
};
use prove_common::{
    AllowEntry, Config, Creator, DeviceRecord, ExeId, Offsets, S_IFCHR, S_IFMT, mode,
};

use crate::maps::{ALLOW_INJECT, CONFIG, DEVICES, HID_CREATORS};

/// Patched by `provd` before load (`EbpfLoader::set_global`).
#[unsafe(no_mangle)]
static OFFSETS: Offsets = Offsets {
    task_mm: 0,
    task_start_boottime: 0,
    mm_exe_file: 0,
    file_f_inode: 0,
    inode_i_mode: 0,
    inode_i_rdev: 0,
    inode_i_ino: 0,
    inode_i_sb: 0,
    sb_s_dev: 0,
    input_dev_dev: 0,
    device_parent: 0,
    device_devt: 0,
    device_kobj_name: 0,
    input_handle_dev: 0,
    hid_device_dev: 0,
    _pad: 0,
};

/// Volatile read of one offset, so the compiler cannot fold the placeholder zero.
macro_rules! off {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(&raw const OFFSETS.$field) } as u64
    };
}

#[inline(always)]
fn read<T: Copy>(addr: u64) -> Option<T> {
    if addr == 0 {
        return None;
    }
    unsafe { bpf_probe_read_kernel(addr as *const T) }.ok()
}

#[inline(always)]
fn read_ptr(addr: u64) -> u64 {
    read::<u64>(addr).unwrap_or(0)
}

pub fn now_ns() -> u64 {
    unsafe { bpf_ktime_get_boot_ns() }
}

pub fn pid_tgid() -> u64 {
    bpf_get_current_pid_tgid()
}

/// Executable identity of the current task; `ExeId::UNKNOWN` for kernel threads.
#[inline(always)]
pub fn current_exe() -> ExeId {
    let task = unsafe { bpf_get_current_task() };
    let mm = read_ptr(task + off!(task_mm));
    let file = read_ptr(mm + off!(mm_exe_file));
    if mm == 0 || file == 0 {
        return ExeId::UNKNOWN;
    }
    let inode = read_ptr(file + off!(file_f_inode));
    let sb = read_ptr(inode + off!(inode_i_sb));
    if inode == 0 || sb == 0 {
        return ExeId::UNKNOWN;
    }
    let ino = read::<u64>(inode + off!(inode_i_ino)).unwrap_or(0);
    let dev = read::<u32>(sb + off!(sb_s_dev)).unwrap_or(0);
    ExeId::new(dev, ino)
}

#[inline(always)]
pub fn current_creator() -> Creator {
    let task = unsafe { bpf_get_current_task() };
    Creator {
        tgid: (bpf_get_current_pid_tgid() >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        start_boottime_ns: read::<u64>(task + off!(task_start_boottime)).unwrap_or(0),
        exe: current_exe(),
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
    }
}

/// Kernel-encoded `i_rdev` of `file` if it is a character device.
#[inline(always)]
pub fn file_chr_rdev(file: u64) -> Option<u32> {
    let inode = read_ptr(file + off!(file_f_inode));
    let i_mode = read::<u16>(inode + off!(inode_i_mode))? as u32;
    if i_mode & S_IFMT != S_IFCHR {
        return None;
    }
    read::<u32>(inode + off!(inode_i_rdev))
}

/// `&input_dev->dev`.
#[inline(always)]
pub fn input_device(input_dev: u64) -> u64 {
    input_dev + off!(input_dev_dev)
}

/// `input_handle->dev`.
#[inline(always)]
pub fn handle_input_dev(handle: u64) -> u64 {
    read_ptr(handle + off!(input_handle_dev))
}

/// `device->parent` (0 if none).
#[inline(always)]
pub fn device_parent(device: u64) -> u64 {
    read_ptr(device + off!(device_parent))
}

#[inline(always)]
pub fn device_devt(device: u64) -> u32 {
    read::<u32>(device + off!(device_devt)).unwrap_or(0)
}

/// The `struct hid_device` embedding `device`, or 0 if the offset is unknown.
#[inline(always)]
pub fn hid_device_of(device: u64) -> u64 {
    let off = off!(hid_device_dev);
    if off == 0 { 0 } else { device.wrapping_sub(off) }
}

/// Parse N from the kobject name `inputN` of an input device.
#[inline(always)]
pub fn input_number(input_dev: u64) -> Option<u64> {
    let name = read_ptr(input_device(input_dev) + off!(device_kobj_name));
    if name == 0 {
        return None;
    }
    let mut buf = [0u8; 16];
    unsafe { bpf_probe_read_kernel_str_bytes(name as *const u8, &mut buf) }.ok()?;
    if buf[0] != b'i' || buf[1] != b'n' || buf[2] != b'p' || buf[3] != b'u' || buf[4] != b't' {
        return None;
    }
    let mut n: u64 = 0;
    let mut digits = 0;
    for &c in &buf[5..15] {
        if c == 0 {
            break;
        }
        if !(b'0'..=b'9').contains(&c) {
            return None;
        }
        n = n * 10 + (c - b'0') as u64;
        digits += 1;
    }
    if digits == 0 { None } else { Some(n) }
}

// ---- hook arguments --------------------------------------------------------------------

pub trait Args {
    fn ptr(&self, n: usize) -> u64;
    fn int(&self, n: usize) -> i32;
}

macro_rules! impl_args {
    ($ctx:ty) => {
        impl Args for $ctx {
            #[inline(always)]
            fn ptr(&self, n: usize) -> u64 {
                self.arg::<u64>(n)
            }
            #[inline(always)]
            fn int(&self, n: usize) -> i32 {
                self.arg::<i32>(n)
            }
        }
    };
}
impl_args!(FEntryContext);
impl_args!(FExitContext);
impl_args!(LsmContext);

pub fn kprobe_arg0(ctx: &ProbeContext) -> u64 {
    ctx.arg::<u64>(0).unwrap_or(0)
}

pub fn kretprobe_ret(ctx: &RetProbeContext) -> u64 {
    ctx.ret::<u64>()
}

// ---- map lookups -----------------------------------------------------------------------

#[inline(always)]
pub fn enforce() -> bool {
    match CONFIG.get(0) {
        Some(Config { mode, .. }) => *mode == mode::ENFORCE,
        None => false,
    }
}

#[inline(always)]
pub fn allow_flags(exe: &ExeId) -> u32 {
    match unsafe { ALLOW_INJECT.get(exe) } {
        Some(AllowEntry { flags }) => *flags,
        None => 0,
    }
}

#[inline(always)]
pub fn device_class(n: u64) -> Option<u32> {
    unsafe { DEVICES.get(&n) }.map(|r: &DeviceRecord| r.class)
}

/// Increment `inject_count` of device `n`, if it has a record. The update is not atomic
/// (the BPF target has no 64-bit atomics in `core`); a lost update under concurrent
/// injection still leaves the counter larger than any earlier snapshot, which is all the
/// consent helper relies on.
#[inline(always)]
pub fn bump_inject_count(n: u64) {
    if let Some(rec) = DEVICES.get_ptr_mut(&n) {
        // SAFETY: the pointer is a live, properly aligned map value.
        unsafe { (*rec).inject_count = (*rec).inject_count.wrapping_add(1) };
    }
}

/// True if the current task has a userspace address space (i.e. is not a kernel thread).
#[inline(always)]
pub fn current_is_user() -> bool {
    let task = unsafe { bpf_get_current_task() };
    read_ptr(task + off!(task_mm)) != 0
}

#[inline(always)]
pub fn hid_creator(hid: u64) -> Option<Creator> {
    unsafe { HID_CREATORS.get(&hid) }.copied()
}

/// Loop forever; eBPF programs cannot unwind.
pub fn halt() -> ! {
    loop {}
}
