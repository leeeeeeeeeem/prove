//! PROVE kernel side: provenance records for input devices and the uinput injection guard.
//!
//! Decisions use `ExeId` only, never `comm` or paths. Every deny path emits an audit event
//! before returning. No key codes or event values are ever read.
#![no_std]
#![no_main]

mod maps;
mod sys;

use aya_ebpf::{
    macros::{fentry, fexit, kprobe, kretprobe, lsm},
    programs::{FEntryContext, FExitContext, LsmContext, ProbeContext, RetProbeContext},
};
use prove_common::{
    AuditEvent, Creator, DeviceRecord, EPERM, GrabRecord, MAY_WRITE, NO_DEVICE, UHID_RDEV,
    UI_DEV_CREATE, UINPUT_RDEV, allow, class, event, verdict,
};

use crate::{
    maps::{CREATE_INFLIGHT, DEVICES, EVENTS, GRABS, HID_CREATORS},
    sys::Args,
};

/// How far up the device tree to look for the uhid misc device. The real depth is 2
/// (input -> hid -> uhid misc device).
const MAX_ANCESTORS: usize = 6;

const EV_KEY: u32 = 1;
const EV_ABS: u32 = 3;

fn emit(kind: u32, class: u32, verdict: u32, rdev: u32, device: u64, actor: Creator) {
    let ev = AuditEvent { kind, class, verdict, rdev, device, ts_ns: sys::now_ns(), actor };
    // A full ring buffer drops the event; enforcement never depends on it.
    let _ = EVENTS.output::<AuditEvent>(&ev, 0);
}

// ---- provenance ------------------------------------------------------------------------

#[fexit(function = "input_register_device")]
pub fn dev_register(ctx: FExitContext) -> i32 {
    // int input_register_device(struct input_dev *dev)
    if ctx.int(1) != 0 {
        return 0;
    }
    let dev = ctx.ptr(0);
    let Some(n) = sys::input_number(dev) else {
        return 0;
    };

    let parent = sys::device_parent(sys::input_device(dev));
    let (class, creator) = if parent == 0 {
        // uinput never sets a parent. Cross-check against the ioctl we saw.
        let marked = CREATE_INFLIGHT.remove(&sys::pid_tgid()).is_ok();
        let class = if marked { class::UINPUT } else { class::UNKNOWN_VIRTUAL };
        (class, sys::current_creator())
    } else {
        let mut is_uhid = false;
        let mut d = parent;
        for _ in 0..MAX_ANCESTORS {
            if d == 0 {
                break;
            }
            if sys::device_devt(d) == UHID_RDEV {
                is_uhid = true;
                break;
            }
            d = sys::device_parent(d);
        }
        if is_uhid {
            // Registered from a kernel worker; the creator was captured at
            // hid_allocate_device() in the writer's context (SPEC F1).
            let creator = sys::hid_creator(sys::hid_device_of(parent)).unwrap_or(Creator::UNKNOWN);
            (class::UHID, creator)
        } else {
            (class::HARDWARE, sys::current_creator())
        }
    };

    let rec =
        DeviceRecord { class, _pad: 0, creator, registered_ns: sys::now_ns(), inject_count: 0 };
    let _ = DEVICES.insert(&n, &rec, 0);
    emit(event::DEVICE_REGISTERED, class, verdict::NONE, 0, n, creator);
    0
}

#[fentry(function = "input_unregister_device")]
pub fn dev_unregister(ctx: FEntryContext) -> i32 {
    let Some(n) = sys::input_number(ctx.ptr(0)) else {
        return 0;
    };
    let Some(class) = sys::device_class(n) else {
        return 0;
    };
    let _ = DEVICES.remove(&n);
    let _ = GRABS.remove(&n);
    emit(event::DEVICE_UNREGISTERED, class, verdict::NONE, 0, n, sys::current_creator());
    0
}

// hid.ko is a module; Aya cannot attach fentry/fexit to module functions, so these two are
// kprobes.

#[kretprobe]
pub fn hid_alloc(ctx: RetProbeContext) -> u32 {
    // struct hid_device *hid_allocate_device(void); ERR_PTR on failure.
    let hid = sys::kretprobe_ret(&ctx);
    if hid == 0 || hid >= (-4095i64) as u64 {
        return 0;
    }
    let _ = HID_CREATORS.insert(&hid, &sys::current_creator(), 0);
    0
}

#[kprobe]
pub fn hid_destroy(ctx: ProbeContext) -> u32 {
    let hid = sys::kprobe_arg0(&ctx);
    let _ = HID_CREATORS.remove(&hid);
    0
}

#[fexit(function = "input_grab_device")]
pub fn grab(ctx: FExitContext) -> i32 {
    // int input_grab_device(struct input_handle *handle)
    if ctx.int(1) != 0 {
        return 0;
    }
    let Some(n) = sys::input_number(sys::handle_input_dev(ctx.ptr(0))) else {
        return 0;
    };
    let rec = GrabRecord { holder: sys::current_creator(), grabbed_ns: sys::now_ns() };
    let _ = GRABS.insert(&n, &rec, 0);
    0
}

#[fentry(function = "input_release_device")]
pub fn release(ctx: FEntryContext) -> i32 {
    // evdev only calls this for the client that holds the grab (SPEC F6).
    if let Some(n) = sys::input_number(sys::handle_input_dev(ctx.ptr(0))) {
        let _ = GRABS.remove(&n);
    }
    0
}

/// S2: count events injected into a device through an evdev write. uinput writes do not
/// pass here (they use input_event()), so this counts injection into existing devices only.
#[fentry(function = "input_inject_event")]
pub fn inject_count(ctx: FEntryContext) -> i32 {
    // void input_inject_event(struct input_handle *handle, unsigned int type, ...)
    let kind = ctx.int(1) as u32;
    if !(EV_KEY..=EV_ABS).contains(&kind) || !sys::current_is_user() {
        return 0;
    }
    if let Some(n) = sys::input_number(sys::handle_input_dev(ctx.ptr(0))) {
        sys::bump_inject_count(n);
    }
    0
}

// ---- enforcement -----------------------------------------------------------------------

/// Allow-list check for the current task. Returns the LSM verdict.
#[inline(always)]
fn check_inject(kind: u32, class: u32, rdev: u32) -> i32 {
    let actor = sys::current_creator();
    if sys::allow_flags(&actor.exe) & allow::INJECT != 0 {
        return 0;
    }
    if sys::enforce() {
        emit(kind, class, verdict::DENIED, rdev, NO_DEVICE, actor);
        -EPERM
    } else {
        emit(kind, class, verdict::AUDIT_ONLY, rdev, NO_DEVICE, actor);
        0
    }
}

#[inline(always)]
fn ioctl_guard(ctx: &LsmContext) -> i32 {
    // int security_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
    if ctx.int(1) as u32 != UI_DEV_CREATE {
        return 0;
    }
    if sys::file_chr_rdev(ctx.ptr(0)) != Some(UINPUT_RDEV) {
        return 0;
    }
    let ret = check_inject(event::DENIED_CREATE, class::UINPUT, UINPUT_RDEV);
    if ret == 0 {
        let _ = CREATE_INFLIGHT.insert(&sys::pid_tgid(), &sys::now_ns(), 0);
    }
    ret
}

#[lsm(hook = "file_ioctl")]
pub fn ioctl_guard_native(ctx: LsmContext) -> i32 {
    ioctl_guard(&ctx)
}

#[lsm(hook = "file_ioctl_compat")]
pub fn ioctl_guard_compat(ctx: LsmContext) -> i32 {
    ioctl_guard(&ctx)
}

#[lsm(hook = "file_permission")]
pub fn write_guard(ctx: LsmContext) -> i32 {
    // int security_file_permission(struct file *file, int mask)
    // Hot path: runs on every read and write in the system.
    if ctx.int(1) as u32 & MAY_WRITE == 0 {
        return 0;
    }
    // uinput: events and legacy set-up. uhid (S1): UHID_CREATE2 and input reports are writes.
    match sys::file_chr_rdev(ctx.ptr(0)) {
        Some(UINPUT_RDEV) => check_inject(event::DENIED_WRITE, class::UINPUT, UINPUT_RDEV),
        Some(UHID_RDEV) => check_inject(event::DENIED_WRITE, class::UHID, UHID_RDEV),
        _ => 0,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::halt()
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
