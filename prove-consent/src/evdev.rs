//! FFI wrappers for the evdev ioctls. The only `unsafe` in this crate.

use std::{fs::File, os::fd::AsRawFd};

pub const EV_KEY: u16 = 0x01;
const KEY_MAX: usize = 0x2ff;
pub const KEY_BYTES: usize = KEY_MAX / 8 + 1;
/// `sizeof(struct input_event)` on 64-bit kernels: timeval (16) + type + code + value.
pub const EVENT_SIZE: usize = 24;

nix::ioctl_write_int!(eviocgrab_raw, b'E', 0x90);
nix::ioctl_read_buf!(eviocgbit_key_raw, b'E', 0x20 + EV_KEY as u8, u8);

/// `EVIOCGRAB(1)`: become the exclusive reader. `EBUSY` if someone else holds the grab.
pub fn grab(file: &File) -> nix::Result<()> {
    // SAFETY: plain ioctl on an fd we own; the argument is an integer.
    unsafe { eviocgrab_raw(file.as_raw_fd(), 1) }.map(|_| ())
}

/// `EVIOCGBIT(EV_KEY)`: bitmap of the key codes the device can emit.
pub fn key_bits(file: &File) -> nix::Result<[u8; KEY_BYTES]> {
    let mut bits = [0u8; KEY_BYTES];
    // SAFETY: the kernel writes at most `bits.len()` bytes into the buffer.
    unsafe { eviocgbit_key_raw(file.as_raw_fd(), &mut bits) }?;
    Ok(bits)
}

pub fn has_key(bits: &[u8; KEY_BYTES], code: u16) -> bool {
    let code = code as usize;
    code <= KEY_MAX && bits[code / 8] & (1 << (code % 8)) != 0
}

/// One decoded `struct input_event` (timestamps ignored).
pub struct Event {
    pub kind: u16,
    pub code: u16,
    pub value: i32,
}

pub fn decode(raw: &[u8]) -> Event {
    Event {
        kind: u16::from_ne_bytes([raw[16], raw[17]]),
        code: u16::from_ne_bytes([raw[18], raw[19]]),
        value: i32::from_ne_bytes([raw[20], raw[21], raw[22], raw[23]]),
    }
}
