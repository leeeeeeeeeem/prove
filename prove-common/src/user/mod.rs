//! std-only helpers shared by the userspace crates.

pub mod exe;
pub mod maps;
pub mod sysfs;

use crate::{AllowEntry, AuditEvent, Config, Creator, DeviceRecord, ExeId, GrabRecord, Offsets};

// SAFETY: all of these are `#[repr(C)]`, `Copy`, contain only integers and integer arrays,
// have no implicit padding, and are valid for every bit pattern.
unsafe impl aya::Pod for ExeId {}
unsafe impl aya::Pod for Creator {}
unsafe impl aya::Pod for DeviceRecord {}
unsafe impl aya::Pod for GrabRecord {}
unsafe impl aya::Pod for AllowEntry {}
unsafe impl aya::Pod for Config {}
unsafe impl aya::Pod for AuditEvent {}
unsafe impl aya::Pod for Offsets {}

/// `comm` as a printable string.
pub fn comm_str(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

pub const RUN_DIR: &str = "/run/prove";
pub const PID_FILE: &str = "/run/prove/provd.pid";
pub const CONSENT_SOCK: &str = "/run/prove/consent.sock";
pub const ETC_DIR: &str = "/etc/prove";
/// journald `SYSLOG_IDENTIFIER` of every PROVE audit record.
pub const JOURNAL_ID: &str = "prove";

/// Decode a kernel-written record. `None` if `bytes` is too short.
pub fn from_bytes<T: aya::Pod>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < size_of::<T>() {
        return None;
    }
    // SAFETY: `T: Pod` is valid for any bit pattern, the length was checked, and
    // `read_unaligned` has no alignment requirement.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}
