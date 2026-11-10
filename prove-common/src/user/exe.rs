//! Executable identity as seen from userspace.

use std::{fs::Metadata, io, os::unix::fs::MetadataExt, path::Path};

use crate::{ExeId, kdev};

/// Convert a userspace `st_dev` (glibc encoding) to the kernel's `major << 20 | minor`.
pub fn kernel_dev(st_dev: u64) -> u32 {
    let major = (((st_dev >> 32) & 0xffff_f000) | ((st_dev >> 8) & 0x0000_0fff)) as u32;
    let minor = (((st_dev >> 12) & 0xffff_ff00) | (st_dev & 0x0000_00ff)) as u32;
    kdev(major, minor)
}

/// Split a userspace `st_rdev`/`st_dev` into (major, minor).
pub fn major_minor(dev: u64) -> (u32, u32) {
    let k = kernel_dev(dev);
    (k >> 20, k & 0xf_ffff)
}

pub fn exe_id_of_metadata(md: &Metadata) -> ExeId {
    ExeId::new(kernel_dev(md.dev()), md.ino())
}

/// Identity of the file at `path` (symlinks followed).
pub fn exe_id_of_path(path: &Path) -> io::Result<ExeId> {
    Ok(exe_id_of_metadata(&std::fs::metadata(path)?))
}

/// Identity and path of the executable of a live process. The path is informational only.
pub fn exe_of_pid(pid: u32) -> io::Result<(ExeId, String)> {
    let link = format!("/proc/{pid}/exe");
    let id = exe_id_of_path(Path::new(&link))?;
    let path = std::fs::read_link(&link)?.to_string_lossy().into_owned();
    Ok((id, path))
}

pub fn fmt_exe_id(id: &ExeId) -> String {
    if id.is_unknown() {
        "-".to_string()
    } else {
        format!("{}:{}/{}", id.dev >> 20, id.dev & 0xf_ffff, id.ino)
    }
}
