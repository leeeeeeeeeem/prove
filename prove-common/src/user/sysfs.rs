//! sysfs views of input devices.

use std::{fs, io, os::unix::fs::MetadataExt, path::PathBuf};

use super::exe::major_minor;
use crate::INPUT_MAJOR;

#[derive(Debug, Clone)]
pub struct SysInput {
    /// The N of `inputN`.
    pub number: u64,
    pub name: String,
    /// Resolved sysfs path, e.g. `/sys/devices/virtual/input/input7`.
    pub path: PathBuf,
}

impl SysInput {
    pub fn is_virtual(&self) -> bool {
        self.path.starts_with("/sys/devices/virtual")
    }
}

fn parse_input_number(name: &str) -> Option<u64> {
    name.strip_prefix("input")?.parse().ok()
}

/// All currently registered input devices.
pub fn list_inputs() -> io::Result<Vec<SysInput>> {
    let mut out = Vec::new();
    for entry in fs::read_dir("/sys/class/input")? {
        let entry = entry?;
        let Some(number) = entry.file_name().to_str().and_then(parse_input_number) else {
            continue;
        };
        let Ok(path) = fs::canonicalize(entry.path()) else { continue };
        let name = fs::read_to_string(path.join("name")).unwrap_or_default().trim().to_string();
        out.push(SysInput { number, name, path });
    }
    out.sort_by_key(|d| d.number);
    Ok(out)
}

pub fn input_name(number: u64) -> String {
    fs::read_to_string(format!("/sys/class/input/input{number}/name"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Map an open evdev node to its input number through `/sys/dev/char/13:M/device`.
pub fn input_number_of_evdev(file: &fs::File) -> io::Result<u64> {
    let md = file.metadata()?;
    let (major, minor) = major_minor(md.rdev());
    if major != INPUT_MAJOR {
        return Err(io::Error::other("not an input character device"));
    }
    let dev = fs::canonicalize(format!("/sys/dev/char/{major}:{minor}/device"))?;
    dev.file_name()
        .and_then(|n| n.to_str())
        .and_then(parse_input_number)
        .ok_or_else(|| io::Error::other("evdev node has no inputN parent"))
}
