//! Access to the maps pinned under [`PIN_DIR`](crate::PIN_DIR). Root only.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use aya::maps::{Array, HashMap, Map, MapData, RingBuf};

use crate::{AllowEntry, Config, Creator, DeviceRecord, ExeId, GrabRecord, PIN_DIR};

pub const DEVICES: &str = "DEVICES";
pub const GRABS: &str = "GRABS";
pub const HID_CREATORS: &str = "HID_CREATORS";
pub const ALLOW_INJECT: &str = "ALLOW_INJECT";
pub const CONFIG: &str = "CONFIG";
pub const EVENTS: &str = "EVENTS";

pub fn pin_path(name: &str) -> PathBuf {
    Path::new(PIN_DIR).join(name)
}

pub fn pins_present() -> bool {
    pin_path(CONFIG).exists()
}

fn open(name: &str) -> Result<MapData> {
    let path = pin_path(name);
    MapData::from_pin(&path).with_context(|| format!("opening pinned map {}", path.display()))
}

pub fn devices() -> Result<HashMap<MapData, u64, DeviceRecord>> {
    Ok(HashMap::try_from(Map::HashMap(open(DEVICES)?))?)
}

pub fn grabs() -> Result<HashMap<MapData, u64, GrabRecord>> {
    Ok(HashMap::try_from(Map::HashMap(open(GRABS)?))?)
}

pub fn hid_creators() -> Result<HashMap<MapData, u64, Creator>> {
    Ok(HashMap::try_from(Map::HashMap(open(HID_CREATORS)?))?)
}

pub fn allow_inject() -> Result<HashMap<MapData, ExeId, AllowEntry>> {
    Ok(HashMap::try_from(Map::HashMap(open(ALLOW_INJECT)?))?)
}

pub fn config() -> Result<Array<MapData, Config>> {
    Ok(Array::try_from(Map::Array(open(CONFIG)?))?)
}

pub fn events() -> Result<RingBuf<MapData>> {
    Ok(RingBuf::try_from(Map::RingBuf(open(EVENTS)?))?)
}

pub fn read_config() -> Result<Config> {
    Ok(config()?.get(&0, 0)?)
}

pub fn write_config(cfg: Config) -> Result<()> {
    Ok(config()?.set(0, cfg, 0)?)
}

/// Remove every pin: links first (detaches the programs), then programs and maps.
/// This is the only supported way to remove enforcement.
pub fn unload() -> Result<()> {
    let dir = Path::new(PIN_DIR);
    if !dir.exists() {
        return Ok(());
    }
    let mut pins: Vec<PathBuf> =
        std::fs::read_dir(dir)?.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    pins.sort_by_key(|p| {
        let n = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
        if n.starts_with("link_") {
            0
        } else if n.starts_with("prog_") {
            1
        } else {
            2
        }
    });
    for p in pins {
        std::fs::remove_file(&p).with_context(|| format!("removing {}", p.display()))?;
    }
    std::fs::remove_dir(dir)?;
    Ok(())
}
