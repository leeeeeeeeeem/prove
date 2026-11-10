use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, LruHashMap, RingBuf},
};
use prove_common::{AllowEntry, Config, Creator, DeviceRecord, ExeId, GrabRecord};

/// Input number (the N of `inputN`) -> provenance record.
#[map]
pub static DEVICES: HashMap<u64, DeviceRecord> = HashMap::with_max_entries(1024, 0);

/// Input number -> holder of the evdev grab.
#[map]
pub static GRABS: HashMap<u64, GrabRecord> = HashMap::with_max_entries(1024, 0);

/// Address of `struct hid_device` -> task that allocated it.
#[map]
pub static HID_CREATORS: HashMap<u64, Creator> = HashMap::with_max_entries(1024, 0);

#[map]
pub static ALLOW_INJECT: HashMap<ExeId, AllowEntry> = HashMap::with_max_entries(256, 0);

#[map]
pub static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// pid_tgid -> timestamp of a `UI_DEV_CREATE` that passed `ioctl_guard` and is in flight.
#[map]
pub static CREATE_INFLIGHT: LruHashMap<u64, u64> = LruHashMap::with_max_entries(1024, 0);
