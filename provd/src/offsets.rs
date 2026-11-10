//! Resolve the kernel structure offsets the eBPF programs need from the running kernel's BTF.

use anyhow::{Context as _, Result, anyhow, bail};
use btf_rs::{Btf, Type};
use prove_common::Offsets;

const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";
const HID_BTF: &str = "/sys/kernel/btf/hid";

/// Find `field` in `strukt`, descending into anonymous structs and unions. Returns bits.
fn member_bits(btf: &Btf, strukt: &btf_rs::Struct, field: &str) -> Result<Option<u32>> {
    for m in &strukt.members {
        let name = btf.resolve_name(m).unwrap_or_default();
        if name == field {
            return Ok(Some(m.bit_offset()));
        }
        if name.is_empty() {
            let inner = match btf.resolve_chained_type(m)? {
                Type::Struct(s) | Type::Union(s) => s,
                _ => continue,
            };
            if let Some(bits) = member_bits(btf, &inner, field)? {
                return Ok(Some(m.bit_offset() + bits));
            }
        }
    }
    Ok(None)
}

fn offset_of(btf: &Btf, strukt: &str, field: &str) -> Result<u32> {
    let types = btf
        .resolve_types_by_name(strukt)
        .map_err(|e| anyhow!("BTF has no type named {strukt}: {e}"))?;
    for t in types {
        let Type::Struct(s) = t else { continue };
        if let Some(bits) = member_bits(btf, &s, field)? {
            if bits % 8 != 0 {
                bail!("{strukt}.{field} is a bitfield");
            }
            return Ok(bits / 8);
        }
    }
    bail!("BTF: struct {strukt} has no member {field}")
}

pub fn resolve() -> Result<Offsets> {
    let btf = Btf::from_file(VMLINUX_BTF).with_context(|| format!("reading {VMLINUX_BTF}"))?;
    let o = |s: &str, f: &str| offset_of(&btf, s, f);

    // hid.ko carries its own (split) BTF. Without it uhid creators cannot be joined and
    // uhid devices are recorded with an unknown creator.
    let hid_device_dev = match Btf::from_split_file(HID_BTF, &btf) {
        Ok(hid) => offset_of(&hid, "hid_device", "dev").unwrap_or(0),
        Err(_) => 0,
    };

    Ok(Offsets {
        task_mm: o("task_struct", "mm")?,
        task_start_boottime: o("task_struct", "start_boottime")?,
        mm_exe_file: o("mm_struct", "exe_file")?,
        file_f_inode: o("file", "f_inode")?,
        inode_i_mode: o("inode", "i_mode")?,
        inode_i_rdev: o("inode", "i_rdev")?,
        inode_i_ino: o("inode", "i_ino")?,
        inode_i_sb: o("inode", "i_sb")?,
        sb_s_dev: o("super_block", "s_dev")?,
        input_dev_dev: o("input_dev", "dev")?,
        device_parent: o("device", "parent")?,
        device_devt: o("device", "devt")?,
        device_kobj_name: o("device", "kobj")? + o("kobject", "name")?,
        input_handle_dev: o("input_handle", "dev")?,
        hid_device_dev,
        _pad: 0,
    })
}
