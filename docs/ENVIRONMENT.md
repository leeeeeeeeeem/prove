# Implementation environment

The environment PROVE was built and validated on (SPEC section 4). Captured from the running VM
on 2026-11-23; the recorded run of 2026-11-26 used the same guest and toolchains.

## Guest (the system under test)

| Item | Value |
|---|---|
| OS | Debian GNU/Linux 13 (trixie), arm64 |
| Kernel | `6.12.116+deb13-arm64`, `#1 SMP Debian 6.12.116-1 (2026-11-07)` |
| Architecture | aarch64 |
| vCPU / RAM | 4 / 4 GB (3.8 GiB usable) |
| Root filesystem | ext4 on `/dev/vda1` (virtio-blk) |
| Disk | 20 GB qcow2 |

Relevant kernel configuration (`/boot/config-$(uname -r)`):

| Option | Value | Meaning |
|---|---|---|
| `CONFIG_BPF_LSM` | `y` | BPF LSM compiled in |
| `CONFIG_DEBUG_INFO_BTF` | `y` | `/sys/kernel/btf/vmlinux` present (≈5.4 MB) |
| `CONFIG_FUNCTION_TRACER` | `y` | fentry/fexit attach support |
| `CONFIG_INPUT_UINPUT` | `m` | uinput is a module |
| `CONFIG_UHID` | `m` | uhid is a module |
| `CONFIG_HID` | `m` | HID core is a module → `hid_allocate_device`/`hid_destroy_device` need kprobes, not fentry/fexit |

Active LSMs (`/sys/kernel/security/lsm`):
`lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm`.
`bpf` is present without any `lsm=` kernel argument: the stock Debian kernel enables it by default
(kernel cmdline is just `BOOT_IMAGE=… root=… ro`).

## Host / hypervisor

| Item | Value |
|---|---|
| Host | Apple `Mac16,1`, macOS 26.0 |
| Hypervisor | QEMU `virt` machine, HVF acceleration, `-cpu host` |
| Emulated input | `usb-kbd` ×2 (separate xHCI controllers), `usb-tablet`, `virtio-keyboard-pci` |

The arm64 `virt` machine has no i8042 PS/2 controller, so the fourth "physical" keyboard is a
second `usb-kbd` on its own controller rather than a PS/2 device. The virtio keyboard sits on a
hot-pluggable PCIe root port for the hot-plug classification rounds.

## Toolchain

| Item | Value |
|---|---|
| Userspace | Rust `1.100.0` (stable), one workspace, built with `cargo build` |
| eBPF | Aya, built by the `provd` build script with `nightly-2026-11-13` (rustc 1.102.0-nightly 8eb778d04) + `rust-src`; `prove-ebpf` is `no_std` |
| BPF linker | `bpf-linker` 0.13.0 (prebuilt, via `cargo binstall`) |
| Install | `scripts/setup-vm.sh` installs all of the above |
| Pinned versions | `rust-toolchain.toml`, `EBPF_TOOLCHAIN` in `provd/build.rs`, `scripts/setup-vm.sh`, `Cargo.lock` |

## Reproducing

```
vm/build.sh            # fetch the Debian cloud image, create disk + cloud-init seed
vm/run.sh              # boot (add --gui for a desktop display)
vm/wait.sh             # block until SSH + cloud-init are ready
vm/sync.sh             # copy the working tree to ~/prove in the guest
vm/ssh.sh 'cd ~/prove && scripts/setup-vm.sh'           # rustup, pinned toolchains, bpf-linker
vm/ssh.sh '. ~/.cargo/env && cd ~/prove && cargo build && sudo scripts/install.sh --test-vm'
vm/ssh.sh 'cd ~/prove && sudo tests/fixtures/setup.sh'   # build C fixtures, write the test allow-list
```

The Debian cloud image installs kernel updates on its own through unattended-upgrades, and the
newest kernel becomes the boot default. To keep the guest on the kernel above (it stays installed
next to any newer one), the test VM has automatic upgrades off and GRUB pinned to it:

```
sudo systemctl disable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service
# /etc/default/grub (UUID from `grep -o "gnulinux-[^']*" /boot/grub/grub.cfg`):
GRUB_DEFAULT="gnulinux-advanced-<uuid>>gnulinux-6.12.116+deb13-arm64-advanced-<uuid>"
sudo update-grub
```

Test entry points run from the host: `tests/run_attacks.py`, `tests/run_classify.py`,
`tests/run_bench.py`. Each writes JSON to `results/<date>/` (or `--out <dir>`). The recorded run is
`results/2026-11-26/`, discussed in `docs/RESULTS.md`; `tests/summarize.py` rebuilds its tables.
