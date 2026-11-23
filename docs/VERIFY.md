# M0 verification checklist

The assumptions marked **[verify]** in SPEC section 10, resolved against the target VM
(Debian 13, kernel `6.12.116+deb13-arm64`). Checked on 2026-11-23. Each item: result, evidence,
and the fallback that was prepared in case it failed.

| # | Item | Result | Evidence | Fallback (not needed) |
|---|---|---|---|---|
| 1 | BPF LSM active, or activatable with `lsm=` | **Yes, by default** | `/sys/kernel/security/lsm` contains `bpf`; kernel cmdline has no `lsm=` override; `CONFIG_BPF_LSM=y` | Add `lsm=<list>,bpf` to `GRUB_CMDLINE_LINUX` and reboot |
| 2 | fentry/fexit + kprobes attach to the input/HID functions | **Yes** | `provectl status` → "10 attached programs"; `/sys/fs/bpf/prove` holds `link_*` + `prog_*` for all ten; `bpftool link show` lists the lsm/tracing programs | Nearest attachable caller/callee, or a kprobe |
| 3 | Creator context: uinput = caller; uhid = worker, via `HID_CREATORS` | **Yes** | Attack A13: uhid device's creator recorded as the attacker `python3`, not a kworker. Classification: 600/600 creator attributions correct (uinput caller + uhid alloc-context) | — |
| 4 | Parent rule; is any non-uinput device parentless? | **Yes; none found** | Classification confusion matrix: all 45 hardware and 100 uhid devices classed correctly, 0 `unknown-virtual`; no real device registered without a parent | `UnknownVirtual` class + ioctl marker already handle this case if one appears |
| 5 | Device name `inputN` readable at fexit | **Yes** | `provectl devices` shows every device's name (e.g. "QEMU Virtio Keyboard"), read in the `input_register_device` fexit | — |
| 6 | Every userspace write path to uinput passes `file_permission` | **Yes** | Attack A12: `write`, `writev`, io_uring write, `splice`, `sendfile`, and legacy set-up all return `EPERM` in enforce mode | — |
| 7 | Both ioctl entry points covered (`file_ioctl` + `file_ioctl_compat`) | **Yes (native exercised; compat attached)** | Native `UI_DEV_CREATE` denied (A1, A12). Compat hook is attached (`link_ioctl_guard_compat`) but not exercisable on this host — arm64 runs no 32-bit userspace, so A12 notes "compat ioctl: not runnable on arm64 host, hook attached" | — |
| 8 | `SO_PEERPIDFD` on Unix stream sockets | **Yes** | `provd` identifies the consent peer with `getsockopt(SO_PEERPIDFD)` (`consent.rs`); attack A9 (non-listed requester) is correctly rejected | — |
| 9 | `bpf_d_path` not needed; executable identity is dev/inode only | **Confirmed by design** | `prove-ebpf` contains no `d_path` use; identity is `ExeId { dev, ino }` (`prove-common`) | — |
| 10 | Default permissions of `/dev/uinput`, `/dev/uhid`, `/dev/input/event*` | **Confirmed** | Stock Debian ships uinput/uhid without a `uaccess` tag, so a non-root user not in `input` cannot open them — this is the attack precondition. The test VM's udev rule (`70-prove-test-uinput.rules`) grants the desktop user access via group `prove-attacker` (`crw-rw---- root prove-attacker`), as Steam/remapper packages do. evdev nodes are `root:input 0660` | — |
| 11 | Aya pins LSM + fentry links and re-attaches after a daemon restart | **Yes** | After `systemctl restart provd` (pid changed), the same 10 programs stay attached to the same pins; `provd` re-attaches rather than reloading. Attack A10: injection stays denied while `provd` is dead, because the pinned maps/programs survive its absence | — |
| 12 | `EVIOCGRAB` from `prove-consent` hides the key from the compositor | **Partial — headless** | The grab mechanism works: `prove-consent` grabs every keyboard during a prompt, and the consent positive/negative cases (P1–P4, A8) pass. Whether the grab hides the key from GNOME/Wayland specifically was not confirmed, as the validation runs headless | Run the consent tests on an Xorg session as a second data point (SPEC risk table); open for the M5 desktop demo |
| 13 | evdev minor numbers beyond the legacy 64–95 range | **None present** | All current evdev nodes are minors 64–68 (`/dev/input/event0‑4`), inside the legacy range. No device exceeds 95 on this VM | Only relevant to the S2 fast path; handled there if a higher minor appears |

## Notes

- Items 1, 4, 8, 10, 11 were the open `[verify]` questions; all resolve favourably. Item 1 is the
  happiest surprise: no GRUB change was needed, as Debian's kernel enables the BPF LSM by default.
- Item 7 (compat ioctl) and item 12 (compositor grab) are confirmed only as far as this
  environment allows — a 32-bit userspace and a real desktop session, respectively, are out of
  scope for the headless arm64 test rig. Both hooks/mechanisms are in place and attach; only the
  end-to-end exercise is deferred.
- Mode is read from `provd.toml` at start-up (default `audit`) and is settable at runtime with
  `provectl mode`; the runtime value lives in the pinned `CONFIG` map, so enforcement persists
  across a `provd` crash (A10) while a clean restart re-reads the file (SPEC section 13).
