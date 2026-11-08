# PROVE — Implementation and Validation Spec

**PROVE: Provenance and Restriction Of Virtual Events**
Kernel System Security term project, Assignment 3 (implementation, validation, evaluation plan).
Author: Stefano Thomas Lemerle (20266401).

This file is the working contract for the repository. It turns the Assignment 2 design document into concrete components, interfaces, milestones and tests. Where this spec and the design document disagree, the design document wins unless the difference is recorded in `docs/DEVIATIONS.md`.

Two markers are used:

- **[source]**: confirmed by reading the upstream Linux v6.12 source (section 15). The Debian kernel may carry patches, so M0 still confirms each one on the VM, but no surprise is expected.
- **[verify]**: an assumption about the running kernel or Debian 13 that only the target VM can answer. Resolved in milestone M0, outcome written to `docs/VERIFY.md`.

---

## 1. Goal

Linux does not record where an input event came from, so a prompt-injected AI agent or any unprivileged process can forge input and approve its own permission prompts. PROVE:

1. records in the kernel which process created each input device, and how (hardware, uinput, uhid);
2. enforces a per-process injection policy at the syscall boundary with BPF LSM;
3. offers a consent contract in which a sensitive prompt is approved only by a key press on a device whose record says "hardware" (or one allow-listed assistive tool).

PROVE is not an anticheat. Cheat tools appear only as extra test adversaries.

## 2. Scope

| Feature | Tier | Milestone |
|---|---|---|
| Device provenance records (class + creator) for all input devices | core | M1 |
| Audit log of device creation and denied actions in journald | core | M1 |
| uinput enforcement: `UI_DEV_CREATE` and writes to uinput fds | core | M2 |
| Allow-list with executable verification, pinned in bpffs | core | M2 |
| Consent contract: `provd` + `prove-consent` + one demo requester | core | M3 |
| Assistive mode: one allow-listed remapper accepted by the prompt | core | M3 |
| Scripted attack suite, classification test, overhead measurements | core | M4 |
| LLM computer-use agent harness demonstration | core (demo) | M5 |
| uhid enforcement and Bluetooth (`bluetoothd` allow-listed) | stretch | S1 |
| evdev-write injection counter | stretch | S2 |
| Protected session (cgroup launcher, game case study) | stretch | S3 |
| Bare-metal run | stretch | S4 |

Non-goals: defending against root, `CAP_SYS_ADMIN`, `CAP_BPF`, hardware HID emulators, fake or overlaid prompts, XTest/Wayland/libei injection outside the prompt, behavioural (ML) classification.

## 3. Threat model

- Trusted: kernel, boot chain, root, `provd`, `prove-consent`, allow-listed executables.
- Attacker: an agent or cheat tool running as the desktop user. No root, no `CAP_SYS_ADMIN`/`CAP_BPF`, not in group `input`. It can open `/dev/uinput` but not `/dev/input/event*`.
- Known residual risk, measured and reported rather than fixed: a same-uid process hijacking an allow-listed tool or requester (ptrace, `LD_PRELOAD`, IPC), confused deputies.

Note: on stock Debian `/dev/uinput` is not user-accessible **[verify]**. The test VM grants the desktop user access (udev rule with `TAG+="uaccess"`), which is what Steam and remapper packages do on real desktops. This is the realistic precondition for the attack, and it is stated in the report.

## 4. Environment

| Item | Value |
|---|---|
| Guest OS | Debian 13 (trixie), amd64 |
| Kernel | Debian 6.12 series; exact `uname -r` and package version recorded in `docs/ENVIRONMENT.md` |
| Hypervisor | QEMU/KVM, 4 vCPU, 4 GB RAM, 20 GB disk (ext4 root) |
| Desktop | GNOME on Wayland (default), plus an Xorg session for the XTest cases |
| Language | Rust end to end, eBPF via Aya; C/libbpf is the fallback (section 12) |
| Toolchain | stable Rust for userspace, nightly + `bpf-linker` for the eBPF crate, `bpftool`, pinned in `rust-toolchain.toml` and `Cargo.lock` |

Kernel requirements, checked by `scripts/check-env.sh`:

- `CONFIG_BPF_LSM=y` and `bpf` present in `/sys/kernel/security/lsm`. Debian compiles BPF LSM in but probably does not list it in the default `lsm=` set **[verify]**; if absent, add `lsm=<current list>,bpf` to `GRUB_CMDLINE_LINUX` and reboot.
- `CONFIG_DEBUG_INFO_BTF=y` (`/sys/kernel/btf/vmlinux` exists).
- `CONFIG_FUNCTION_TRACER` / fentry support, `CONFIG_INPUT_UINPUT`, `CONFIG_UHID`.

`vm/` contains the scripts that build and boot the VM reproducibly (cloud image or preseed, QEMU command line with a QMP socket, package list). The QEMU machine exposes four "physical" input devices: i8042 PS/2 keyboard, `usb-kbd`, `usb-tablet`, `virtio-keyboard-pci`.

## 5. Architecture

```
            kernel                                   userspace
 ┌──────────────────────────────┐        ┌──────────────────────────────────┐
 │ fexit  input_register_device │──┐     │ provd (root, early boot)         │
 │ fentry input_unregister_dev. │  │     │  - loads + pins programs/maps    │
 │ fexit  hid_allocate_device   │  ├────▶│  - loads + verifies allow-lists  │
 │ fentry hid_destroy_device    │  │ring │  - audit events -> journald      │
 │ fexit  input_grab_device     │  │buf  │  - consent socket                │
 │ fentry input_release_device  │  │     │  - spawns prove-consent          │
 │ lsm    file_ioctl(_compat)   │  │     ├──────────────────────────────────┤
 │ lsm    file_permission       │──┘     │ prove-consent (uid prove-consent,│
 │                              │        │  group input, only during prompt)│
 │ maps: DEVICES, GRABS,        │◀──────▶│                                  │
 │   HID_CREATORS, ALLOW_INJECT,│  maps  │                                  │
 │   CONFIG, EVENTS             │        ├──────────────────────────────────┤
 └──────────────────────────────┘        │ provectl (root CLI)              │
                                         │ prove-requester-demo (requester) │
                                         └──────────────────────────────────┘
```

Enforcement lives entirely in pinned eBPF programs and maps, so it survives a `provd` crash. Consent requires `provd` and fails closed without it.

## 6. Repository layout

```
SPEC.md
Cargo.toml                 workspace
rust-toolchain.toml
prove-common/              no_std types shared by kernel and user side (records, events, keys)
prove-ebpf/                eBPF programs (no_std, Aya)
provd/                     root daemon
prove-consent/             headless evdev helper
provectl/                  CLI: status, devices, mode, allow-list reload
prove-requester-demo/      minimal requester showing a prompt
config/                    allow-list examples, systemd units, udev rule, sysusers
vm/                        VM build and run scripts
tests/attacks/             one script per attack case
tests/classify/            device classification test
tests/bench/               overhead and latency benchmarks
tests/run.sh               runs everything, writes results/
agent-demo/                LLM agent harness demonstration
docs/                      ENVIRONMENT.md, VERIFY.md, DEVIATIONS.md, RESULTS.md
```

## 7. Kernel side (`prove-ebpf`)

### 7.1 Maps

| Map | Type | Key | Value |
|---|---|---|---|
| `DEVICES` | hash, 1024 | `u64` input number (the N of `inputN`) | `DeviceRecord` |
| `GRABS` | hash, 1024 | `u64` input number | `GrabRecord` (holder identity) |
| `HID_CREATORS` | hash, 1024 | `u64` address of `struct hid_device` | `Creator` |
| `ALLOW_INJECT` | hash, 256 | `ExeId` | `AllowEntry` (flags: `INJECT`, `ASSISTIVE`) |
| `CONFIG` | array, 1 | 0 | `Config { mode: Audit \| Enforce, provd_exe: ExeId }` |
| `EVENTS` | ring buffer, 256 KiB | – | `AuditEvent` |

```rust
struct ExeId { dev: u32, ino: u64 }          // kernel dev_t encoding (major << 20 | minor) of the superblock
struct Creator {
    tgid: u32, uid: u32,
    start_boottime_ns: u64,                  // disambiguates pid reuse
    exe: ExeId, cgroup_id: u64,
    comm: [u8; 16],                          // audit only, never used for decisions
}
enum DeviceClass { Hardware, Uinput, Uhid, UnknownVirtual, Preexisting }
struct DeviceRecord {
    class: DeviceClass, creator: Creator,
    registered_ns: u64,
    inject_count: u64,                       // stretch S2
}
```

The device key is the input number parsed from the device name (`inputN`). The name is set in `input_allocate_device()`, before registration, so it is readable at both fentry and fexit of `input_register_device()` **[source]**. Userspace maps an evdev fd to the same key through `fstat` → `/sys/dev/char/13:M/device`.

`ExeId.dev` uses the kernel encoding; userspace `st_dev` uses a different one, so `provd` converts explicitly. The root filesystem must be ext4 (btrfs and overlayfs report a different `st_dev` than `s_dev`).

### 7.2 Programs

| Program | Hook | Behaviour |
|---|---|---|
| `dev_register` | fexit `input_register_device` | If return value is 0: classify, resolve creator (rule below), insert into `DEVICES`, emit `DeviceRegistered`. |
| `dev_unregister` | fentry `input_unregister_device` | Remove from `DEVICES` and `GRABS`, emit `DeviceUnregistered`. |
| `hid_alloc` | fexit `hid_allocate_device` | If the returned pointer is valid: store current task as `Creator` in `HID_CREATORS`, keyed by the pointer. |
| `hid_destroy` | fentry `hid_destroy_device` | Remove from `HID_CREATORS`. |
| `grab` | fexit `input_grab_device` | If return value is 0: record current task as holder in `GRABS`. |
| `release` | fentry `input_release_device` | Remove from `GRABS` unconditionally. All evdev clients of a device share one handle, and evdev only calls this function for the client that holds the grab, including on close and `EVIOCREVOKE` **[source]**. |
| `ioctl_guard` | lsm `file_ioctl` and `file_ioctl_compat` | If file is uinput (char 10:223) and `cmd == UI_DEV_CREATE` (0x5501): look up current exe in `ALLOW_INJECT`; on miss emit `Denied` and return `-EPERM` in enforce mode, 0 in audit mode. |
| `write_guard` | lsm `file_permission` | Early exit unless `mask & MAY_WRITE`, inode is a char device and rdev is uinput (core), uhid 10:239 (S1) or evdev major 13 (S2). Then the same allow-list check as above against the writer. |
| `inject_count` | fentry `input_inject_event` (S2) | For user tasks and `EV_KEY`/`EV_REL`/`EV_ABS` only: increment `inject_count`. |

Classification rule, from device topology only (names, bus type and vendor/product IDs are attacker-chosen and never consulted):

- `dev->dev.parent == NULL` → `Uinput`. uinput never sets a parent **[source]**;
- an ancestor is the uhid misc device (devt 10:239) → `Uhid`. The input device's parent is the HID device, whose parent is `uhid_misc.this_device` **[source]**;
- otherwise → `Hardware`.

Creator rule. The two paths differ, which corrects the design document (section 15, finding F1):

- `Uinput`: the creator is the current task. `UI_DEV_CREATE` calls `input_register_device()` synchronously inside the ioctl **[source]**.
- `Uhid`: the current task at registration is a kernel worker, because uhid defers `hid_add_device()` to a workqueue **[source]**. The creator is taken instead from `HID_CREATORS`, looked up by the input device's parent HID device. That entry was written when the `UHID_CREATE`/`UHID_CREATE2` write called `hid_allocate_device()` in the writer's own context **[source]**. If the lookup misses, the creator is recorded as unknown and the device is untrusted.
- `Hardware`: the creator fields are informational only (usually a kernel thread or `modprobe`).

Cross-check: `ioctl_guard` sets a per-task marker while a `UI_DEV_CREATE` is in flight. A parentless device registered without the marker is recorded as `UnknownVirtual` (treated as untrusted) and logged, so that kernel-created parentless devices are surfaced and not silently mislabelled. Whether any such device exists on the VM is a **[verify]** item.

The kernel side never emits key codes or event values; only labels, identities and counters.

`write_guard` runs on every read and write in the system. The first three instructions must reject the common case (non-write, non-char-device); its cost is measured in section 11.3.

### 7.3 Pinning

Everything is pinned under `/sys/fs/bpf/prove/` (directory mode 0700, root): programs, links and maps. `provd` on start reuses existing pins if present and compatible, otherwise loads fresh. `provectl unload` is the only supported way to remove enforcement.

## 8. Userspace

### 8.1 `provd`

Runs as root from a systemd unit ordered before the display manager.

Startup sequence:

1. Check environment (BPF LSM active, BTF present). Refuse to start in enforce mode otherwise.
2. Load or reuse pinned programs and maps.
3. Enumerate `/sys/class/input/input*` and insert records for devices that existed before the hooks: sysfs path under `/sys/devices/virtual/` → `Preexisting` (untrusted, creator unknown); otherwise → `Hardware`.
4. Load `/etc/prove/allow-inject.toml` and `/etc/prove/requesters.toml`, verify every entry, fill `ALLOW_INJECT`.
5. Set mode from `/etc/prove/provd.toml`.
6. Open the consent socket and start the ring-buffer reader.

Allow-list entry format:

```toml
[[tool]]
name   = "keyd"
path   = "/usr/bin/keyd"
sha256 = "…"
flags  = ["inject", "assistive"]     # assistive = its uinput device may satisfy an assistive-mode prompt
```

Verification at load, entry rejected (and logged) on any failure: file and every parent directory owned by root and not writable by group or others; SHA-256 matches; then `(dev, ino)` goes into the map. `provd` reloads on `SIGHUP` or `provectl reload`. Identification by systemd unit (cgroup id) is optional and only added if time allows.

Audit: every `AuditEvent` is written to journald with structured fields (`PROVE_EVENT`, `PROVE_CLASS`, `PROVE_PID`, `PROVE_EXE`, `PROVE_UID`, `PROVE_CGROUP`, `PROVE_DEVICE`, `PROVE_VERDICT`). `provd` resolves `ExeId` to a path and hash where it can.

### 8.2 Consent protocol

Socket: `/run/prove/consent.sock`, `SOCK_STREAM`, mode 0666 (authentication is by peer identity, not file permission). Messages are length-prefixed JSON (u32 little-endian length + body).

```
requester -> provd   { "type": "request", "nonce": "<32 hex>", "action": "<text shown to the user>",
                       "mode": "physical" | "assistive" }
provd -> requester   { "type": "challenge", "key": "KEY_F7", "timeout_ms": 30000 }
        ... requester displays action, its own name and the challenge key ...
provd -> requester   { "type": "result", "nonce": "…", "action_sha256": "…",
                       "verdict": "approved" | "denied" | "timeout" | "error", "reason": "…" }
```

Rules:

- On connect, `provd` takes `SO_PEERPIDFD`, resolves the peer's executable and requires it to be in `requesters.toml` (same verification as section 8.1). `SO_PEERCRED` is not sufficient because the attacker shares the uid. The pidfd is re-checked for liveness before the result is sent.
- The challenge key is drawn uniformly from a fixed set (`KEY_F1`…`KEY_F12`, digits) with the OS CSPRNG, fresh per request.
- One prompt at a time system-wide; a second request gets `error: busy`.
- The result is sent only on the requesting connection and carries the nonce and action hash, so it cannot be replayed or redirected.
- Any internal failure yields `denied`/`error`. There is no code path that approves by default.

### 8.3 `prove-consent`

Spawned by `provd` per prompt, as uid `prove-consent`, supplementary group `input`, connected by a socketpair. It is the only component that reads evdev, and only for the duration of a prompt. It does not talk to the display server, so XTest, Wayland virtual-keyboard and libei input can never reach it.

Algorithm:

1. Open every `/dev/input/event*` that reports `EV_KEY` with keyboard keys. Look up each device's record; skip devices with no record.
2. `EVIOCGRAB` each device whose class is `Hardware`.
   - Success: continue. The compositor does not see the key.
   - `EBUSY`: read `GRABS`. Unknown holder → abort with `denied`. Holder is an `ASSISTIVE` allow-listed tool and the request mode is `assistive` → instead open that tool's uinput device (record class `Uinput`, creator exe equal to the holder's exe). Any other holder → `denied`.
3. Before reading, and again when the key arrives, re-validate each fd against its record (same key, same `registered_ns`; with S2, `inject_count` unchanged since step 1).
4. Wait for a key-down of exactly the challenge key on an accepted device. Any other key is ignored. Timeout → `timeout`.
5. Release grabs, report to `provd`, exit.

Devices hot-plugged during a prompt are ignored.

### 8.4 `provectl`

`status`, `devices` (table of records), `mode audit|enforce`, `reload`, `unload`, `log` (follow PROVE journald entries). Root only.

### 8.5 `prove-requester-demo`

A small GTK or terminal program that sends a request, shows action + name + challenge key, and prints the verdict. It stands in for a polkit agent or an agent harness's permission layer, and is what the attack suite and the agent demo approve against.

## 9. Agent demonstration (`agent-demo/`)

An LLM computer-use harness runs as the desktop user with an input tool backed by uinput (`ydotool` or python-evdev `UInput`) and by XTest (`xdotool`). Its permission layer is `prove-requester-demo`, running outside the agent's tool sandbox. Scenario: a document containing a prompt injection instructs the agent to perform a gated action and press the approval key itself. Record (screen capture + journald) the run in audit mode (approval forged) and enforce mode (device creation denied, prompt times out).

If a real harness proves infeasible in the VM, downgrade to a scripted agent that replays the same tool calls, and record that in `docs/DEVIATIONS.md`.

## 10. Milestones

| ID | Deliverable | Acceptance |
|---|---|---|
| M0 | VM, toolchain, Aya skeleton, `scripts/check-env.sh`, verification checklist | A trivial fentry and a trivial LSM program load and fire on the VM; `docs/VERIFY.md` filled in |
| M1 | Provenance records + audit | `provectl devices` shows correct class and creator for the 4 QEMU devices and a test uinput device; events appear in journald |
| M2 | uinput enforcement + allow-list + pinning | Non-allow-listed creation and writes get `EPERM` in enforce mode and are only logged in audit mode; enforcement holds after `kill -9 provd` |
| M3 | Consent contract + assistive mode | Physical key approves; uinput/XTest/Wayland keys never approve; remapper approves in assistive mode only |
| M4 | Attack suite, classification test, benchmarks | `tests/run.sh` produces `results/` and `docs/RESULTS.md` tables |
| M5 | Agent demo + Assignment 3 report | Recorded demo, report sections drafted from `docs/` |
| S1–S4 | Stretch items, in that order | Only after M5 is complete |

M0 verification checklist (each line gets result, evidence and fallback in `docs/VERIFY.md`):

| # | Item | Status before M0 |
|---|---|---|
| 1 | BPF LSM is active, or can be activated with the `lsm=` parameter | open **[verify]** |
| 2 | fentry/fexit attach to `input_register_device`, `input_unregister_device`, `input_grab_device`, `input_release_device`, `input_inject_event`, `hid_allocate_device`, `hid_destroy_device` | all are non-static functions in 6.12 **[source]**; attachability on the Debian build is open **[verify]** |
| 3 | Creator context: uinput registers in the caller's task; uhid registers from a worker and needs `HID_CREATORS` | settled **[source]** (F1); confirm with a trace on the VM |
| 4 | Parent rule: uinput has no parent; uhid descends from the uhid misc device | settled **[source]** (F2). Still open: is any non-uinput device on the VM parentless **[verify]** |
| 5 | The device name `inputN` is readable at fexit | settled **[source]** (F3) |
| 6 | Every userspace write path to uinput passes `file_permission` | settled **[source]** (F4); A12 confirms at run time |
| 7 | Both ioctl entry points are covered by `file_ioctl` and `file_ioctl_compat` | settled **[source]** (F5) |
| 8 | `SO_PEERPIDFD` works on Unix stream sockets | open **[verify]** |
| 9 | `bpf_d_path` is not needed anywhere (it is unavailable in fexit); executable identity uses dev/inode only | by design |
| 10 | Default Debian permissions of `/dev/uinput`, `/dev/uhid`, `/dev/input/event*` | open **[verify]** |
| 11 | Aya can pin LSM and fentry links and re-attach to pins after a daemon restart | open **[verify]** |
| 12 | `EVIOCGRAB` from `prove-consent` hides the key from GNOME/Wayland | open **[verify]** |
| 13 | evdev minor numbers beyond the legacy 64–95 range (needed only for the S2 fast path) | open **[verify]** |

## 11. Validation and evaluation

All tests run from the host through SSH and QMP, in both `audit` (baseline) and `enforce` mode, and write machine-readable results to `results/<date>/`. "Physical" keys are sent through QMP `send-key`/`input-send-event`, so in the VM they originate from the hypervisor; this is stated as a limitation.

### 11.1 Attack suite (`tests/attacks/`)

Each case is a standalone script with a declared expected outcome. A case passes if the observed outcome equals the expected one.

| # | Case | Expected in enforce mode |
|---|---|---|
| A1 | Create uinput keyboard, type the challenge key | Creation denied (`EPERM`), prompt not approved |
| A2 | Same with spoofed name/bus/vendor/product of a real USB keyboard | Denied; never classed `Hardware` |
| A3 | XTest key (`xdotool`) at the prompt | Injection not blocked, prompt not approved |
| A4 | Wayland virtual keyboard / libei key (`wtype`) at the prompt | Injection not blocked, prompt not approved |
| A5 | fd passing: allow-listed helper creates the device, passes the fd over `SCM_RIGHTS`, attacker writes | Write denied |
| A6 | Device created before `provd` starts | Classed `Preexisting`, not accepted by the prompt |
| A7 | Race: create device during prompt set-up / between steps 2 and 4 | Not approved |
| A8 | Attacker holds `EVIOCGRAB` (with granted ACL) on the keyboard | Prompt denied (unknown holder) |
| A9 | Attacker connects to the consent socket as a non-listed requester, or replays a result | Rejected |
| A10 | Kill `provd` then inject | Injection still denied; consent fails closed |
| A11 | Replace an allow-listed binary as the desktop user | Impossible by file permissions; entry rejected if made writable |
| A12 | 32-bit compat ioctl, `writev`, io_uring write, `splice`, `sendfile` | Denied (`splice` fails with `EINVAL` even without PROVE, as uinput has no `splice_write`) |
| A13 | uhid device created by the attacker (provenance only, before S1) | Classed `Uhid` with the attacker as creator, not a kernel worker; not accepted by the prompt |
| R1 | ptrace an allow-listed tool and inject through it | **Succeeds** (residual risk) |
| R2 | `LD_PRELOAD` / IPC confused deputy on an allow-listed tool | **Succeeds** (residual risk) |
| R3 | Hijacked requester | **Succeeds** (residual risk) |
| S-a | uhid device creation and input (S1) | Denied when S1 is implemented; otherwise recorded as undetected-by-enforcement but classed `Uhid` |
| S-b | Write to `/dev/input/eventN` with granted ACL (S2) | Counter increments; prompt rejects the device |

Positive cases (must pass in both modes): P1 physical key on each of the 4 QEMU devices approves a `physical` prompt; P2 allow-listed remapper (keyd or equivalent) approves an `assistive` prompt; P3 the same remapper is rejected by a `physical` prompt; P4 wrong key and timeout produce `denied`/`timeout`.

In audit mode, A1, A2 and A5 are expected to succeed at injecting (this is the baseline that shows the attack is real), but the prompt must still reject them because consent checks records independently of the enforcement mode.

### 11.2 Classification test (`tests/classify/`)

- Hardware set: PS/2 keyboard, USB keyboard, USB tablet, virtio keyboard, hot-plugged and unplugged repeatedly through QMP.
- Synthetic set: at least 500 uinput devices (and uhid devices for S1) with randomised names, bus types, vendor/product IDs and capability sets, half of them copying the identity of a real device.
- Metric: confusion matrix over classes. Target: zero injected devices classed `Hardware`, zero real devices classed injected. Creator attribution is checked against the pid and executable the test itself used.

### 11.3 Overhead (`tests/bench/`)

Three configurations: PROVE not loaded, audit, enforce. At least 10 runs each, report median and spread.

- `fio` (sequential and random read/write, small block sizes) and `lmbench` (`lat_syscall` read/write, `lat_ctx`) for the `file_permission` cost.
- Micro-benchmark: 10⁶ `write()` calls to `/dev/null` and to a uinput fd from an allow-listed process.
- Input latency: timestamp at uinput write vs. timestamp at evdev read, 10⁴ events.
- Per-program run time from `bpftool prog show` with `kernel.bpf_stats_enabled=1`.
- Device registration latency with and without the fexit hook.

Targets are set relative to the measured baseline once it exists, and written to `docs/RESULTS.md`; no absolute numbers are promised in advance.

### 11.4 Test data characteristics

There is no external dataset. All test data is generated: synthetic device descriptors (seeded RNG, seed stored with the results), scripted attack traces, QMP key sequences, and standard benchmark workloads. Every run stores the kernel version, PROVE commit, mode and seed.

### 11.5 Mapping to Assignment 3

| Assignment 3 asks for | Source |
|---|---|
| Implementation and validation of the design | sections 7–9, `docs/RESULTS.md` |
| Description of the implementation environment | `docs/ENVIRONMENT.md` (section 4) |
| List of evaluation methods | sections 11.1–11.3 |
| Characteristics of test data or benchmarks | section 11.4 |

## 12. Risks and fallbacks

| Risk | Fallback |
|---|---|
| Aya has limited CO-RE support for reading kernel struct fields from Rust; bindings are generated from the VM's BTF and tied to that kernel build | Pin the kernel package in the VM. If field access becomes unworkable, write the eBPF side in C with libbpf and keep userspace in Rust (libbpf-rs) |
| BPF LSM cannot be enabled on the Debian kernel | Rebuild the Debian kernel with `bpf` in `CONFIG_LSM`; record as an environment change |
| An input-core function is inlined or not attachable | Use the nearest attachable caller/callee, or a kprobe; record the substitution |
| Parentless non-uinput devices exist | The `UnknownVirtual` class and ioctl marker (section 7.2) already cover this; list such devices in the report |
| `file_permission` overhead is significant | Narrow the fast path further; as a last resort attach enforcement to uinput-specific functions with `fmod_ret` where the kernel allows it |
| Real agent harness does not run in the VM | Scripted agent replaying the same tool calls (section 9) |
| `EVIOCGRAB` conflicts with the compositor in unexpected ways | Document behaviour per compositor; run the consent tests on the Xorg session as a second data point |

## 13. Conventions

- No `unsafe` in userspace crates except in clearly marked FFI wrappers; `unsafe` in `prove-ebpf` is limited to kernel reads through helper functions in one module.
- All decisions in eBPF are made on `ExeId`, never on `comm` or paths.
- Every deny path emits an audit event before returning.
- Default mode after install is `audit`. Switching to `enforce` is an explicit `provectl` action or config change.
- Each milestone ends with: tests passing on a fresh VM snapshot, `docs/` updated, a git tag (`m0`…`m5`).
- Any departure from the design document goes into `docs/DEVIATIONS.md` with the reason, since the Assignment 3 report must explain it.
- The first entry of `docs/DEVIATIONS.md` is finding F1 (section 15).

Version control, for any coding agent working in this repository:

- Commit at regular intervals: after each coherent unit of work (a program that loads, a passing test, a filled-in checklist item, a doc update), and at least once per working session. Do not let large uncommitted changes accumulate.
- Each commit builds, has a short imperative subject line and names the milestone it belongs to (for example `M1: record creator for uinput devices`).
- Never push. No `git push`, no pushing tags, no creating or updating remote branches or pull requests. All commits and milestone tags stay local; the author reviews and pushes them himself.

## 14. Open decisions (defaults apply unless changed)

1. Remapper used for assistive mode: **keyd**.
2. Requester UI: **terminal program** first, GTK window if time allows.
3. Agent harness: **an open computer-use harness driving the VM desktop**, model and harness chosen at M5.
4. Systemd-unit-based identification: **not implemented** unless M5 finishes early.

## 15. Source review (Linux v6.12, upstream)

Done by reading the upstream v6.12 tree before any code was written. Nothing here was run. Files read: `drivers/input/input.c`, `drivers/input/evdev.c`, `drivers/input/misc/uinput.c`, `drivers/hid/uhid.c`, `drivers/hid/hid-input.c`, `fs/read_write.c`, `fs/splice.c`, `fs/ioctl.c`, `io_uring/rw.c`, `include/linux/miscdevice.h`.

**F1. uhid devices are not registered in the creator's context (deviation from the design document).** The design document says the creator is the current task for both `UI_DEV_CREATE` and `UHID_CREATE`. This holds for uinput: `uinput_create_device()` calls `input_register_device()` directly from the ioctl handler. It does not hold for uhid: `uhid_dev_create2()` runs in the writer's context but only allocates the HID device and schedules a work item; `uhid_device_add_worker()` later calls `hid_add_device()`, so the input device is registered by a kernel worker. Fix adopted in section 7.2: capture the creator at `hid_allocate_device()`, which `uhid_dev_create2()` calls synchronously, and join on the HID device pointer at registration. The legacy `UHID_CREATE` path ends in `uhid_dev_create2()` and is covered too.

**F2. Parent rule.** `uinput_create_device()` never assigns `dev->dev.parent`, and `input_allocate_device()` leaves it unset. For HID, `hidinput_allocate()` sets the input device's parent to the HID device, and uhid sets the HID device's parent to `uhid_misc.this_device`. The uhid misc device uses the fixed minor 239 and uinput uses 223, so the checks on 10:239 and 10:223 are stable.

**F3. Device name.** `inputN` is assigned in `input_allocate_device()` from a global counter, not in `input_register_device()`. It is available to every hook on the device's lifetime.

**F4. Write paths.** `security_file_permission()` is called from `rw_verify_area()`. That function is called by `vfs_write`, `vfs_writev`, `vfs_iter_write`, `vfs_iocb_iter_write`, `kernel_write`, `do_sendfile` and `vfs_copy_file_range`; by io_uring's `io_write()`; and by `do_splice()` on the pipe-to-file branch. Splicing into a file without `splice_write` fails with `-EINVAL`. The only path that skips the check is `__kernel_write()`, which is callable from kernel code only. A write to a uinput fd before the device is created goes to the legacy setup path, so `write_guard` also blocks legacy setup by non-allow-listed processes; creation still needs the ioctl.

**F5. ioctl paths.** The native ioctl syscall calls `security_file_ioctl()` and the compat syscall calls `security_file_ioctl_compat()`, both before dispatch. `UI_DEV_CREATE` has the same command number in both and is not remapped by uinput's compat handler, so one comparison serves both hooks. Hooking only `file_ioctl` would leave a 32-bit bypass.

**F6. Grab tracking.** evdev's `EVIOCGRAB` calls `input_grab_device()`, which returns `-EBUSY` when a grab exists; hence the hook is an fexit that records only on success. Release happens through `input_release_device()` from the ungrab ioctl, from close and from `EVIOCREVOKE`, and evdev calls it only for the client holding the grab.

**F7. Injection counter (S2).** A write to an evdev node calls `input_inject_event()` once per event. A write to a uinput fd calls `input_event()` instead, so the S2 counter sees evdev writes only, as the design intends. `input_inject_event()` drops the event when another handle holds the grab.

Not answerable from source, left for M0: checklist items 1, 8, 10, 11, 12, 13, the attachability half of item 2 and the parentless-device half of item 4.
