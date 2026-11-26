# Results

Validation and evaluation of PROVE (SPEC section 11). This file records the run of
2026-11-23. Rerunning the test scripts writes the same data as JSON to a local, untracked
`results/<date>/` directory.

## Environment

| Item | Value |
|---|---|
| Guest OS | Debian GNU/Linux 13 (trixie), arm64 |
| Guest kernel | `6.12.116+deb13-arm64` (package `6.12.116-1`) |
| Guest resources | 4 vCPU, 4 GB RAM, 20 GB ext4 root |
| Hypervisor | QEMU `virt` machine with HVF acceleration |
| Host | Apple `Mac16,1`, macOS 26.0 |

All tests run from the host over SSH and QMP. "Physical" key presses are injected through QMP
`input-send-event`, so in the VM they originate from the hypervisor rather than a real device;
this is the one unavoidable gap between the test rig and a bare-metal desktop.

## Attack suite (SPEC 11.1)

`tests/run_attacks.py`, both modes. **38/38 runs pass (19 cases × audit and enforce.)** The
observed column below is the enforce-mode run.

| # | Case | Enforce-mode outcome |
|---|---|---|
| A1 | uinput keyboard types the challenge key | create `EPERM`; prompt timeout |
| A2 | uinput keyboard spoofing a real USB keyboard | create `EPERM`; never classed hardware; timeout |
| A3 | XTest key (`xdotool`) at the prompt | injection not blocked by design; prompt timeout |
| A4 | Wayland virtual keyboard (`wtype`) at the prompt | injection not blocked by design; prompt timeout |
| A5 | fd passed from an allow-listed helper, attacker writes | write `EPERM`; prompt timeout |
| A6 | device created before `provd` starts | classed `preexisting`; write `EPERM`; timeout |
| A7 | device creation racing prompt set-up | 0 created / 2863 denied; no prompt approved |
| A8 | attacker holds `EVIOCGRAB` on the keyboards | prompt denied (device grabbed by an unaccepted holder) |
| A9 | non-listed requester / result forgery | request rejected; socket cannot be replaced |
| A10 | kill `provd`, then inject | create `EPERM` (enforcement survives); consent fails closed |
| A11 | replace an allow-listed binary as the user | replacement blocked; writable entry rejected |
| A12 | `writev` / io_uring / `splice` / `sendfile` / legacy set-up | all `EPERM` |
| A13 | uhid keyboard created by the attacker (S-a) | create `EPERM`; prompt timeout |
| S-b | write to `/dev/input/eventN` of a hardware keyboard | injection counted; prompt refuses the tainted device |
| P1 | physical key on each hardware keyboard | approved on usbkbd0, usbkbd1, viokbd0 |
| P2/P3 | allow-listed remapper (keyd), assistive vs physical | assistive approved; physical denied |
| P4 | wrong key, timeout, concurrent prompt | wrong key → timeout; second prompt refused (busy) |
| R1 | ptrace an allow-listed tool | residual risk, not implemented |
| R2 | `LD_PRELOAD` into an allow-listed tool | injection succeeds (residual risk); physical prompt still not approved |
| R3 | hijacked requester | attacker accepted as requester (residual risk) |

In audit mode the same cases pass: A1, A2, A5 and S-b succeed at *injecting* (the baseline that
shows the attack is real), but every prompt still rejects them, because consent checks the device
record independently of the enforcement mode. R2 and R3 are the documented residual risks and
"pass" by succeeding as expected. R1 (ptrace) is listed in the threat model as a residual risk and
has no implemented case.

## Classification (SPEC 11.2)

`tests/run_classify.py --seed 20266401 --uinput 500 --uhid 100 --hotplug-rounds 10`. **PASS.**

Confusion matrix (rows: true class, columns: recorded class):

| true ↓ / recorded → | hardware | uinput | uhid | unknown-virtual | preexisting | missing |
|---|---|---|---|---|---|---|
| hardware | **45** | 0 | 0 | 0 | 0 | 0 |
| uinput | 0 | **500** | 0 | 0 | 0 | 0 |
| uhid | 0 | 0 | **100** | 0 | 0 | 0 |

- Injected devices classed `hardware`: **0**
- Hardware devices classed otherwise: **0**
- Creator attribution correct: **600/600**
- Synthetic devices copying a real hardware identity: **300** (none misclassified)
- Stale records after teardown: **0**

The hardware count (45) is the four emulated devices plus the power button, across 10 hot-plug
rounds. Spoofing a real keyboard's name, bus, and vendor/product never changed the class, because
classification uses device topology only, never attacker-chosen identity fields.

## Overhead (SPEC 11.3)

`tests/run_bench.py --runs 10`, three configurations (PROVE unloaded / audit / enforce). Medians
over 10 runs, with inter-quartile range.

| Metric | Unit | Unloaded | Audit | Enforce | Audit Δ | Enforce Δ |
|---|---|---|---|---|---|---|
| `write()` → /dev/null | ns/op | 119.9 | 212.3 | 209.6 | +77% | +75% |
| `read()` ← /dev/zero | ns/op | 118.0 | 192.4 | 189.6 | +63% | +61% |
| `write()` → uinput fd | ns/op | 130.9 | 287.0 | 286.9 | +119% | +119% |
| pipe round trip | ns/op | 28270 | 28561 | 28091 | +1% | −1% |
| input latency (median) | ns | 333 | 583 | 583 | +75% | +75% |
| device registration (median) | ns | 1.73M | 2.18M | 2.16M | +26% | +25% |
| fio seq write, 512 B | IOPS | 3.51M | 2.72M | 2.72M | −22% | −22% |
| fio seq read, 512 B | IOPS | 3.76M | 2.98M | 2.98M | −21% | −21% |
| fio rand write, 4 K | IOPS | 1.67M | 1.50M | 1.51M | −10% | −9% |
| fio rand read, 4 K | IOPS | 1.68M | 1.49M | 1.51M | −12% | −10% |

Per-program kernel run time (`bpftool prog show`, `bpf_stats_enabled`, under a write-heavy load):

| Program | Hook | avg ns/call (enforce) | Notes |
|---|---|---|---|
| `write_guard` | lsm `file_permission` | 31.4 | the hot path: runs on every write |
| `ioctl_guard_native` | lsm `file_ioctl` | 922 | per ioctl, allow-list lookup on `UI_DEV_CREATE` |
| `dev_register` | fexit `input_register_device` | 106k | walks the device tree; once per device, rare |
| `dev_unregister` | fentry `input_unregister_device` | 4.4k | once per device |

Reading the numbers:

- The hot path, `write_guard`, is **~31 ns per call**. The larger per-op percentages come from
  adding that fixed cost to very cheap syscalls: a `write()` to `/dev/null` is ~120 ns to begin
  with, so +90 ns reads as +77%. The uinput write pays more (+156 ns) because its rdev matches the
  guarded range and the allow-list lookup runs.
- fio throughput drops **10–22%**: every I/O passes `file_permission`, and small-block, high-IOPS
  workloads feel the per-call cost most. Larger blocks (not shown) amortise it.
- Device registration is slow in absolute terms (~100 µs) because the fexit walks up to six
  ancestors to detect uhid, but it fires only when a device is created, not on the data path.
- **audit and enforce are statistically indistinguishable** on every metric, as expected: enforce
  adds a branch and an `EPERM` return, not extra work on the allowed path.

Caveat: these are measured in a VM under HVF on a laptop. The within-run spread is small (tight
IQRs), but the *baseline itself* shifts between sessions with host load, so treat the percentages
as indicative of the shape of the cost, not as bare-metal figures. A bare-metal run (SPEC S4)
would be needed for absolute numbers.
