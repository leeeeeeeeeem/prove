# Results

Validation and evaluation of PROVE (SPEC section 10). This file discusses the recorded run of
2026-11-26. The raw output is committed in [`results/2026-11-26/`](../results/2026-11-26/):

| File | Contents |
|---|---|
| `attacks.json`, `attacks.log` | Every case in both modes: expected and observed outcome, details, duration |
| `classify.json`, `classify.log` | Confusion matrix, creator check, stale records, per-unplug timings |
| `bench.json`, `bench.log` | Every sample of every metric in all three configurations, per-program kernel stats |

`python3 tests/summarize.py` rebuilds the tables below from those files; it needs only Python.

The attack suite and benchmarks ran at commit `f84985f` and the classification test at `afa6bad`,
which differs only in the classification script's unplug timeout (40 s to 120 s, plus recording
the timings). The first classification attempt at `f84985f` stopped in hot-plug round 5, because
QEMU's PCIe hot-unplug of the virtio keyboard did not complete within 40 s. No device had been
misclassified up to that point. In the recorded rerun every unplug took at most 5.4 s.
Before the run, the eBPF programs were unloaded and loaded fresh, and the C fixtures rebuilt.

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

## Attack suite (SPEC 10.1)

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
| A7 | device creation racing prompt set-up | 0 created / 2639 denied; no prompt approved |
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
| R2 | `LD_PRELOAD` into an allow-listed tool | injection succeeds (residual risk); physical prompt still not approved |
| R3 | hijacked requester | attacker accepted as requester (residual risk) |

In audit mode the same cases pass: A1, A2, A5 and S-b succeed at *injecting* (the baseline that
shows the attack is real), but every prompt still rejects them, because consent checks the device
record independently of the enforcement mode. R2 and R3 are the documented residual risks and
"pass" by succeeding as expected.

## Classification (SPEC 10.2)

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

## Overhead (SPEC 10.3)

`tests/run_bench.py --runs 10`, three configurations (PROVE unloaded / audit / enforce). Medians
over 10 runs; the inter-quartile ranges are in `bench.json` and in the output of `tests/summarize.py`.

| Metric | Unit | Unloaded | Audit | Enforce | Audit Δ | Enforce Δ |
|---|---|---|---|---|---|---|
| `write()` → /dev/null | ns/op | 119.4 | 211.5 | 212.6 | +77% | +78% |
| `read()` ← /dev/zero | ns/op | 113.1 | 189.7 | 189.8 | +68% | +68% |
| `write()` → uinput fd | ns/op | 132.3 | 293.1 | 294.1 | +122% | +122% |
| pipe round trip | ns/op | 28072 | 28896 | 29043 | +3% | +3% |
| input latency (median) | ns | 334 | 583 | 583 | +75% | +75% |
| device registration (median) | ns | 2.38M | 2.51M | 2.59M | +5% | +9% |
| fio seq write, 512 B | IOPS | 3.56M | 2.69M | 2.69M | −24% | −25% |
| fio seq read, 512 B | IOPS | 3.82M | 2.95M | 2.93M | −23% | −23% |
| fio rand write, 4 K | IOPS | 1.71M | 1.51M | 1.50M | −12% | −13% |
| fio rand read, 4 K | IOPS | 1.72M | 1.50M | 1.49M | −13% | −13% |

Per-program kernel run time (`bpftool prog show`, `bpf_stats_enabled`, under a write-heavy load):

| Program | Hook | avg ns/call (enforce) | Notes |
|---|---|---|---|
| `write_guard` | lsm `file_permission` | 32.6 | the hot path: runs on every write |
| `ioctl_guard_native` | lsm `file_ioctl` | 485 | per ioctl, allow-list lookup on `UI_DEV_CREATE` |
| `dev_register` | fexit `input_register_device` | 104k | walks the device tree; once per device, rare |
| `dev_unregister` | fentry `input_unregister_device` | 7.0k | once per device |

Reading the numbers:

- The hot path, `write_guard`, is **~32 ns per call**. The larger per-op percentages come from
  adding that fixed cost to very cheap syscalls: a `write()` to `/dev/null` is ~120 ns to begin
  with, so +93 ns reads as +78%. The uinput write pays more (+162 ns) because its rdev matches the
  guarded range and the allow-list lookup runs.
- fio throughput drops **12–25%**: every I/O passes `file_permission`, and small-block, high-IOPS
  workloads feel the per-call cost most. Larger blocks (not shown) amortise it.
- The registration fexit takes ~100 µs because it walks up to six ancestors to detect uhid. Against
  a ~2.4 ms registration this is within the run-to-run spread (the IQRs of the three
  configurations overlap), and it fires only when a device is created, not on the data path.
- **audit and enforce are statistically indistinguishable** on every metric, as expected: enforce
  adds a branch and an `EPERM` return, not extra work on the allowed path.

Caveat: these are measured in a VM under HVF on a laptop. The within-run spread is mostly small
(tight IQRs), but the *baseline itself* shifts between sessions with host load, so treat the percentages
as indicative of the shape of the cost, not as bare-metal figures. Absolute numbers would need a
bare-metal run.
