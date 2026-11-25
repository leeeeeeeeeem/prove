# PROVE

**Provenance and Restriction Of Virtual Events.** Kernel System Security term project, KAIST.

Linux does not record where an input event comes from. Any process that can open `/dev/uinput`
can create a virtual keyboard and type into the desktop, including into a permission prompt. A
prompt-injected AI agent can use this to approve its own actions.
What PROVE delivers is a consent prompt that applications can send before sensitive operations 
that need user approval, which asks the user to input a *challenge key* with a 30 second timeout.
PROVE then guarantees that the key was sent through a hardware keyboard by the user and not injected by
an attacker.

This is done with BPF:

1. **Provenance.** Every input device gets a kernel record of how it was created (hardware,
   uinput, uhid) and which process created it.
2. **Enforcement.** A BPF LSM policy decides at the syscall boundary which executables may create
   or write to virtual input devices. Everything else gets `EPERM`.
3. **Consent.** A sensitive prompt is approved only by a key press on a device recorded as
   hardware, or on one allow-listed assistive tool.

PROVE does not defend against root, hardware HID emulators or fake prompts. The full threat model
is in [SPEC.md](SPEC.md).

## Components

| Path | What it is |
|---|---|
| `prove-ebpf/` | eBPF programs: device tracking hooks and LSM guards (Aya) |
| `prove-common/` | Types shared by the kernel and user side |
| `provd/` | Root daemon. Loads and pins the programs, holds the allow-lists, writes the audit log, serves the consent socket |
| `prove-consent/` | Helper that grabs the keyboards during a prompt and waits for the challenge key |
| `provectl/` | CLI: `status`, `devices`, `mode audit\|enforce`, `reload`, `unload`, `log` |
| `prove-requester-demo/` | Small terminal program that asks for consent and prints the verdict |
| `config/` | Allow-list examples, systemd unit, udev rule, sysusers file |
| `vm/` | Scripts to build, boot and control the test VM |
| `tests/` | Attack suite, classification test, benchmarks |
| `docs/` | Environment, verification checklist, results |

## Running it

Everything runs in a Debian 13 arm64 VM under QEMU. The host needs `qemu-system-aarch64` and an
SSH key.

```sh
vm/build.sh                 # fetch the cloud image, create the disk and cloud-init seed
vm/run.sh                   # boot headless (add --gui for a VNC display on 127.0.0.1:5)
vm/wait.sh                  # wait for SSH and cloud-init
scripts/vm-build.sh         # copy the tree into the VM and build it there
vm/ssh.sh 'cd prove && sudo scripts/install.sh --test-vm'
vm/ssh.sh sudo provectl status
```

`install.sh` starts PROVE in `audit` mode. Switch with `sudo provectl mode enforce`. The
`--test-vm` flag gives the desktop user access to `/dev/uinput` and `/dev/uhid`, which is the
precondition for the attacks.

For a desktop session (needed for the agent demo), run `vm/desktop.sh` once on a running VM, then
reboot it with `vm/stop.sh && vm/run.sh --gui`.

## Tests

Run from the host while the VM is up:

```sh
python3 tests/run_attacks.py     # attack suite, audit and enforce mode
python3 tests/run_classify.py    # device classification
python3 tests/run_bench.py       # overhead
```

Each writes JSON under `results/<date>/`. The latest numbers are summarised in
[docs/RESULTS.md](docs/RESULTS.md): 38 of 38 attack runs pass, no injected device is ever classed
as hardware, and the hot path costs about 31 ns per write.

## Status

| Milestone | State |
|---|---|
| M0 environment and verification | done |
| M1 provenance records and audit log | done |
| M2 uinput enforcement and allow-list | done |
| M3 consent contract and assistive mode | done |
| M4 attack suite, classification, benchmarks | done |
| S1 uhid enforcement | done |
| S2 evdev-write injection counter | done |
| S3 protected session | not started |
| S4 bare-metal run | not started |
| S5 agent demo | planned, for the presentation |

## Docs

- [SPEC.md](SPEC.md): design, interfaces, milestones and test plan
- [docs/ENVIRONMENT.md](docs/ENVIRONMENT.md): exact VM, kernel and toolchain versions
- [docs/VERIFY.md](docs/VERIFY.md): kernel assumptions checked on the VM
- [docs/RESULTS.md](docs/RESULTS.md): test and benchmark results
