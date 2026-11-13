"""A12: every userspace path that can deliver bytes to a uinput fd, plus the legacy
write()-based device set-up. The 32-bit compat ioctl cannot be exercised on this VM (the
CPU has no AArch32 EL0); the compat hook is attached and shares the code of the native one."""
from harness import Prompt, brief, lines

ID, TITLE = "A12", "writev, io_uring, splice, sendfile, legacy set-up"
EXPECT = {"enforce": "all denied (splice/sendfile fail regardless)",
          "audit": "write, writev, io_uring succeed (baseline); splice/sendfile EINVAL"}

def run(vm, mode):
    with Prompt(vm) as p:
        _, out = vm.attacker(f"fd_attack.py --key {p.key['code']} --ops write,writev,uring,splice,sendfile")
        res = p.finish()
    _, legacy = vm.attacker("uinput_kbd.py --legacy --hold 0")
    _, compat = vm.sh("test -e /sys/fs/bpf/prove/link_ioctl_guard_compat && echo compat-hook-attached", sudo=True)
    got = dict(l.split(None, 1) for l in lines(out) if " " in l)
    if mode == "enforce":
        ok = all(got.get(op) == "EPERM" for op in ("write", "writev", "uring"))
        ok = ok and got.get("splice") in ("EPERM", "EINVAL") and got.get("sendfile") in ("EPERM", "EINVAL")
        ok = ok and "setup EPERM" in legacy
    else:
        ok = all(got.get(op) == "OK" for op in ("write", "writev", "uring"))
        ok = ok and got.get("splice") == "EINVAL" and got.get("sendfile") == "EINVAL" and "created" in legacy
    ok = ok and res["verdict"] != "approved" and "compat-hook-attached" in compat
    return ok, f"{brief(out)}; legacy set-up: {brief(legacy).split(';')[0]}; compat ioctl: not runnable on arm64 host, " \
               f"hook attached; prompt: {res['verdict']}", {"ops": got}
