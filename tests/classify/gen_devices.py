#!/usr/bin/env python3
"""Synthetic device generator for the classification test (SPEC 11.2). Runs in the VM as
the unprivileged user, in audit mode.

usage: gen_devices.py --seed S --uinput N --uhid M [--batch B]

Creates devices in batches. After each batch it prints one JSON line
  {"batch": [{"n": <input number>, "kind": "uinput"|"uhid", "spoofed": bool, "name": ...}, ...], "pid": <pid>}
and waits for a line on stdin before destroying the batch, so that the harness can read the
provenance records while the devices exist. Half of the devices copy the identity (name,
bus, vendor, product) of a real hardware device; the rest are random. Capability sets are
random. Ends with {"done": true}.
"""
import argparse, fcntl, glob, json, os, random, struct, sys, time

UI_SET_EVBIT, UI_SET_KEYBIT, UI_SET_RELBIT = 0x40045564, 0x40045565, 0x40045566
UI_DEV_SETUP, UI_DEV_CREATE, UI_DEV_DESTROY = 0x405C5503, 0x5501, 0x5502
UI_GET_SYSNAME_64 = 0x80000000 | (64 << 16) | (0x55 << 8) | 44
UHID_DESTROY, UHID_CREATE2 = 1, 11
RDESC = bytes([
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00,
    0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01,
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65,
    0x81, 0x00, 0xC0,
])

def real_identities():
    """(name, bus, vendor, product) of every non-virtual input device."""
    out = []
    for d in glob.glob("/sys/class/input/input*"):
        if "/virtual/" in os.path.realpath(d):
            continue
        rd = lambda f: open(os.path.join(d, f)).read().strip()
        try:
            out.append((rd("name"), int(rd("id/bustype"), 16), int(rd("id/vendor"), 16), int(rd("id/product"), 16)))
        except OSError:
            pass
    return out

def identity(rng, real, spoof):
    if spoof and real:
        return rng.choice(real)
    name = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz ABCDEFGHIJ0123456789-_") for _ in range(rng.randint(3, 40)))
    return (name, rng.choice([0x01, 0x03, 0x05, 0x06, 0x11, 0x18, 0x19, 0x1D]), rng.getrandbits(16), rng.getrandbits(16))

def make_uinput(rng, ident):
    name, bus, vendor, product = ident
    fd = os.open("/dev/uinput", os.O_WRONLY)
    fcntl.ioctl(fd, UI_SET_EVBIT, 1)
    for code in rng.sample(range(1, 250), rng.randint(1, 120)):
        fcntl.ioctl(fd, UI_SET_KEYBIT, code)
    if rng.random() < 0.3:  # sometimes also a pointer
        fcntl.ioctl(fd, UI_SET_EVBIT, 2)
        fcntl.ioctl(fd, UI_SET_RELBIT, 0)
        fcntl.ioctl(fd, UI_SET_RELBIT, 1)
        fcntl.ioctl(fd, UI_SET_KEYBIT, 0x110)
    fcntl.ioctl(fd, UI_DEV_SETUP, struct.pack("<HHHH80sI", bus, vendor, product, 1, name.encode()[:79], 0))
    fcntl.ioctl(fd, UI_DEV_CREATE)
    sysname = fcntl.ioctl(fd, UI_GET_SYSNAME_64, bytes(64)).split(b"\0")[0].decode()
    return fd, int(sysname.removeprefix("input"))

def make_uhid(rng, ident, token):
    name, bus, vendor, product = ident
    fd = os.open("/dev/uhid", os.O_RDWR)
    body = struct.pack("<128s64s64sHHIIII", name.encode()[:127], b"", token.encode(), len(RDESC), bus,
                       vendor, product, 0, 0) + RDESC.ljust(4096, b"\0")
    os.write(fd, struct.pack("<I", UHID_CREATE2) + body)
    return fd

def find_by_uniq(tokens, timeout=10):
    """uhid registers asynchronously; locate the input devices through their uniq string."""
    found, end = {}, time.time() + timeout
    while len(found) < len(tokens) and time.time() < end:
        for d in glob.glob("/sys/class/input/input*"):
            try:
                u = open(os.path.join(d, "uniq")).read().strip()
            except OSError:
                continue
            if u in tokens:
                found[u] = int(os.path.basename(d).removeprefix("input"))
        time.sleep(0.05)
    return found

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--uinput", type=int, default=500)
    ap.add_argument("--uhid", type=int, default=100)
    ap.add_argument("--batch", type=int, default=50)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    real = real_identities()
    plan = [("uinput", i % 2 == 0) for i in range(a.uinput)] + [("uhid", i % 2 == 0) for i in range(a.uhid)]
    serial = 0
    for start in range(0, len(plan), a.batch):
        fds, batch, pending = [], [], {}
        for kind, spoof in plan[start:start + a.batch]:
            ident = identity(rng, real, spoof)
            serial += 1
            if kind == "uinput":
                fd, n = make_uinput(rng, ident)
                batch.append({"n": n, "kind": kind, "spoofed": spoof, "name": ident[0]})
            else:
                token = f"prove-classify-{a.seed}-{serial}"
                fd = make_uhid(rng, ident, token)
                pending[token] = {"kind": kind, "spoofed": spoof, "name": ident[0]}
            fds.append((kind, fd))
        for token, n in find_by_uniq(set(pending)).items():
            batch.append({"n": n, **pending.pop(token)})
        for token, rest in pending.items():
            batch.append({"n": None, **rest})
        print(json.dumps({"batch": batch, "pid": os.getpid()}), flush=True)
        sys.stdin.readline()
        for kind, fd in fds:
            if kind == "uinput":
                fcntl.ioctl(fd, UI_DEV_DESTROY)
            else:
                os.write(fd, struct.pack("<I", UHID_DESTROY).ljust(4380, b"\0"))
            os.close(fd)
        time.sleep(0.3)
    print(json.dumps({"done": True}), flush=True)

if __name__ == "__main__":
    main()
