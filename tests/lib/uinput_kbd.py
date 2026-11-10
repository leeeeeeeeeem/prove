#!/usr/bin/env python3
"""Create a uinput keyboard with raw ioctls, optionally press keys, keep it alive.

usage: uinput_kbd.py [--name NAME] [--vendor 0x..] [--product 0x..] [--bus N] [--hold SECONDS]
                     [--key EV_KEY_CODE ...] [--legacy]
Prints "created" once UI_DEV_CREATE succeeded, then "wrote" after the key events.
On failure prints "<step> <ERRNO>" (step is open, setup, create or write) and exits 1.
--legacy configures the device through the old write() path instead of UI_DEV_SETUP.
"""
import argparse, errno, fcntl, os, struct, sys, time

UI_SET_EVBIT, UI_SET_KEYBIT = 0x40045564, 0x40045565
UI_DEV_SETUP, UI_DEV_CREATE, UI_DEV_DESTROY = 0x405C5503, 0x5501, 0x5502
EV_SYN, EV_KEY = 0, 1

def fail(step, e):
    print(step, errno.errorcode.get(e.errno, str(e.errno)), flush=True)
    sys.exit(1)

def event(etype, code, value):
    return struct.pack("<qqHHi", 0, 0, etype, code, value)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="prove-test-uinput")
    ap.add_argument("--vendor", type=lambda s: int(s, 0), default=0x1234)
    ap.add_argument("--product", type=lambda s: int(s, 0), default=0x5678)
    ap.add_argument("--bus", type=lambda s: int(s, 0), default=0x03)
    ap.add_argument("--hold", type=float, default=2.0)
    ap.add_argument("--key", type=lambda s: int(s, 0), action="append", default=[])
    ap.add_argument("--legacy", action="store_true")
    a = ap.parse_args()
    try:
        fd = os.open("/dev/uinput", os.O_WRONLY)
    except OSError as e:
        fail("open", e)
    try:
        fcntl.ioctl(fd, UI_SET_EVBIT, EV_KEY)
        for code in range(1, 128):
            fcntl.ioctl(fd, UI_SET_KEYBIT, code)
        if a.legacy:
            # struct uinput_user_dev: name[80], input_id, ff_effects_max, abs arrays 4*64 ints
            os.write(fd, struct.pack("<80sHHHHI", a.name.encode(), a.bus, a.vendor, a.product, 1, 0)
                     + bytes(4 * 64 * 4))
        else:
            fcntl.ioctl(fd, UI_DEV_SETUP,
                        struct.pack("<HHHH80sI", a.bus, a.vendor, a.product, 1, a.name.encode(), 0))
    except OSError as e:
        fail("setup", e)
    try:
        fcntl.ioctl(fd, UI_DEV_CREATE)
    except OSError as e:
        fail("create", e)
    print("created", flush=True)
    time.sleep(0.5)
    try:
        for code in a.key:
            os.write(fd, event(EV_KEY, code, 1) + event(EV_SYN, 0, 0))
            time.sleep(0.02)
            os.write(fd, event(EV_KEY, code, 0) + event(EV_SYN, 0, 0))
            time.sleep(0.02)
    except OSError as e:
        fail("write", e)
    if a.key:
        print("wrote", flush=True)
    time.sleep(a.hold)
    fcntl.ioctl(fd, UI_DEV_DESTROY)

if __name__ == "__main__":
    main()
