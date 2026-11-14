#!/usr/bin/env python3
"""Inject a key directly into existing evdev nodes (the test grants the ACL).

usage: evdev_inject.py --key CODE
Writes a press and release of CODE to every /dev/input/event* it can open for writing and
prints "injected N" with the number of nodes written.
"""
import argparse, glob, os, struct

def event(etype, code, value):
    return struct.pack("<qqHHi", 0, 0, etype, code, value)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", type=int, required=True)
    a = ap.parse_args()
    n = 0
    for path in sorted(glob.glob("/dev/input/event*")):
        try:
            fd = os.open(path, os.O_WRONLY)
            os.write(fd, event(1, a.key, 1) + event(0, 0, 0) + event(1, a.key, 0) + event(0, 0, 0))
            os.close(fd)
            n += 1
        except OSError:
            pass
    print("injected", n, flush=True)

if __name__ == "__main__":
    main()
