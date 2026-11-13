#!/usr/bin/env python3
"""Hold EVIOCGRAB on every evdev node this user can open (the test grants the ACL).

usage: grab_all.py [--hold S]
Prints "grabbed N" with the number of devices grabbed.
"""
import argparse, fcntl, glob, os, time

EVIOCGRAB = 0x40044590

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hold", type=float, default=6)
    a = ap.parse_args()
    fds = []
    for path in sorted(glob.glob("/dev/input/event*")):
        try:
            fd = os.open(path, os.O_RDONLY)
            fcntl.ioctl(fd, EVIOCGRAB, 1)
            fds.append(fd)
        except OSError:
            pass
    print("grabbed", len(fds), flush=True)
    time.sleep(a.hold)

if __name__ == "__main__":
    main()
