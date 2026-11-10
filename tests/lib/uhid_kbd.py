#!/usr/bin/env python3
"""Create a uhid keyboard, optionally press keys, keep it alive for a while.

usage: uhid_kbd.py [--name NAME] [--vendor 0x..] [--product 0x..] [--bus N] [--hold SECONDS]
                   [--key HID_USAGE ...]
Prints "created" once the device exists. Exit status 1 with the errno name if creation fails.
"""
import argparse, errno, os, struct, sys, time

UHID_DESTROY, UHID_INPUT2, UHID_CREATE2 = 1, 12, 11
# Boot keyboard report descriptor.
RDESC = bytes([
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00,
    0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01,
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65,
    0x81, 0x00, 0xC0,
])

def create2(name, bus, vendor, product):
    body = struct.pack("<128s64s64sHHIIII", name.encode(), b"", b"", len(RDESC), bus,
                       vendor, product, 0, 0) + RDESC.ljust(4096, b"\0")
    return struct.pack("<I", UHID_CREATE2) + body

def input2(report):
    return struct.pack("<IH", UHID_INPUT2, len(report)) + report.ljust(4096, b"\0")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="prove-test-uhid")
    ap.add_argument("--vendor", type=lambda s: int(s, 0), default=0x1234)
    ap.add_argument("--product", type=lambda s: int(s, 0), default=0x5678)
    ap.add_argument("--bus", type=lambda s: int(s, 0), default=0x03)
    ap.add_argument("--hold", type=float, default=2.0)
    ap.add_argument("--key", type=lambda s: int(s, 0), action="append", default=[])
    a = ap.parse_args()
    try:
        fd = os.open("/dev/uhid", os.O_RDWR)
        os.write(fd, create2(a.name, a.bus, a.vendor, a.product))
    except OSError as e:
        print(errno.errorcode.get(e.errno, str(e.errno)))
        sys.exit(1)
    print("created", flush=True)
    time.sleep(0.5)
    for usage in a.key:
        os.write(fd, input2(bytes([0, 0, usage, 0, 0, 0, 0, 0])))
        time.sleep(0.02)
        os.write(fd, input2(bytes(8)))
        time.sleep(0.02)
    time.sleep(a.hold)
    os.write(fd, struct.pack("<I", UHID_DESTROY).ljust(4380, b"\0"))
    os.close(fd)

if __name__ == "__main__":
    main()
