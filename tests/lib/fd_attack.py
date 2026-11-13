#!/usr/bin/env python3
"""fd-passing attack: an allow-listed helper creates the uinput device and hands the fd to
this (non-allow-listed) process, which then tries every userspace write path.

usage: fd_attack.py --key CODE [--ops write,writev,splice,sendfile,uring]
Prints "got-fd", then one line "<op> OK" or "<op> <ERRNO>" per operation.
"""
import argparse, array, errno, os, socket, struct, subprocess, sys, tempfile, time

HELPER = "/usr/libexec/prove-test/inject-helper"
URING = "/usr/libexec/prove-test/uring-write"

def event(etype, code, value):
    return struct.pack("<qqHHi", 0, 0, etype, code, value)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", type=int, required=True)
    ap.add_argument("--ops", default="write")
    a = ap.parse_args()
    down = event(1, a.key, 1) + event(0, 0, 0)
    up = event(1, a.key, 0) + event(0, 0, 0)

    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    helper = subprocess.Popen([HELPER, "pass", str(theirs.fileno()), "4"], pass_fds=[theirs.fileno()],
                              stdout=subprocess.PIPE, text=True)
    theirs.close()
    ours.settimeout(3)
    try:
        _, fds, _, _ = socket.recv_fds(ours, 1, 1)
    except OSError:
        fds = []
    if not fds:
        print("no-fd", (helper.stdout.read() or "").strip(), flush=True)
        sys.exit(1)
    fd = fds[0]
    print("got-fd", flush=True)
    time.sleep(0.4)

    def attempt(name, fn):
        try:
            fn()
            print(name, "OK", flush=True)
        except OSError as e:
            print(name, errno.errorcode.get(e.errno, str(e.errno)), flush=True)
        try:
            os.write(fd, up)  # release the key if the press went through
        except OSError:
            pass

    for op in a.ops.split(","):
        if op == "write":
            attempt(op, lambda: os.write(fd, down))
        elif op == "writev":
            attempt(op, lambda: os.writev(fd, [down[:24], down[24:]]))
        elif op == "splice":
            def do_splice():
                r, w = os.pipe()
                os.write(w, down)
                os.splice(r, fd, len(down))
            attempt(op, do_splice)
        elif op == "sendfile":
            def do_sendfile():
                with tempfile.TemporaryFile() as f:
                    f.write(down); f.flush()
                    os.sendfile(fd, f.fileno(), 0, len(down))
            attempt(op, do_sendfile)
        elif op == "uring":
            r = subprocess.run([URING, str(fd), str(a.key)], pass_fds=[fd], capture_output=True, text=True)
            print(r.stdout.strip().replace("io_uring", "uring"), flush=True)
            try:
                os.write(fd, up)
            except OSError:
                pass
    time.sleep(0.3)
    helper.kill()

if __name__ == "__main__":
    main()
