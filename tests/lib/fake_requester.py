#!/usr/bin/env python3
"""A requester that is not in requesters.toml: speak the consent protocol and print the
first reply as JSON. Also tries to tamper with the socket file.

usage: fake_requester.py
"""
import json, os, socket, struct

SOCK = "/run/prove/consent.sock"

def main():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    req = json.dumps({"type": "request", "nonce": "00" * 16, "action": "attacker action", "mode": "physical"}).encode()
    s.sendall(struct.pack("<I", len(req)) + req)
    s.settimeout(5)
    try:
        n = struct.unpack("<I", s.recv(4))[0]
        print("reply", s.recv(n).decode(), flush=True)
    except Exception as e:
        print("reply-error", repr(e), flush=True)
    for what, fn in (("unlink", lambda: os.unlink(SOCK)),
                     ("create", lambda: open("/run/prove/evil.sock", "w"))):
        try:
            fn()
            print(what, "OK", flush=True)
        except OSError as e:
            print(what, type(e).__name__, flush=True)

if __name__ == "__main__":
    main()
