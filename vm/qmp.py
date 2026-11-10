#!/usr/bin/env python3
"""Minimal QMP client for the PROVE VM.

usage: qmp.py key <qcode> [--device ID] [--hold MS]   press and release one key
       qmp.py plug <driver> <id> [prop=value ...]     device_add
       qmp.py unplug <id>                             device_del
       qmp.py raw '<json command>'                    send one command, print the reply

"Physical" input in the tests is produced here, i.e. by the hypervisor (SPEC section 11).
--device routes the key to one specific emulated keyboard (QEMU input device id).
"""
import json, os, socket, sys, time

SOCK = os.environ.get("QMP_SOCK", os.path.join(os.path.dirname(os.path.abspath(__file__)), "run", "qmp.sock"))

class Qmp:
    def __init__(self, path=SOCK):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(path)
        self.f = self.s.makefile("rw")
        json.loads(self.f.readline())  # greeting
        self.cmd("qmp_capabilities")

    def cmd(self, execute, **arguments):
        msg = {"execute": execute}
        if arguments:
            msg["arguments"] = arguments
        self.f.write(json.dumps(msg) + "\n")
        self.f.flush()
        while True:
            reply = json.loads(self.f.readline())
            if "event" in reply:
                continue
            if "error" in reply:
                raise RuntimeError(f"{execute}: {reply['error']['desc']}")
            return reply.get("return")

    def key(self, qcode, device=None, hold_ms=40):
        for down in (True, False):
            args = {"events": [{"type": "key", "data": {"down": down, "key": {"type": "qcode", "data": qcode}}}]}
            if device:
                args["device"] = device
            self.cmd("input-send-event", **args)
            if down:
                time.sleep(hold_ms / 1000)

def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    q = Qmp()
    op, rest = argv[1], argv[2:]
    if op == "key":
        device, hold = None, 40
        while len(rest) > 1:
            if rest[1] == "--device":
                device = rest[2]; del rest[1:3]
            elif rest[1] == "--hold":
                hold = int(rest[2]); del rest[1:3]
            else:
                sys.exit(__doc__)
        q.key(rest[0], device, hold)
    elif op == "plug":
        props = dict(p.split("=", 1) for p in rest[2:])
        q.cmd("device_add", driver=rest[0], id=rest[1], **props)
    elif op == "unplug":
        q.cmd("device_del", id=rest[0])
    elif op == "raw":
        c = json.loads(rest[0])
        print(json.dumps(q.cmd(c["execute"], **c.get("arguments", {})), indent=1))
    else:
        sys.exit(__doc__)

if __name__ == "__main__":
    main(sys.argv)
