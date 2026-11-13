"""A9: a process that is not a listed requester talks to the consent socket and tries to
replace the socket so that it could feed forged results to real requesters."""
import json
from harness import brief, lines

ID, TITLE = "A9", "non-listed requester / result forgery"
EXPECT = {m: "request rejected; socket cannot be replaced" for m in ("audit", "enforce")}

def run(vm, mode):
    _, out = vm.attacker("fake_requester.py")
    reply = next((json.loads(l[6:]) for l in lines(out) if l.startswith("reply {")), {})
    ok = (reply.get("type") == "result" and reply.get("verdict") == "error"
          and "unlink PermissionError" in out and "create PermissionError" in out)
    return ok, f"reply: {reply.get('verdict')} ({reply.get('reason')}); " \
               f"{'; '.join(l for l in lines(out) if not l.startswith('reply'))}", {"raw": out}
