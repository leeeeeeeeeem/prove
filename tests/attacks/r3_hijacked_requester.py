"""R3 (residual risk): attacker code inside a listed requester is treated as that requester:
it can open prompts with text of its choosing (and a hijacked requester can ignore verdicts)."""
import json
from harness import brief, lines

ID, TITLE = "R3", "hijacked requester (LD_PRELOAD)"
EXPECT = {m: "attacker is accepted as the requester: SUCCEEDS (residual risk)" for m in ("audit", "enforce")}

def run(vm, mode):
    _, out = vm.sh("PROVE_EVIL=consent LD_PRELOAD=/usr/libexec/prove-test/evil-preload.so prove-requester-demo x")
    reply = next((json.loads(l[12:]) for l in lines(out) if l.startswith("evil: reply ")), {})
    ok = reply.get("type") == "challenge"
    return ok, f"provd answered the hijacked requester with: {reply.get('type', brief(out))}", {"raw": out}
