"""P4: a wrong key is ignored and an unanswered prompt times out; a second request while a
prompt is active is refused."""
from harness import KEYS, Prompt

ID, TITLE = "P4", "wrong key, timeout, concurrent prompt"
EXPECT = {m: "wrong key ignored -> timeout; second prompt refused (busy)" for m in ("audit", "enforce")}

def run(vm, mode):
    with Prompt(vm) as p:
        wrong = next(k for k in KEYS.values() if k["name"] != p.key["name"])
        vm.press(wrong)
        with Prompt(vm) as second:
            busy = second.finish()
        res = p.finish()
    ok = res["verdict"] == "timeout" and busy["verdict"] == "error" and busy["reason"] == "busy"
    return ok, f"wrong key then silence: {res['verdict']}; concurrent request: {busy['verdict']} ({busy['reason']})", {}
