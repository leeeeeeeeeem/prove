"""A5: an allow-listed helper creates the device and passes the fd (SCM_RIGHTS) to the
attacker, who writes to it. The write guard checks the writer, not the creator."""
from harness import Prompt, brief

ID, TITLE = "A5", "fd passing from an allow-listed helper"
EXPECT = {"enforce": "write denied (EPERM), prompt not approved",
          "audit": "write succeeds (baseline), prompt not approved"}

def run(vm, mode):
    with Prompt(vm) as p:
        _, out = vm.attacker(f"fd_attack.py --key {p.key['code']} --ops write")
        res = p.finish()
    want = "write EPERM" if mode == "enforce" else "write OK"
    ok = "got-fd" in out and want in out and res["verdict"] != "approved"
    return ok, f"attacker: {brief(out)}; prompt: {res['verdict']}", {"result": res}
