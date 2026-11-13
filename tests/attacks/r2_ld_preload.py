"""R2 (residual risk): attacker code loaded into an allow-listed tool with LD_PRELOAD
injects with that tool's identity. PROVE identifies executables, not the code they run."""
from harness import Prompt, brief

ID, TITLE = "R2", "LD_PRELOAD into an allow-listed tool"
EXPECT = {m: "injection SUCCEEDS (residual risk); physical prompt still not approved" for m in ("audit", "enforce")}

def run(vm, mode):
    with Prompt(vm) as p:
        _, out = vm.sh(f"PROVE_EVIL=uinput:{p.key['code']} LD_PRELOAD=/usr/libexec/prove-test/evil-preload.so "
                       f"/usr/libexec/prove-test/inject-helper hold 1")
        res = p.finish()
    ok = "evil: wrote" in out and res["verdict"] != "approved"
    return ok, f"attacker: {brief(out)}; prompt: {res['verdict']}", {"result": res}
