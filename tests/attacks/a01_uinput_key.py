"""A1: create a uinput keyboard and type the challenge key."""
from harness import Prompt, brief

ID, TITLE = "A1", "uinput keyboard types the challenge key"
EXPECT = {"enforce": "creation denied (EPERM), prompt not approved",
          "audit": "injection succeeds (baseline), prompt not approved"}

def run(vm, mode):
    with Prompt(vm) as p:
        _, out = vm.attacker(f"uinput_kbd.py --key {p.key['code']} --hold 0.3")
        res = p.finish()
    injected = "wrote" in out
    denied = "create EPERM" in out
    ok = res["verdict"] != "approved" and (denied if mode == "enforce" else injected)
    return ok, f"attacker: {brief(out)}; prompt: {res['verdict']}", {"attacker": out, "result": res}
