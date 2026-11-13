"""A6: a uinput device created before PROVE is loaded."""
from harness import Prompt

ID, TITLE = "A6", "device created before provd starts"
EXPECT = {"enforce": "classed preexisting, write denied, prompt not approved",
          "audit": "classed preexisting, prompt not approved"}

def run(vm, mode):
    vm.sh("systemctl stop provd; provectl unload", sudo=True)
    proc = vm.attacker_bg("uinput_kbd.py --name prove-early-device --interactive", stdin=True)
    try:
        created = proc.stdout.readline().split()
        vm.restart_provd(mode)
        cls = [d["class"] for d in vm.devices() if d["name"] == "prove-early-device"]
        with Prompt(vm) as p:
            proc.stdin.write(f"{p.key['code']}\n"); proc.stdin.flush()
            wrote = proc.stdout.readline().strip()
            res = p.finish()
    finally:
        proc.stdin.close(); proc.wait(timeout=10)
        if vm.get_mode() != mode:
            vm.restart_provd(mode)
    ok = created[:1] == ["created"] and cls == ["preexisting"] and res["verdict"] != "approved"
    ok = ok and (wrote == "write EPERM" if mode == "enforce" else wrote == "wrote")
    return ok, f"class: {cls}; attacker: {wrote}; prompt: {res['verdict']}", {"result": res}
