"""A8: the attacker (given an ACL on the evdev nodes) holds EVIOCGRAB on the keyboards.
The prompt must refuse to run rather than read from a device someone else controls."""
from harness import Prompt, brief

ID, TITLE = "A8", "attacker holds EVIOCGRAB on the keyboards"
EXPECT = {m: "prompt denied even for a physical key" for m in ("audit", "enforce")}

def run(vm, mode):
    vm.sh("chmod o+rw /dev/input/event*", sudo=True)
    proc = vm.attacker_bg("grab_all.py --hold 6")
    try:
        grabbed = proc.stdout.readline().strip()
        with Prompt(vm) as p:
            if p.key:
                vm.press(p.key)
            res = p.finish()
    finally:
        proc.wait(timeout=20)
        vm.sh("chmod o-rw /dev/input/event*", sudo=True)
    ok = grabbed.startswith("grabbed") and grabbed != "grabbed 0" and res["verdict"] == "denied"
    return ok, f"attacker: {grabbed}; prompt: {res['verdict']} ({res['reason']})", {"result": res}
