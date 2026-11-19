"""S-b: the attacker (given an ACL) writes the challenge key straight into the evdev node of
a hardware keyboard. The kernel side counts the injection; the prompt notices that the
record changed and refuses the device, even for a later physical key press."""
from harness import Prompt

ID, TITLE = "S-b", "write to /dev/input/eventN of a hardware keyboard"
EXPECT = {m: "injection counted; prompt rejects the device" for m in ("audit", "enforce")}

def run(vm, mode):
    vm.sh("chmod o+rw /dev/input/event*", sudo=True)
    try:
        before = sum(int(d["injected"]) for d in vm.keyboards())
        with Prompt(vm) as p:
            _, out = vm.attacker(f"evdev_inject.py --key {p.key['code']}")
            after = sum(int(d["injected"]) for d in vm.keyboards())
            # A genuine key press on the now-tainted device, but only while the prompt is still
            # open: usually it has already refused the device, and a stray press would land in
            # the next case's prompt.
            pressed = p.proc.poll() is None
            if pressed:
                vm.press(p.key)
            res = p.finish()
    finally:
        vm.sh("chmod o-rw /dev/input/event*", sudo=True)
    ok = after > before and res["verdict"] == "denied"
    observed = (f"attacker: {out.strip()}; inject_count {before} -> {after}; "
                f"physical press: {'sent' if pressed else 'not needed'}; prompt: {res['verdict']} ({res['reason']})")
    return ok, observed, {"result": res}
