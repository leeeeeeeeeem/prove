"""A13: a uhid keyboard created by the attacker (provenance only; enforcement is S1)."""
from harness import Prompt

ID, TITLE = "A13", "uhid keyboard created by the attacker"
EXPECT = {m: "classed uhid with the attacker as creator, prompt not approved" for m in ("audit", "enforce")}

def run(vm, mode):
    with Prompt(vm) as p:
        proc = vm.attacker_bg(f"uhid_kbd.py --name prove-a13-uhid --key {p.key['hid']} --hold 1.5")
        first = proc.stdout.readline().split()
        rec = {}
        if first[:1] == ["created"]:
            devs = vm.wait_devices(lambda ds: any(d["name"] == "prove-a13-uhid" for d in ds), timeout=5)
            rec = next(d for d in devs if d["name"] == "prove-a13-uhid")
        res = p.finish()
        proc.wait(timeout=10)
    ok = (rec.get("class") == "uhid" and rec.get("pid") == first[1] and rec.get("comm") == "python3"
          and res["verdict"] != "approved")
    return ok, f"class: {rec.get('class')}; creator: {rec.get('comm')}({rec.get('pid')}), attacker pid {first[1:2]}; " \
               f"prompt: {res['verdict']}", {"record": rec, "result": res}
