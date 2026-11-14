"""A13 / S-a: a uhid keyboard created by the attacker. Provenance must name the attacker
(not the kernel worker that registers the device), and with S1 enforcement the creating
write to /dev/uhid is denied."""
from harness import Prompt, brief

ID, TITLE = "A13", "uhid keyboard created by the attacker (also S-a)"
EXPECT = {"enforce": "creation denied (EPERM), prompt not approved",
          "audit": "classed uhid with the attacker as creator, prompt not approved"}

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
    if mode == "enforce":
        ok = first == ["create", "EPERM"] and res["verdict"] != "approved"
        return ok, f"attacker: {' '.join(first)}; prompt: {res['verdict']}", {"result": res}
    ok = (rec.get("class") == "uhid" and rec.get("pid") == first[1] and rec.get("comm") == "python3"
          and res["verdict"] != "approved")
    return ok, f"class: {rec.get('class')}; creator: {rec.get('comm')}({rec.get('pid')}), attacker pid {first[1]}; " \
               f"prompt: {res['verdict']}", {"record": rec, "result": res}
