"""A2: like A1, but the device copies name, bus, vendor and product of the real USB keyboard."""
from harness import Prompt, brief

ID, TITLE = "A2", "uinput keyboard with the identity of a real USB keyboard"
EXPECT = {"enforce": "creation denied; never classed hardware",
          "audit": "classed uinput (never hardware), prompt not approved"}
SPOOF = "--name 'QEMU QEMU USB Keyboard' --vendor 0x0627 --product 0x0001 --bus 3"

def run(vm, mode):
    with Prompt(vm) as p:
        proc = vm.attacker_bg(f"uinput_kbd.py {SPOOF} --interactive", stdin=True)
        first = proc.stdout.readline().split()
        classes = []
        if first[:1] == ["created"]:
            pid = first[1]
            classes = [d["class"] for d in vm.devices() if d["pid"] == pid]
            proc.stdin.write(f"{p.key['code']}\n"); proc.stdin.flush()
            first.append(proc.stdout.readline().strip())
        proc.stdin.close(); proc.wait(timeout=10)
        res = p.finish()
    out = " ".join(first)
    if mode == "enforce":
        ok = first[:2] == ["create", "EPERM"] and res["verdict"] != "approved"
    else:
        ok = classes == ["uinput"] and "wrote" in out and res["verdict"] != "approved"
    return ok, f"attacker: {out}; class: {classes or '-'}; prompt: {res['verdict']}", {"result": res}
