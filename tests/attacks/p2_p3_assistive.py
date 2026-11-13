"""P2 + P3: an allow-listed remapper (keyd) grabs the hardware keyboards and re-emits keys
through its own uinput device. An assistive prompt accepts that device; a physical prompt
refuses to run."""
from harness import Prompt

ID, TITLE = "P2/P3", "allow-listed remapper (keyd): assistive vs physical prompt"
EXPECT = {m: "assistive prompt approved; physical prompt denied" for m in ("audit", "enforce")}

def run(vm, mode):
    vm.sh("systemctl start keyd", sudo=True)
    try:
        devs = vm.wait_devices(lambda ds: any("keyd virtual keyboard" in d["name"] and d["class"] == "uinput" for d in ds)
                               and all(d["grab"].startswith("keyd") for d in vm.keyboards(ds)), timeout=15)
        with Prompt(vm, mode="assistive") as p:
            vm.press(p.key)
            assistive = p.finish()
        with Prompt(vm, mode="physical") as p:
            if p.key:
                vm.press(p.key)
            physical = p.finish()
    finally:
        vm.sh("systemctl stop keyd", sudo=True)
    ok = assistive["verdict"] == "approved" and physical["verdict"] == "denied"
    return ok, f"assistive: {assistive['verdict']} ({assistive['reason']}); " \
               f"physical: {physical['verdict']} ({physical['reason']})", {"assistive": assistive, "physical": physical}
