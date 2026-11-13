"""P1: a key on each emulated hardware keyboard approves a physical prompt. The key is routed
to one specific keyboard by unplugging the others. (The USB tablet has no keys and cannot
approve anything; it is covered by the classification test.)"""
import time
from harness import KEYBOARDS, Prompt

ID, TITLE = "P1", "physical key on each hardware keyboard"
EXPECT = {m: "approved on every keyboard" for m in ("audit", "enforce")}

def run(vm, mode):
    seen, observed, ok = {}, [], True
    try:
        for target in KEYBOARDS:
            for other in KEYBOARDS:
                if other != target:
                    vm.unplug(other)
            vm.wait_devices(lambda ds: len(vm.keyboards(ds)) == 1, timeout=30)
            with Prompt(vm) as p:
                vm.press(p.key)
                res = p.finish()
            observed.append(f"{target}: {res['verdict']}")
            ok = ok and res["verdict"] == "approved"
            seen[target] = res
            for other, (driver, props) in KEYBOARDS.items():
                if other != target:
                    vm.plug(other, driver, props)
            vm.wait_devices(lambda ds: len(vm.keyboards(ds)) == len(KEYBOARDS), timeout=30)
            time.sleep(0.5)
    finally:
        present = {d["id"] for d in vm.qmp.cmd("qom-list", path="/machine/peripheral") if "id" in d} | \
                  {d["name"] for d in vm.qmp.cmd("qom-list", path="/machine/peripheral")}
        for dev, (driver, props) in KEYBOARDS.items():
            if dev not in present:
                vm.plug(dev, driver, props)
    return ok, "; ".join(observed), seen
