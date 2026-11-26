#!/usr/bin/env python3
"""Device classification test (SPEC 10.2).

usage: run_classify.py [--out DIR] [--seed S] [--uinput N] [--uhid M] [--hotplug-rounds R]

Hardware set: the emulated keyboards and the tablet, hot-unplugged and re-plugged R times
through QMP. Synthetic set: N uinput and M uhid devices with random or copied identities.
Produces a confusion matrix (true class x recorded class) and checks creator attribution.
Runs in audit mode, because enforce mode would simply refuse to create the synthetic set.
"""
import argparse, collections, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from harness import KEYBOARDS, VM, default_out  # noqa: E402

HOTPLUG = dict(KEYBOARDS, usbtablet0=("usb-tablet", {"bus": "xhci0.0"}))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=default_out())
    ap.add_argument("--seed", type=int, default=20266401)
    ap.add_argument("--uinput", type=int, default=500)
    ap.add_argument("--uhid", type=int, default=100)
    ap.add_argument("--hotplug-rounds", type=int, default=10)
    a = ap.parse_args()
    vm = VM()
    vm.restart_provd("audit")
    matrix = collections.Counter()   # (true class, recorded class) -> count
    errors = []
    unplug_s = {}                    # device id -> seconds each hot-unplug took

    # ---- hardware set ----
    real = lambda ds: [d for d in ds if d["class"] != "preexisting" and d["name"].startswith("QEMU")]
    expected_real = len(real(vm.devices()))
    for d in vm.devices():
        if d["name"].startswith("QEMU") or d["name"] == "Power Button":
            matrix[("hardware", d["class"])] += 1
    for rnd in range(a.hotplug_rounds):
        for dev, (driver, props) in HOTPLUG.items():
            before = {d["device"] for d in vm.devices()}
            vm.unplug(dev)
            # PCIe hot-unplug waits for the guest's 5 s attention-button delay and has been seen to
            # take over 40 s under HVF; wait generously and record how long each unplug took.
            t0 = time.time()
            vm.wait_devices(lambda ds: len(real(ds)) == expected_real - 1, timeout=120)
            unplug_s.setdefault(dev, []).append(round(time.time() - t0, 1))
            vm.plug(dev, driver, props)
            devs = vm.wait_devices(lambda ds: len(real(ds)) == expected_real, timeout=40)
            new = [d for d in devs if d["device"] not in before]
            if len(new) != 1:
                errors.append(f"hotplug {dev} round {rnd}: {len(new)} new devices")
            for d in new:
                matrix[("hardware", d["class"])] += 1
                if d["class"] != "hardware":
                    errors.append(f"hotplug {dev} round {rnd}: classed {d['class']}")
        print(f"hotplug round {rnd + 1}/{a.hotplug_rounds} done", flush=True)

    # ---- synthetic set ----
    _, exe = vm.sh("readlink -f $(command -v python3)")
    exe = exe.strip()
    gen = vm.popen(f"python3 -u ~/prove/tests/classify/gen_devices.py --seed {a.seed} --uinput {a.uinput} --uhid {a.uhid}",
                   stdin=True)
    creator_ok = creator_total = spoofed = 0
    while True:
        line = gen.stdout.readline()
        if not line:
            errors.append("generator died")
            break
        msg = json.loads(line)
        if msg.get("done"):
            break
        records = {d["device"]: d for d in vm.devices()}
        for item in msg["batch"]:
            rec = records.get(f"input{item['n']}")
            recorded = rec["class"] if rec else "missing"
            matrix[(item["kind"], recorded)] += 1
            spoofed += item["spoofed"]
            if recorded != item["kind"]:
                errors.append(f"{item['kind']} device {item['name']!r} (spoofed={item['spoofed']}) recorded as {recorded}")
            if rec:
                creator_total += 1
                good = rec["pid"] == str(msg["pid"]) and rec["exe"] == exe
                creator_ok += good
                if not good:
                    errors.append(f"creator of input{item['n']}: {rec['comm']}({rec['pid']}) {rec['exe']}, "
                                  f"expected pid {msg['pid']} {exe}")
        gen.stdin.write("next\n"); gen.stdin.flush()
    gen.wait(timeout=30)
    time.sleep(1)
    leftover = [d for d in vm.devices() if d["class"] in ("uinput", "uhid")]

    classes = ["hardware", "uinput", "uhid", "unknown-virtual", "preexisting", "missing"]
    print("\nconfusion matrix (rows: true class, columns: recorded class)")
    print(f"{'':<10}" + "".join(f"{c:>17}" for c in classes))
    for t in ("hardware", "uinput", "uhid"):
        print(f"{t:<10}" + "".join(f"{matrix[(t, c)]:>17}" for c in classes))
    injected_as_hw = matrix[("uinput", "hardware")] + matrix[("uhid", "hardware")]
    hw_as_injected = sum(matrix[("hardware", c)] for c in classes if c != "hardware")
    print(f"\ninjected devices classed hardware: {injected_as_hw}")
    print(f"hardware devices classed otherwise: {hw_as_injected}")
    print(f"creator attribution correct: {creator_ok}/{creator_total}")
    print(f"synthetic devices with a copied hardware identity: {spoofed}")
    print(f"stale records after teardown: {len(leftover)}")
    for e in errors[:20]:
        print("  !!", e)
    ok = not errors and injected_as_hw == 0 and hw_as_injected == 0 and creator_ok == creator_total and not leftover
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "classify.json"), "w") as f:
            json.dump({"info": vm.info(), "seed": a.seed, "uinput": a.uinput, "uhid": a.uhid,
                       "hotplug_rounds": a.hotplug_rounds, "unplug_seconds": unplug_s, "spoofed": spoofed,
                       "matrix": [{"true": t, "recorded": c, "count": n} for (t, c), n in sorted(matrix.items())],
                       "injected_as_hardware": injected_as_hw, "hardware_as_injected": hw_as_injected,
                       "creator_correct": creator_ok, "creator_total": creator_total,
                       "stale_records": len(leftover), "errors": errors, "pass": ok}, f, indent=1)
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
