#!/usr/bin/env python3
"""Run the attack suite (SPEC 10.1) in audit and enforce mode.

usage: run_attacks.py [--out DIR] [--mode audit|enforce] [--only ID[,ID...]]
Writes attacks.json into DIR and prints one line per case. Exit status 1 if any case fails.
"""
import argparse, importlib.util, json, os, sys, time, traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from harness import VM  # noqa: E402

def load_cases():
    cases = []
    for name in sorted(os.listdir(os.path.join(HERE, "attacks"))):
        if not name.endswith(".py"):
            continue
        spec = importlib.util.spec_from_file_location(name[:-3], os.path.join(HERE, "attacks", name))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cases.append(mod)
    order = lambda m: ("APSR".index(m.ID[0]), int("".join(c for c in m.ID.split("/")[0] if c.isdigit()) or 0))
    return sorted(cases, key=order)

# Many cases end in a timeout, so the suite shortens it while it runs and restores the normal value after.
TEST_TIMEOUT_MS = 4000
NORMAL_TIMEOUT_MS = 30000

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--mode", choices=["audit", "enforce"], action="append")
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    only = {x.upper() for x in a.only.split(",") if x}
    vm = VM()
    vm.set_consent_timeout(TEST_TIMEOUT_MS)
    try:
        results, failed = run(vm, a, only)
    finally:
        vm.set_consent_timeout(NORMAL_TIMEOUT_MS)
        vm.restart_provd("audit")
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "attacks.json"), "w") as f:
            json.dump({"info": vm.info(), "results": results}, f, indent=1, default=str)
    print(f"\n{len(results) - failed}/{len(results)} cases passed")
    sys.exit(1 if failed else 0)

def run(vm, a, only):
    results, failed = [], 0
    for mode in a.mode or ["audit", "enforce"]:
        vm.restart_provd(mode)
        print(f"== mode: {mode}")
        for case in load_cases():
            if only and case.ID.upper() not in only:
                continue
            t0 = time.time()
            try:
                ok, observed, detail = case.run(vm, mode)
            except Exception:
                ok, observed, detail = False, "harness error", {"traceback": traceback.format_exc()}
                print(detail["traceback"], file=sys.stderr)
            if vm.get_mode() != mode:
                vm.restart_provd(mode)
            time.sleep(1)  # let any queued hypervisor input drain before the next case opens a prompt
            failed += not ok
            results.append({"id": case.ID, "title": case.TITLE, "mode": mode, "expected": case.EXPECT[mode],
                            "observed": observed, "pass": ok, "seconds": round(time.time() - t0, 1), "detail": detail})
            print(f"{'PASS' if ok else 'FAIL'}  {case.ID:<6} {case.TITLE}\n        expected: {case.EXPECT[mode]}\n        observed: {observed}")
    return results, failed

if __name__ == "__main__":
    main()
