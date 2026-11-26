#!/usr/bin/env python3
"""Rebuild the result tables of docs/RESULTS.md and the report from the raw JSON of a run.

usage: summarize.py [DIR]      (default: results/2026-11-26, the recorded run)
Reads attacks.json, classify.json and bench.json from DIR (whichever exist) and prints Markdown.
Needs only Python 3; no VM, no root.
"""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIGS = ("unloaded", "audit", "enforce")

def load(d, name):
    p = os.path.join(d, name)
    return json.load(open(p)) if os.path.exists(p) else None

def attacks(a):
    by = {}
    for r in a["results"]:
        by.setdefault(r["id"], {})[r["mode"]] = r
    ok = sum(r["pass"] for r in a["results"])
    print(f"## Attack suite\n\n{ok}/{len(a['results'])} runs match their expected outcome.\n")
    print("| Case | Audit | Enforce | Expected (enforce) | Observed (enforce) |\n|---|---|---|---|---|")
    for cid, modes in by.items():
        mark = lambda m: ("pass" if modes[m]["pass"] else "**FAIL**") if m in modes else "-"
        e = modes.get("enforce", {})
        print(f"| {cid} | {mark('audit')} | {mark('enforce')} | {e.get('expected', '')} | {e.get('observed', '')} |")
    print()

def classify(c):
    classes = sorted({m["recorded"] for m in c["matrix"]} | {m["true"] for m in c["matrix"]})
    print(f"## Classification\n\nseed {c['seed']}, {c['uinput']} uinput + {c['uhid']} uhid devices "
          f"({c['spoofed']} copying a real identity), {c['hotplug_rounds']} hot-plug rounds.\n")
    print("| true \\ recorded | " + " | ".join(classes) + " |\n|---|" + "---|" * len(classes))
    for t in sorted({m["true"] for m in c["matrix"]}):
        cells = [str(sum(m["count"] for m in c["matrix"] if m["true"] == t and m["recorded"] == r)) for r in classes]
        print(f"| {t} | " + " | ".join(cells) + " |")
    checks = [("injected devices classed hardware", c["injected_as_hardware"], c["injected_as_hardware"] == 0),
              ("hardware devices classed otherwise", c["hardware_as_injected"], c["hardware_as_injected"] == 0),
              ("creator correct", f"{c['creator_correct']}/{c['creator_total']}",
               c["creator_correct"] == c["creator_total"]),
              ("stale records after removal", c["stale_records"], c["stale_records"] == 0),
              ("errors", len(c["errors"]), not c["errors"])]
    print("\n| Check | Value | Pass |\n|---|---|---|")
    for name, v, ok in checks:
        print(f"| {name} | {v} | {'yes' if ok else '**no**'} |")
    print(f"\nOverall: {'PASS' if c['pass'] else 'FAIL'}\n")

def fmt(v):
    return f"{v / 1e6:.2f}M" if v >= 1e5 else f"{v:.1f}"

def bench(b):
    cfg = b["configs"]
    print(f"## Overhead\n\nMedians over {b['runs']} runs; [q1, q3] in brackets.\n")
    print("| Metric | Unit | Unloaded | Audit | Enforce | Audit Δ | Enforce Δ |\n|---|---|---|---|---|---|---|")
    for name, base in cfg["unloaded"].items():
        cells, meds = [], []
        for c in CONFIGS:
            m = cfg[c].get(name)
            meds.append(m["median"] if m else float("nan"))
            cells.append(f"{fmt(m['median'])} [{fmt(m['q1'])}, {fmt(m['q3'])}]" if m else "-")
        d = [f"{(v / meds[0] - 1) * 100:+.0f}%" for v in meds[1:]]
        print(f"| `{name}` | {base['unit']} | " + " | ".join(cells) + f" | {d[0]} | {d[1]} |")
    print("\nPer-program kernel run time under a write-heavy load (`bpf_stats_enabled`):\n")
    print("| Program | Calls (audit) | avg ns (audit) | Calls (enforce) | avg ns (enforce) |\n|---|---|---|---|---|")
    ps = b["prog_stats"]
    for name in sorted(ps.get("enforce", {})):
        a, e = ps.get("audit", {}).get(name, {}), ps["enforce"][name]
        if not (a.get("run_cnt") or e.get("run_cnt")):
            continue
        print(f"| `{name}` | {a.get('run_cnt', '-')} | {a.get('avg_ns', '-')} | {e['run_cnt']} | {e['avg_ns']} |")
    print()

def main():
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "results", "2026-11-26")
    found = False
    for name, fn in (("attacks.json", attacks), ("classify.json", classify), ("bench.json", bench)):
        data = load(d, name)
        if data is not None:
            found = True
            print(f"<!-- {name}: kernel {data['info']['kernel']} -->")
            fn(data)
    if not found:
        sys.exit(f"no result files in {d}")

if __name__ == "__main__":
    main()
