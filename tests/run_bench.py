#!/usr/bin/env python3
"""Overhead measurements (SPEC 10.3) in three configurations: PROVE not loaded, audit, enforce.

usage: run_bench.py [--out DIR] [--runs N] [--quick]
Writes bench.json into DIR: every raw sample plus median / min / max / IQR per metric.
"""
import argparse, json, os, re, statistics, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from harness import VM, default_out  # noqa: E402

B = "/usr/libexec/prove-test"
FIO = ("fio --name=j --directory=/dev/shm --size=64M --ioengine=psync --runtime={rt} --time_based "
       "--output-format=json --rw={rw} --bs={bs} | python3 -c \"import json,sys; j=json.load(sys.stdin)['jobs'][0]; "
       "print(j['read']['iops']+j['write']['iops'])\"; rm -f /dev/shm/j.*")

def metrics(quick):
    n = 200_000 if quick else 1_000_000
    rt = 1 if quick else 3
    return [
        # name, unit, command (run as root), parser
        ("write_devnull", "ns/op", f"{B}/bench-write null {n}", float),
        ("read_devzero", "ns/op", f"{B}/bench-write read {n}", float),
        ("write_uinput", "ns/op", f"{B}/bench-write uinput {n}", float),
        ("pipe_roundtrip", "ns/op", f"{B}/bench-write pipe {n // 10}", float),
        ("input_latency_median", "ns", f"{B}/bench-latency {2000 if quick else 10000}", lambda s: float(s.split()[0])),
        ("register_median", "ns", f"{B}/bench-register {50 if quick else 200}", float),
        ("fio_seqwrite_512", "IOPS", FIO.format(rw="write", bs="512", rt=rt), float),
        ("fio_seqread_512", "IOPS", FIO.format(rw="read", bs="512", rt=rt), float),
        ("fio_randwrite_4k", "IOPS", FIO.format(rw="randwrite", bs="4k", rt=rt), float),
        ("fio_randread_4k", "IOPS", FIO.format(rw="randread", bs="4k", rt=rt), float),
    ]

def configure(vm, cfg):
    if cfg == "unloaded":
        rc, out = vm.sh("systemctl stop provd; provectl unload", sudo=True)
        assert rc == 0, out
    else:
        vm.restart_provd(cfg)

def prog_stats(vm, n=1_000_000):
    """Average run time of each PROVE program under a write()-heavy workload. The programs stay
    pinned across provd restarts, so their counters accumulate: report the difference between
    a snapshot taken before and one taken after the workload."""
    dump = "for p in /sys/fs/bpf/prove/prog_*; do bpftool -j prog show pinned $p; echo; done"
    def parse(out):
        return {j["name"]: (j.get("run_cnt", 0), j.get("run_time_ns", 0))
                for j in (json.loads(l) for l in out.splitlines() if l.startswith("{"))}
    _, out = vm.sh(f"sysctl -qw kernel.bpf_stats_enabled=1; {dump}", sudo=True)
    before = parse(out)
    _, out = vm.sh(f"{B}/bench-write null {n} >/dev/null; {B}/bench-write uinput {n // 10} >/dev/null; "
                   f"{B}/bench-register 100 >/dev/null; {dump}; sysctl -qw kernel.bpf_stats_enabled=0", sudo=True)
    stats = {}
    for name, (cnt, ns) in parse(out).items():
        c0, t0 = before.get(name, (0, 0))
        cnt, ns = cnt - c0, ns - t0
        stats[name] = {"run_cnt": cnt, "avg_ns": round(ns / cnt, 1) if cnt else None}
    return stats

def summarise(samples):
    q = statistics.quantiles(samples, n=4) if len(samples) >= 4 else [min(samples), statistics.median(samples), max(samples)]
    return {"median": statistics.median(samples), "min": min(samples), "max": max(samples), "q1": q[0], "q3": q[2],
            "n": len(samples)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=default_out())
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    vm = VM()
    result = {"info": vm.info(), "runs": a.runs, "configs": {}, "prog_stats": {}}
    try:
        for cfg in ("unloaded", "audit", "enforce"):
            configure(vm, cfg)
            samples = {name: [] for name, *_ in metrics(a.quick)}
            for run in range(a.runs):
                for name, unit, cmd, parse in metrics(a.quick):
                    rc, out = vm.sh(cmd, sudo=True, timeout=300)
                    try:
                        samples[name].append(parse(out.strip().splitlines()[-1]))
                    except Exception:
                        print(f"!! {cfg}/{name}: {out.strip()[-200:]}", file=sys.stderr)
                print(f"{cfg}: run {run + 1}/{a.runs} done", flush=True)
            result["configs"][cfg] = {name: {"unit": unit, "samples": samples[name], **summarise(samples[name])}
                                      for name, unit, *_ in metrics(a.quick) if samples[name]}
            if cfg != "unloaded":
                result["prog_stats"][cfg] = prog_stats(vm, 200_000 if a.quick else 1_000_000)
    finally:
        vm.restart_provd("audit")

    base = result["configs"]["unloaded"]
    print(f"\n{'metric':<24}{'unit':<8}{'unloaded':>12}{'audit':>12}{'enforce':>12}{'audit %':>9}{'enforce %':>10}")
    for name, m in base.items():
        row = [result["configs"][c].get(name, {}).get("median", float("nan")) for c in ("unloaded", "audit", "enforce")]
        pct = [(v / row[0] - 1) * 100 for v in row[1:]]
        print(f"{name:<24}{m['unit']:<8}{row[0]:>12.1f}{row[1]:>12.1f}{row[2]:>12.1f}{pct[0]:>+8.1f}%{pct[1]:>+9.1f}%")
    for cfg, stats in result["prog_stats"].items():
        print(f"\nper-program run time ({cfg}):")
        for name, s in sorted(stats.items()):
            print(f"  {name:<20} runs={s['run_cnt']:<9} avg={s['avg_ns']} ns")
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "bench.json"), "w") as f:
            json.dump(result, f, indent=1)

if __name__ == "__main__":
    main()
