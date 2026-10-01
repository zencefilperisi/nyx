#!/usr/bin/env python3
"""
Analyse a Nyx benchmark run and produce statistics + a coverage-over-time plot.

The C++ `bench_runner` (built against an instrumented target) writes two CSVs:
    summary.csv   mode,trial,final_edges,crashes,iters
    timeline.csv  mode,trial,iter,edges

This script reads them and reports, per mode, the median/mean/spread of final
edge coverage; runs a one-sided Mann-Whitney U test between modes (is the
difference significant, not noise?); and plots the median coverage curve with an
interquartile band per mode.

Usage:
    python bench/run_benchmark.py --in bench_results --out bench/results
"""
import argparse
import csv
import statistics as st
from collections import defaultdict
from pathlib import Path

MODES = ["byte", "uniform", "entropy"]
LABEL = {
    "byte": "byte-level",
    "uniform": "structure-aware (uniform)",
    "entropy": "structure-aware (entropy)",
}
COLOR = {"byte": "#888888", "uniform": "#5b8cff", "entropy": "#00b894"}


def load_finals(path):
    finals = defaultdict(list)
    with open(path) as f:
        for r in csv.DictReader(f):
            finals[r["mode"]].append(int(r["final_edges"]))
    return finals


def load_timeline(path):
    tl = defaultdict(lambda: defaultdict(list))
    with open(path) as f:
        for r in csv.DictReader(f):
            tl[r["mode"]][int(r["iter"])].append(int(r["edges"]))
    return tl


def report(finals):
    print("=== Final edge coverage ===")
    for m in MODES:
        if not finals.get(m):
            continue
        v = finals[m]
        print(f"  {LABEL[m]:<30} median={st.median(v):.0f}  mean={st.mean(v):.1f}"
              f"  sd={st.pstdev(v):.1f}  n={len(v)}")

    try:
        from scipy.stats import mannwhitneyu
    except ImportError:
        print("\n(scipy not installed; skipping significance tests)")
        return

    def mw(a, b):
        return mannwhitneyu(finals[a], finals[b], alternative="greater").pvalue

    print("\n=== Mann-Whitney U (one-sided: row reaches more coverage) ===")
    if finals.get("uniform") and finals.get("byte"):
        print(f"  structure-aware(uniform) > byte-level : p = {mw('uniform','byte'):.4g}")
    if finals.get("entropy") and finals.get("byte"):
        print(f"  structure-aware(entropy) > byte-level : p = {mw('entropy','byte'):.4g}")
    if finals.get("entropy") and finals.get("uniform"):
        print(f"  structure-aware(entropy) > uniform    : p = {mw('entropy','uniform'):.4g}")


def plot(tl, out_png):
    try:
        import numpy as np
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib/numpy not installed; skipping plot)")
        return
    plt.figure(figsize=(8, 5))
    for m in MODES:
        if m not in tl:
            continue
        iters = sorted(tl[m])
        med = [st.median(tl[m][i]) for i in iters]
        lo = [np.percentile(tl[m][i], 25) for i in iters]
        hi = [np.percentile(tl[m][i], 75) for i in iters]
        plt.plot(iters, med, label=LABEL[m], color=COLOR[m], linewidth=2)
        plt.fill_between(iters, lo, hi, color=COLOR[m], alpha=0.15)
    plt.xlabel("iterations")
    plt.ylabel("edge coverage (median of trials)")
    plt.title("Nyx: coverage over time")
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_png, dpi=120)
    print(f"\nplot -> {out_png}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", default="bench_results")
    ap.add_argument("--out", dest="outdir", default="bench/results")
    args = ap.parse_args()
    indir, outdir = Path(args.indir), Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    finals = load_finals(indir / "summary.csv")
    report(finals)
    plot(load_timeline(indir / "timeline.csv"), str(outdir / "coverage.png"))


if __name__ == "__main__":
    main()
