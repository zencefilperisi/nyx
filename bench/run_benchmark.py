#!/usr/bin/env python3
"""
Nyx benchmark harness (FuzzBench-style).
========================================

Runs several fuzzers against the SAME instrumented target for a fixed time
budget, repeated over N independent trials, and records edge coverage and
unique crashes over time. The point is a FAIR, REPRODUCIBLE comparison with
statistical backing -- not a single cherry-picked run.

Fuzzers compared:
    - nyx        (this project: structure-aware + entropy-guided)
    - nyx-uniform(ablation: structure-aware, entropy scheduler OFF)
    - libfuzzer  (in-process baseline)
    - aflpp      (SOTA general fuzzer)
    - nautilus   (grammar-based -- the direct competitor)

Methodology:
    * fixed wall-clock budget per trial (default 24h; use --seconds for smoke)
    * N trials per fuzzer (default 10) with different seeds
    * report median coverage with 95% CI, and a Mann-Whitney U test between
      nyx and each baseline (significance of the difference)

This file is the orchestration skeleton; per-fuzzer adapters are added in Phase 4.
"""

import argparse
import json
import statistics
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

FUZZERS = ["nyx", "nyx-uniform", "libfuzzer", "aflpp", "nautilus"]


@dataclass
class TrialResult:
    fuzzer: str
    trial: int
    seconds: int
    edges_over_time: list = field(default_factory=list)  # (t, edge_count)
    unique_crashes: int = 0
    time_to_first_crash: float | None = None


def run_trial(fuzzer: str, target: Path, corpus: Path, seconds: int,
              trial: int, out_dir: Path) -> TrialResult:
    """Run one fuzzer for `seconds` and collect its coverage/crash timeline.

    TODO(phase-4): dispatch to the per-fuzzer adapter that knows how to launch
    it against `target`, poll coverage, and harvest crashes. For nyx this shells
    out to the nyx binary; for the baselines to their standard CLIs.
    """
    raise NotImplementedError(f"adapter for {fuzzer} not implemented yet")


def summarize(results: list[TrialResult]) -> dict:
    """Median final coverage + spread per fuzzer (CI and Mann-Whitney in Phase 4)."""
    summary = {}
    by_fuzzer: dict[str, list[int]] = {}
    for r in results:
        final = r.edges_over_time[-1][1] if r.edges_over_time else 0
        by_fuzzer.setdefault(r.fuzzer, []).append(final)
    for fuzzer, finals in by_fuzzer.items():
        summary[fuzzer] = {
            "trials": len(finals),
            "median_edges": statistics.median(finals) if finals else 0,
            "mean_edges": statistics.mean(finals) if finals else 0,
            "stdev": statistics.pstdev(finals) if len(finals) > 1 else 0.0,
        }
    return summary


def main():
    ap = argparse.ArgumentParser(description="Nyx fuzzer benchmark")
    ap.add_argument("--target", required=True, type=Path)
    ap.add_argument("--corpus", required=True, type=Path)
    ap.add_argument("--seconds", type=int, default=86400, help="budget per trial")
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--fuzzers", nargs="+", default=FUZZERS, choices=FUZZERS)
    ap.add_argument("--out", type=Path, default=Path("bench_results"))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    all_results: list[TrialResult] = []
    for fuzzer in args.fuzzers:
        for trial in range(args.trials):
            print(f"[bench] {fuzzer} trial {trial+1}/{args.trials} "
                  f"({args.seconds}s)")
            try:
                res = run_trial(fuzzer, args.target, args.corpus,
                                args.seconds, trial, args.out)
                all_results.append(res)
            except NotImplementedError as e:
                print(f"  skipped: {e}")

    summary = summarize(all_results)
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
