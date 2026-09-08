"""ScamShield Research Evaluation Lab — CLI entry point.

Run the full evaluation:

    python -m app.research_eval
    python -m app.research_eval --json
    python -m app.research_eval --output-dir models/research
    python -m app.research_eval --skip-latency
    python -m app.research_eval --iterations 30

All evaluation is completely local (no network) and deterministic.
Output artefacts are written under models/research/ by default.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from scamshield.research.runner import run_full_evaluation, write_artifacts  # noqa: E402


def _print_summary(summary: dict) -> None:
    """Print a human-readable summary to stdout."""
    print("=" * 70)
    print("  SCAMSHIELD RESEARCH EVALUATION LAB")
    print("=" * 70)
    print()

    profile = summary.get("dataset_profile", {})
    raw  = profile.get("raw_counts", {})
    dedup = profile.get("deduped_counts", {})
    print("DATASET PROFILE")
    print(f"  Raw rows       : train={raw.get('train',0)}, val={raw.get('validation',0)}, "
          f"test={raw.get('test',0)}, total={raw.get('total',0)}")
    print(f"  Deduped rows   : train={dedup.get('train',0)}, val={dedup.get('validation',0)}, "
          f"test={dedup.get('test',0)}, total={dedup.get('total',0)}")
    test_p = profile.get("test", {})
    dist = test_p.get("distribution", {})
    print(f"  Test set (n={test_p.get('n',0)}): scam={dist.get('scam',0)}, safe={dist.get('safe',0)}")
    print()

    leakage = summary.get("leakage", {})
    totals  = leakage.get("totals", {})
    print("LEAKAGE AUDIT")
    print(f"  Normalised overlap : {totals.get('normalised', 0)} text(s)")
    print(f"  Exact overlap      : {totals.get('exact', 0)} text(s)")
    print(f"  Affected pairs     : {leakage.get('affected_split_pairs', [])}")
    print()

    comparison = summary.get("comparison", [])
    print("SYSTEM COMPARISON (frozen deduped test set)")
    print(f"  {'System':<25} {'Acc':>6} {'Prec':>6} {'Rec':>6} {'F1':>6} {'n':>5}")
    print("  " + "-" * 56)
    for row in comparison:
        name = row.get("system", "")
        acc  = row.get("accuracy")
        pre  = row.get("precision")
        rec  = row.get("recall")
        f1   = row.get("f1")
        n    = row.get("n_samples", 0)
        acc_s  = f"{acc:.4f}"  if acc is not None else "N/A"
        pre_s  = f"{pre:.4f}"  if pre is not None else "N/A"
        rec_s  = f"{rec:.4f}"  if rec is not None else "N/A"
        f1_s   = f"{f1:.4f}"   if f1  is not None else "N/A"
        print(f"  {name:<25} {acc_s:>6} {pre_s:>6} {rec_s:>6} {f1_s:>6} {n:>5}")
    print()

    latency = summary.get("latency", {})
    engines = latency.get("engines", {})
    if engines:
        print(f"DETECTION LATENCY ({latency.get('iterations',0)} iterations)")
        for name, stats in engines.items():
            print(f"  {name:<20}: mean={stats['mean_ms']:.3f}ms  "
                  f"median={stats['median_ms']:.3f}ms  "
                  f"min={stats['min_ms']:.3f}ms  max={stats['max_ms']:.3f}ms")
        print()

    rule_res = summary.get("rule_engine", {})
    fn_count = rule_res.get("fn_count", 0)
    fp_count = rule_res.get("fp_count", 0)
    print(f"MISCLASSIFICATION SUMMARY (Rule Engine)")
    print(f"  False negatives (missed scams) : {fn_count}")
    print(f"  False positives (safe flagged)  : {fp_count}")
    print()

    lc = summary.get("leakage_clean_combined", {})
    lc_note = lc.get("note", "")
    if lc_note:
        print("LEAKAGE-CLEAN EVALUATION")
        print(f"  {lc_note}")
        lc_m = lc.get("metrics", {})
        if lc_m:
            print(f"  accuracy={lc_m.get('accuracy','?')}  precision={lc_m.get('precision','?')}  "
                  f"recall={lc_m.get('recall','?')}  F1={lc_m.get('f1','?')}")
        print()

    print("=" * 70)
    print("  Evaluation complete. Artefacts written to models/research/")
    print("=" * 70)


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    parser = argparse.ArgumentParser(
        description="ScamShield Research Evaluation Lab",
    )
    parser.add_argument("--json", action="store_true",
                        help="print the full evaluation summary as JSON")
    parser.add_argument("--output-dir", default="models/research",
                        help="directory for artefact files (default: models/research)")
    parser.add_argument("--data-root", default="data",
                        help="root directory for dataset splits (default: data)")
    parser.add_argument("--skip-latency", action="store_true",
                        help="skip latency measurement (faster run)")
    parser.add_argument("--iterations", type=int, default=20,
                        help="iterations per engine for latency (default 20)")
    args = parser.parse_args(argv)

    t0 = time.perf_counter()
    summary = run_full_evaluation(
        data_root=args.data_root,
        include_latency=not args.skip_latency,
        latency_iterations=args.iterations,
    )
    elapsed = time.perf_counter() - t0

    write_artifacts(summary, args.output_dir)

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
    else:
        _print_summary(summary)
        print(f"\nCompleted in {elapsed:.1f}s (models/research/)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
