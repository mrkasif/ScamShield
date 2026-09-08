"""Research evaluation runner and artifact writer.

Orchestrates a full evaluation pass across all systems, stratifications,
leakage audit, latency measurement and FP / FN analysis. Results are written
as machine-readable JSON, CSV and human-readable Markdown under
``models/research/``.

No network, no model changes, no dataset mutations.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from .datasets import load_dataset
from .leakage import audit_leakage, leakage_clean_records
from .evaluate import (
    evaluate_rule, evaluate_ml, evaluate_combined, build_comparison_table,
)
from .stratified import by_language, by_category
from .latency import measure_latencies
from .sanitize import sanitize_text

DEFAULT_OUTPUT_DIR = Path("models/research")


# ---------------------------------------------------------------------------
# Artifact writers
# ---------------------------------------------------------------------------

def _write_json(data: dict, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, default=str)


def _write_csv(rows: list[dict], path: Path) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_markdown(text: str, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def _build_markdown_report(summary: dict) -> str:
    """Build a human-readable Markdown evaluation report from the summary dict."""
    lines: list[str] = []
    now = summary.get("timestamp", "")
    lines.append("# ScamShield Research Evaluation Report\n")
    lines.append(f"- **Generated**: {now}")
    lines.append(f"- **Random seed**: N/A (deterministic, no stochastic process)")
    lines.append("")

    # --- dataset profile ---
    profile = summary.get("dataset_profile", {})
    raw  = profile.get("raw_counts", {})
    dedup = profile.get("deduped_counts", {})
    lines.append("## 1. Dataset Profile\n")
    lines.append(f"| Split | Raw rows | Deduplicated rows |")
    lines.append(f"|-------|---------|-------------------|")
    for split in ("train", "validation", "test"):
        lines.append(f"| {split.title()} | {raw.get(split, 0)} | {dedup.get(split, 0)} |")
    lines.append(f"| **Total** | **{raw.get('total',0)}** | **{dedup.get('total',0)}** |")
    lines.append("")

    test_profile = profile.get("test", {})
    dist = test_profile.get("distribution", {})
    lines.append(f"**Test set (deduped, n={test_profile.get('n',0)})**")
    lines.append(f"- scam: {dist.get('scam',0)} | safe: {dist.get('safe',0)}")
    langs = test_profile.get("languages", {})
    lines.append(f"- languages: {langs}")
    cats = {k: v for k, v in test_profile.get("categories", {}).items() if k != "safe"}
    lines.append(f"- scam categories: {cats}")
    lines.append("")

    # --- leakage ---
    leakage = summary.get("leakage", {})
    totals = leakage.get("totals", {})
    lines.append("## 2. Leakage Audit\n")
    lines.append(f"- **Normalised texts in multiple splits**: {totals.get('normalised', 0)}")
    lines.append(f"- **Exact texts in multiple splits**: {totals.get('exact', 0)}")
    lines.append(f"- **Overlap type**: {leakage.get('overlap_type', 'unknown')}")
    lines.append(f"- **Affected pairs**: {leakage.get('affected_split_pairs', [])}")
    lines.append(f"- **Recommendation**: {leakage.get('recommendation', '')}")
    lines.append("")

    # --- system comparison ---
    comparison = summary.get("comparison", [])
    lines.append("## 3. System Comparison (frozen test set)\n")
    lines.append("| System | Accuracy | Precision | Recall | F1 | n |")
    lines.append("|--------|----------|-----------|--------|----|---|")
    for row in comparison:
        acc = row.get("accuracy")
        pre = row.get("precision")
        rec = row.get("recall")
        f1  = row.get("f1")
        n   = row.get("n_samples", 0)
        name = row.get("system", "")
        acc_s  = f"{acc:.4f}"  if acc is not None else "N/A"
        pre_s  = f"{pre:.4f}"  if pre is not None else "N/A"
        rec_s  = f"{rec:.4f}"  if rec is not None else "N/A"
        f1_s   = f"{f1:.4f}"   if f1  is not None else "N/A"
        lines.append(f"| {name} | {acc_s} | {pre_s} | {rec_s} | {f1_s} | {n} |")
    lines.append("")

    # positive prediction docs
    rule_res  = summary.get("rule_engine", {})
    ml_res    = summary.get("ml", {})
    comb_res  = summary.get("combined", {})
    lines.append("**Positive prediction definitions**:\n")
    lines.append(f"- Rule: {rule_res.get('prediction_documentation', '')}")
    lines.append(f"- ML:   {ml_res.get('prediction_documentation', '')}")
    lines.append(f"- Combined: {comb_res.get('prediction_documentation', '')}")
    lines.append("")

    # leakage clean
    lc = summary.get("leakage_clean_combined", {})
    lc_note = lc.get("note", "")
    lc_m = lc.get("metrics", {})
    lines.append("## 4. Leakage-Clean Combined Evaluation\n")
    if lc_note:
        lines.append(f"- {lc_note}")
    if lc_m:
        lines.append(f"- n = {lc_m.get('n_samples', '?')}")
        lines.append(f"- accuracy = {lc_m.get('accuracy','?')}, precision = {lc_m.get('precision','?')}, recall = {lc_m.get('recall','?')}, F1 = {lc_m.get('f1','?')}")
        cm = lc_m.get("confusion_matrix", {})
        lines.append(f"- TP={cm.get('true_positive',0)} FN={cm.get('false_negative',0)} FP={cm.get('false_positive',0)} TN={cm.get('true_negative',0)}")
    lines.append("")

    # --- latency ---
    latency = summary.get("latency", {})
    lines.append("## 5. Detection Latency\n")
    lines.append(f"- Iterations per engine: {latency.get('iterations', 0)}")
    engines = latency.get("engines", {})
    for name, stats in engines.items():
        lines.append(
            f"- **{name}**: mean={stats['mean_ms']:.3f}ms, "
            f"median={stats['median_ms']:.3f}ms, "
            f"min={stats['min_ms']:.3f}ms, "
            f"max={stats['max_ms']:.3f}ms"
        )
    lines.append("")

    # --- language stratification ---
    lang_results = summary.get("language_results", {})
    lines.append("## 6. Per-Language Evaluation (Combined)\n")
    if lang_results.get("available"):
        for lang, data in lang_results.get("languages", {}).items():
            m = data.get("metrics")
            n = data.get("n", 0)
            if m:
                lines.append(
                    f"- **{lang}** (n={n}): accuracy={m['accuracy']}, "
                    f"precision={m['precision']}, recall={m['recall']}, F1={m['f1']}"
                )
            else:
                lines.append(f"- **{lang}** (n={n}): insufficient samples")
    lines.append("")

    # --- category stratification ---
    cat_results = summary.get("category_results", {})
    lines.append("## 7. Per-Category Evaluation (Combined, one-vs-rest)\n")
    if cat_results.get("available"):
        cats_data = cat_results.get("categories", {})
        if cats_data:
            lines.append("| Category | n | Accuracy | Precision | Recall | F1 |")
            lines.append("|----------|---|----------|-----------|--------|----|")
            for cat, data in cats_data.items():
                cm = data.get("confusion", {})
                lines.append(
                    f"| {cat} | {data['n']} | {data['accuracy']} | "
                    f"{data['precision']} | {data['recall']} | {data['f1']} |"
                )
        else:
            lines.append("*No category has enough samples for per-category metrics.*")
    lines.append("")

    # --- FP / FN examples ---
    rule_fn = rule_res.get("fn_examples", [])
    rule_fp = rule_res.get("fp_examples", [])
    lines.append("## 8. Representative Misclassified Examples (Rule Engine)\n")
    if rule_fn:
        lines.append(f"### False Negatives ({rule_res.get('fn_count',0)} total)\n")
        for ex in rule_fn[:5]:
            lines.append(f"- `{ex.get('id','')}` [{ex.get('label','')}→{ex.get('predicted','')}] lang={ex.get('language','')} scam_type={ex.get('scam_type','')}")
            lines.append(f"  > {ex.get('excerpt','')}")
        lines.append("")
    if rule_fp:
        lines.append(f"### False Positives ({rule_res.get('fp_count',0)} total)\n")
        for ex in rule_fp[:5]:
            lines.append(f"- `{ex.get('id','')}` [{ex.get('label','')}→{ex.get('predicted','')}] lang={ex.get('language','')}")
            lines.append(f"  > {ex.get('excerpt','')}")
    if not rule_fn and not rule_fp:
        lines.append("*No misclassified examples.*")
    lines.append("")

    # --- limitations ---
    lines.append("## 9. Limitations and Research Integrity Notes\n")
    lines.append("- The labelled dataset is synthetic (template-generated) and a small public "
                 "sample — evaluation numbers do not generalise to production traffic.")
    lines.append("- Cross-split normalised leakage means held-out metrics are somewhat optimistic.")
    lines.append("- The rule engine is deliberately conservative; its design favours recall "
                 "(catching scams) over precision and may produce more false positives.")
    lines.append("- The ML model is trained on a tiny, class-imbalanced dataset; its reported "
                 "metrics are not reliable indicators of production performance.")
    lines.append("- URL reputation / DNS / live content analysis are out of scope; the URL engine "
                 "is static and structural only.")
    lines.append("- QR decoding depends on the local cv2 backend; QR latency varies by image.")
    lines.append("- No live threat intelligence or external APIs are used anywhere in the pipeline.")
    lines.append("- Language stratification results are indicative only; per-language sample sizes "
                 "are small and should not be extrapolated.")
    lines.append("- The combined ScamShield message verdict is driven entirely by the deterministic "
                 "rule engine by design; ML is kept separate under engine_results and does not alter "
                 "the top-level verdict.")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_full_evaluation(
    *,
    data_root: str = "data",
    model_path: str | None = None,
    include_latency: bool = True,
    latency_iterations: int = 20,
    max_fp_fn_examples: int = 8,
    min_category_samples: int = 5,
    min_language_samples: int = 5,
) -> dict:
    """Run a complete evaluation pass and return the summary dict.

    All artefacts are computed in memory. Call ``write_artifacts()`` separately
    to persist them. No network, no dataset mutations.

    Returns a fully JSON-serialisable dict with all evaluation results.
    """
    # --- 1. Dataset ---
    ds = load_dataset(data_root)
    test_records  = ds["test"]
    train_records = ds["train"]
    valid_records = ds["validation"]

    # --- 2. Leakage ---
    leakage_raw = load_dataset(data_root)  # reuse for raw counts only
    leakage = audit_leakage(
        leakage_raw["train_raw"], leakage_raw["validation_raw"], leakage_raw["test_raw"],
    )

    # --- 3. System evaluation ---
    rule_result   = evaluate_rule(test_records, max_examples=max_fp_fn_examples)
    ml_result     = evaluate_ml(test_records, model_path=model_path,
                                max_examples=max_fp_fn_examples)
    combined_result = evaluate_combined(test_records, max_examples=max_fp_fn_examples)

    # --- 4. Comparison ---
    comparison = build_comparison_table(rule_result, ml_result, combined_result)

    # --- 5. Leakage-clean combined ---
    lc_test = leakage_clean_records(test_records, train_records, valid_records)
    lc_combined: dict = {}
    if len(lc_test) < len(test_records):
        lc_combined = evaluate_combined(lc_test, max_examples=0)
        lc_combined["n_original_test"] = len(test_records)
        lc_combined["n_leakage_clean"] = len(lc_test)
        lc_combined["n_excluded"]      = len(test_records) - len(lc_test)
        lc_combined["note"] = (
            f"Leakage-clean subset: {len(lc_test)} of {len(test_records)} test "
            f"samples retained ({len(test_records)-len(lc_test)} excluded because "
            "their normalised text appeared in train or validation)."
        )
    else:
        lc_combined["note"] = (
            "No leakage-clean exclusion applied — no normalised text in test "
            "also appeared in train or validation."
        )
        lc_combined["metrics"] = combined_result
        lc_combined["n_original_test"] = len(test_records)
        lc_combined["n_leakage_clean"] = len(test_records)
        lc_combined["n_excluded"] = 0

    # --- 6. Stratification ---
    combined_predictions: list[str] = []
    for rec in test_records:
        from ..analyzer import analyze as _analyze
        res = _analyze("message", rec["text"])
        combined_predictions.append("scam" if res.get("is_suspicious") else "safe")

    lang_results = by_language(test_records, combined_predictions,
                               min_samples=min_language_samples)
    cat_results  = by_category(test_records, combined_predictions,
                               min_samples=min_category_samples)

    # --- 7. Latency ---
    latency: dict = {}
    if include_latency:
        latency = measure_latencies(iterations=latency_iterations)

    # --- 8. Assemble ---
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reproducibility": {
            "random_seed": "N/A (deterministic, no stochastic process)",
            "test_split": f"data/test/messages.csv (frozen, deduped: {len(test_records)} samples)",
            "dataset_root": data_root,
            "note": (
                "All evaluation is deterministic and run on the labelled dataset. "
                "No random processes, no stochastic training, no external network "
                "calls. Same inputs produce same outputs."
            ),
        },
        "dataset_profile": ds["profile"],
        "leakage": leakage,
        "rule_engine": rule_result,
        "ml": ml_result,
        "combined": combined_result,
        "comparison": comparison,
        "leakage_clean_combined": lc_combined,
        "language_results": lang_results,
        "category_results": cat_results,
        "latency": latency,
        "limitations": {
            "dataset_synthetic": (
                "The labelled dataset is synthetic (template-generated) and "
                "includes a small public sample. Evaluation numbers do not "
                "generalise to production traffic."
            ),
            "cross_split_leakage": (
                "Normalised text leakage across splits inflates held-out "
                "metrics. A leakage-clean evaluation is provided separately."
            ),
            "class_imbalance": "Test set is imbalanced (more scam than safe).",
            "ml_training_size": (
                "ML model trained on ~285 samples — too small for reliable "
                "generalisation."
            ),
            "rule_coverage": (
                "The rule engine is conservative by design and favours recall "
                "over precision; it may produce more false positives."
            ),
            "url_static_only": (
                "URL engine is structural/static only — no reputation, DNS, "
                "or content analysis."
            ),
            "qr_decode_dependency": "QR decode depends on local cv2 backend.",
            "no_live_threat_intel": (
                "No external threat intelligence or APIs are used anywhere."
            ),
            "combined_is_rule_driven": (
                "On message inputs, the combined ScamShield verdict is driven "
                "by the deterministic rule engine; ML does not alter the "
                "top-level is_suspicious. The combined result is expected to "
                "match the rule engine on the message benchmark by design."
            ),
        },
    }
    return summary


def write_artifacts(summary: dict, out_dir: str | Path = DEFAULT_OUTPUT_DIR) -> Path:
    """Write all evaluation artefacts to the given output directory.

    Creates ``{out_dir}/`` with:
        - evaluation_summary.json
        - model_comparison.csv
        - confusion_matrices.json
        - language_results.json
        - category_results.json
        - leakage_report.json
        - latency_results.json
        - fp_fn_examples.json
        - evaluation_report.md

    Returns the output directory path.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    _write_json(summary, out / "evaluation_summary.json")
    _write_csv(summary.get("comparison", []), out / "model_comparison.csv")
    _write_json({
        "rule_engine": summary.get("rule_engine", {}).get("confusion_matrix"),
        "ml": summary.get("ml", {}).get("confusion_matrix"),
        "combined": summary.get("combined", {}).get("confusion_matrix"),
        "leakage_clean_combined": summary.get("leakage_clean_combined", {}).get("metrics", {}).get("confusion_matrix"),
    }, out / "confusion_matrices.json")
    _write_json(summary.get("language_results", {}), out / "language_results.json")
    _write_json(summary.get("category_results", {}), out / "category_results.json")
    _write_json(summary.get("leakage", {}), out / "leakage_report.json")
    _write_json(summary.get("latency", {}), out / "latency_results.json")
    _write_json({
        "rule_engine": {
            "fp_examples": summary.get("rule_engine", {}).get("fp_examples", []),
            "fn_examples": summary.get("rule_engine", {}).get("fn_examples", []),
            "fp_count": summary.get("rule_engine", {}).get("fp_count", 0),
            "fn_count": summary.get("rule_engine", {}).get("fn_count", 0),
        },
        "combined": {
            "fp_examples": summary.get("combined", {}).get("fp_examples", []),
            "fn_examples": summary.get("combined", {}).get("fn_examples", []),
            "fp_count": summary.get("combined", {}).get("fp_count", 0),
            "fn_count": summary.get("combined", {}).get("fn_count", 0),
        },
    }, out / "fp_fn_examples.json")
    _write_markdown(_build_markdown_report(summary), out / "evaluation_report.md")

    return out
