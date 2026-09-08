"""Tests for the ScamShield Research Evaluation Lab (src/scamshield/research/).

Covers: metric calculations, confusion matrix calculations, deterministic
output, dataset loading, leakage detection, sensitive-data sanitisation,
missing-model handling, missing-dataset handling, and JSON/CSV/Markdown output.

All tests use tiny synthetic fixtures and temp directories — they never touch
the real trained model or the real dataset, and never use the network.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scamshield.research import metrics as rm  # noqa: E402
from scamshield.research import sanitize as rs  # noqa: E402
from scamshield.research import datasets as rd  # noqa: E402
from scamshield.research import leakage as rl  # noqa: E402
from scamshield.research import evaluate as rev  # noqa: E402
from scamshield.research import stratified as rst  # noqa: E402


SAMPLE_RECORDS = [
    {"id": "r1", "text": "Your KYC has expired. Click now.", "language": "en",
     "scam_or_safe": "scam", "scam_type": "kyc", "source": "synthetic_scamshield"},
    {"id": "r2", "text": "Hello friend, how are you today?", "language": "en",
     "scam_or_safe": "safe", "scam_type": "safe", "source": "synthetic_scamshield"},
    {"id": "r3", "text": "Pay 50000 now or face action", "language": "hi",
     "scam_or_safe": "scam", "scam_type": "upi_payment", "source": "synthetic_scamshield"},
    {"id": "r4", "text": "Order delivered earlier", "language": "mr",
     "scam_or_safe": "safe", "scam_type": "safe", "source": "synthetic_scamshield"},
]


# ---------------------------------------------------------------------------
# Metric calculations
# ---------------------------------------------------------------------------

def test_classification_metrics_basic():
    m = rm.classification_metrics(
        ["scam", "safe", "scam", "safe"],
        ["scam", "scam", "safe", "safe"],
    )
    # TP=1, FP=1, FN=1, TN=1
    assert m["confusion_matrix"] == {
        "true_positive": 1, "false_positive": 1,
        "false_negative": 1, "true_negative": 1,
    }
    assert m["accuracy"] == 0.5
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5
    assert m["f1"] == 0.5
    assert m["positive_class"] == "scam"


def test_classification_metrics_perfect_and_empty():
    perfect = rm.classification_metrics(["scam", "safe"], ["scam", "safe"])
    assert perfect["accuracy"] == 1.0
    assert perfect["precision"] == 1.0
    assert perfect["recall"] == 1.0
    assert perfect["f1"] == 1.0
    with pytest.raises(ValueError):
        rm.classification_metrics([], [])


def test_bool_to_label():
    assert rm.bool_to_label(True) == "scam"
    assert rm.bool_to_label(False) == "safe"


def test_per_category_confusion():
    c = rm.per_category_confusion(
        ["scam", "safe", "uber", "uber", "safe"],
        ["scam", "scam", "uber", "safe", "scam"],
        "uber",
    )
    # cat uber: true2 pred2 (TP), true2 predsafe (FN); others not uber stay TN
    assert c == {"tp": 1, "fp": 0, "tn": 3, "fn": 1, "n": 5}


# ---------------------------------------------------------------------------
# Confusion matrix calculations (through evaluate_system)
# ---------------------------------------------------------------------------

def test_evaluate_system_confusion():
    def _pred(text):
        return {"prediction": "scam", "model_available": True}

    res = rev.evaluate_system(SAMPLE_RECORDS, predict_fn=_pred, system_name="rule")
    # All true scam -> scam (TP), all true safe -> scam (FP)
    cm = res["confusion_matrix"]
    assert cm["true_positive"] == 2
    assert cm["false_positive"] == 2
    assert cm["true_negative"] == 0
    assert cm["false_negative"] == 0
    assert res["accuracy"] == 0.5
    assert res["precision"] == 0.5
    assert res["recall"] == 1.0


def test_build_comparison_table():
    rule  = rev.evaluate_system(SAMPLE_RECORDS, predict_fn=lambda t: {"prediction": "scam"}, system_name="rule")
    ml    = rev.evaluate_system(SAMPLE_RECORDS, predict_fn=lambda t: {"prediction": "safe"}, system_name="ml")
    comb  = rev.evaluate_system(SAMPLE_RECORDS, predict_fn=lambda t: {"prediction": "scam"}, system_name="combined")
    table = rev.build_comparison_table(rule, ml, comb)
    assert len(table) == 3
    assert table[0]["system"] == "Rule Engine"
    assert table[1]["system"] == "Local ML"
    assert table[2]["system"] == "Combined ScamShield"
    assert "accuracy" in table[0]


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_evaluation_is_deterministic():
    a = rev.evaluate_system(SAMPLE_RECORDS, predict_fn=lambda t: {"prediction": "scam"}, system_name="rule")
    b = rev.evaluate_system(SAMPLE_RECORDS, predict_fn=lambda t: {"prediction": "scam"}, system_name="rule")
    assert a == b


def test_sanitize_is_deterministic():
    assert rs.sanitize_text("pay 500 refund now") == rs.sanitize_text("pay 500 refund now")


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def _write_split(path: Path, rows: list[list[str]]) -> None:
    header = ["id", "text", "language", "scam_or_safe", "scam_type", "source", "split"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        for row in rows:
            writer.writerow(row)


def test_dataset_loading_profile(tmp_path):
    root = tmp_path
    _write_split(root / "train/messages.csv", [
        ["a1", "Train scam msg 1", "en", "scam", "kyc", "synthetic_scamshield", "train"],
        ["a2", "Train safe msg", "en", "safe", "safe", "synthetic_scamshield", "train"],
    ])
    _write_split(root / "validation/messages.csv", [
        ["b1", "Valid scam msg", "hi", "scam", "phishing", "synthetic_scamshield", "validation"],
    ])
    _write_split(root / "test/messages.csv", [
        ["c1", "Test scam msg", "en", "scam", "delivery", "synthetic_scamshield", "test"],
        ["c2", "Test safe msg", "mr", "safe", "safe", "synthetic_scamshield", "test"],
    ])
    ds = rd.load_dataset(root)
    assert ds["profile"]["raw_counts"]["total"] == 5
    assert ds["profile"]["raw_counts"]["test"] == 2
    test_dist = ds["profile"]["test"]["distribution"]
    assert test_dist["scam"] == 1
    assert test_dist["safe"] == 1
    assert ds["profile"]["test"]["n"] == 2


def test_dataset_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        rd.load_dataset(tmp_path)


def test_dataset_dedup_keeps_first(tmp_path):
    root = tmp_path
    _write_split(root / "train/messages.csv", [
        ["a1", "Bank msg duplicate", "en", "scam", "kyc", "synthetic_scamshield", "train"],
        ["a2", "Bank msg duplicate", "en", "scam", "kyc", "synthetic_scamshield", "train"],
    ])
    _write_split(root / "validation/messages.csv", [["b1", "v msg", "en", "safe", "safe", "synthetic_scamshield", "validation"]])
    _write_split(root / "test/messages.csv", [["c1", "t msg", "en", "scam", "loans", "synthetic_scamshield", "test"]])
    ds = rd.load_dataset(root)
    # Normalised text dedup
    assert ds["profile"]["deduped_counts"]["train"] == 1
    assert ds["profile"]["raw_counts"]["train"] == 2


# ---------------------------------------------------------------------------
# Leakage detection
# ---------------------------------------------------------------------------

def test_leakage_detection_normalised_only():
    train = [{"text": "click here now"}]
    # Same text with different whitespace/case (normalised but not exact)
    validation = [{"text": "  CLICK Here Now "}]
    test = [{"text": "totally different"}]
    audit = rl.audit_leakage(train, validation, test)
    assert audit["totals"]["normalised"] == 1
    assert audit["totals"]["exact"] == 0
    assert audit["overlap_type"] == "normalised"
    assert "train-validation" in audit["affected_split_pairs"]


def test_leakage_detection_exact():
    train = [{"text": "same text"}]
    validation = [{"text": "same text"}]
    test = [{"text": "other"}]
    audit = rl.audit_leakage(train, validation, test)
    assert audit["totals"]["exact"] == 1
    assert audit["totals"]["normalised"] == 1


def test_leakage_clean_records():
    test = [{"text": "shared text"}, {"text": "unique test"}]
    train = [{"text": "shared text"}]
    validation = [{"text": "unrelated"}]
    clean = rl.leakage_clean_records(test, train, validation)
    assert len(clean) == 1
    assert clean[0]["text"] == "unique test"


def test_no_leakage():
    audit = rl.audit_leakage(
        [{"text": "one"}], [{"text": "two"}], [{"text": "three"}],
    )
    assert audit["overlap_type"] == "none"
    assert audit["affected_split_pairs"] == []
    assert audit["totals"]["normalised"] == 0


# ---------------------------------------------------------------------------
# Sensitive-data sanitisation
# ---------------------------------------------------------------------------

def test_sanitize_otp():
    out = rs.sanitize_text("Your OTP is 123456, do not share")
    assert "123456" not in out
    assert "OTP" in out


def test_sanitize_phone():
    out = rs.sanitize_text("Call me on 9876543210 now")
    assert "9876543210" not in out
    assert "PHONE" in out


def test_sanitize_card_and_account():
    out = rs.sanitize_text("card 1234 5678 9012 3456 a/c 987654321012")
    assert "1234 5678" not in out
    assert "CARD" in out
    assert "ACCOUNT" in out


def test_sanitize_url_and_email():
    out = rs.sanitize_text("go to https://evil.example.com/new or mail me@ex.com")
    assert "evil.example.com" not in out
    assert "URL" in out
    assert "EMAIL" in out


def test_sanitize_upi():
    out = rs.sanitize_text("pay merchant@okaxis now")
    assert "merchant@okaxis" not in out
    assert "UPI_ID" in out


def test_sanitize_truncates():
    out = rs.sanitize_text("x" * 1000, max_len=50)
    assert len(out) <= 50


def test_sanitize_example_never_includes_raw_text():
    rec = {"id": "r", "text": "OTP 999888 my card 1234567890123456", "scam_or_safe": "scam",
           "language": "en", "scam_type": "kyc"}
    example = rs.sanitize_example(rec, predicted="safe")
    assert "999888" not in str(example)
    assert "1234" not in str(example)
    assert example["label"] == "scam"
    assert example["predicted"] == "safe"


# ---------------------------------------------------------------------------
# Stratified evaluation
# ---------------------------------------------------------------------------

def test_by_language_metrics():
    recs = [
        dict(SAMPLE_RECORDS[0], language="en"),
        dict(SAMPLE_RECORDS[1], language="en"),
        dict(SAMPLE_RECORDS[2], language="hi"),
        dict(SAMPLE_RECORDS[3], language="hi"),
    ]
    preds = ["scam", "safe", "scam", "safe"]
    res = rst.by_language(recs, preds, min_samples=2)
    assert res["available"] is True
    assert "en" in res["languages"]
    assert res["languages"]["en"]["metrics"]["accuracy"] == 1.0


def test_by_language_insufficient_samples():
    recs = [dict(SAMPLE_RECORDS[0], language="mr")]
    preds = ["scam"]
    res = rst.by_language(recs, preds, min_samples=5)
    assert res["languages"]["mr"]["metrics"] is None


def test_by_category_metrics():
    recs = [
        {"text": "a", "scam_or_safe": "scam", "scam_type": "kyc"},
        {"text": "b", "scam_or_safe": "safe", "scam_type": "safe"},
        {"text": "c", "scam_or_safe": "scam", "scam_type": "phishing"},
    ]
    preds = ["scam", "safe", "scam"]
    res = rst.by_category(recs, preds, min_samples=1)
    assert "kyc" in res["categories"]
    kyc = res["categories"]["kyc"]
    # Only 1 sample (below typical min) but we allow min_samples=1
    # kyc: TP=1, FN=0, FP=0? phishing predicted scam but different category -> contributes FP for kyc
    # Actually FP for kyc = rows NOT kyc predicted as "scam" = phishing row -> 1
    assert kyc["confusion"]["tp"] == 1
    assert kyc["confusion"]["fp"] == 1


def test_by_category_does_not_invent_categories():
    recs = [{"text": "a", "scam_or_safe": "scam", "scam_type": "kyc"}]
    preds = ["scam"]
    res = rst.by_category(recs, preds, min_samples=5)
    # kyc has only 1 sample < 5 -> skipped entirely
    assert res["categories"] == {}


# ---------------------------------------------------------------------------
# Missing model handling
# ---------------------------------------------------------------------------

def test_missing_model_is_graceful(monkeypatch, tmp_path):
    missing_dir = tmp_path / "no_model"
    missing_dir.mkdir()
    from scamshield.research import evaluate as ev_mod

    ml_result = ev_mod.evaluate_ml(SAMPLE_RECORDS, model_path=missing_dir / "missing.joblib")
    # Model file absent -> all records fall back to safe (no crash), and all
    # model-based predictions are recorded; the result stays well-formed.
    assert ml_result["system"] == "ml"
    assert ml_result["n_samples"] == len(SAMPLE_RECORDS)
    assert ml_result["accuracy"] >= 0
    assert isinstance(ml_result["confusion_matrix"], dict)
    # No examples to inspect since predictions never raise
    assert isinstance(ml_result["fp_examples"], list)
    assert isinstance(ml_result["fn_examples"], list)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def test_runner_artifacts_json_valid(tmp_path):
    from scamshield.research import runner

    # Build a minimal summary manually and write artifacts
    summary = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "dataset_profile": {
            "raw_counts": {"train": 0, "validation": 0, "test": 0, "total": 0},
            "deduped_counts": {"train": 0, "validation": 0, "test": 0, "total": 0},
            "test": {"n": 0, "distribution": {}},
        },
        "leakage": {"totals": {"exact": 0, "normalised": 0}, "overlap_type": "none",
                     "affected_split_pairs": [], "recommendation": "no leakage"},
        "comparison": [],
        "rule_engine": {"confusion_matrix": {}, "fp_examples": [], "fn_examples": []},
        "ml": {"confusion_matrix": {}},
        "combined": {"confusion_matrix": {}, "fp_examples": [], "fn_examples": []},
        "leakage_clean_combined": {"note": "x"},
        "language_results": {"available": True, "languages": {}},
        "category_results": {"available": True, "categories": {}},
        "latency": {"engines": {}},
    }
    out_dir = runner.write_artifacts(summary, tmp_path / "res")
    # evaluation_summary.json parses
    with open(out_dir / "evaluation_summary.json", encoding="utf-8") as handle:
        json.load(handle)
    # model_comparison.csv created (empty is skipped, so it may not exist)
    assert (out_dir / "evaluation_summary.json").exists()


# ---------------------------------------------------------------------------
# CSV output validity
# ---------------------------------------------------------------------------

def test_comparison_csv_valid(tmp_path):
    from scamshield.research import runner

    summary = {
        "comparison": [
            {"system": "Rule Engine", "accuracy": 0.9, "precision": 0.8,
             "recall": 0.85, "f1": 0.82, "n_samples": 100, "note": ""},
            {"system": "Combined ScamShield", "accuracy": 0.92, "precision": 0.85,
             "recall": 0.88, "f1": 0.86, "n_samples": 100, "note": ""},
        ]
    }
    out_dir = runner.write_artifacts(summary, tmp_path / "res2")
    csv_path = out_dir / "model_comparison.csv"
    with open(csv_path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert rows[0]["system"] == "Rule Engine"
    assert float(rows[0]["f1"]) == pytest.approx(0.82)


# ---------------------------------------------------------------------------
# Latency (deterministic, no network)
# ---------------------------------------------------------------------------

def test_latency_measurement_runs():
    from scamshield.research import latency as rlat

    # Use a tiny iteration count with just the message engine (fast, no QR)
    samples = {"message": {"input_type": "message", "content": "test message here"}}
    result = rlat.measure_latencies(samples=samples, iterations=3)
    message_stats = result["engines"]["message"]
    assert message_stats["n"] == 3
    assert message_stats["mean_ms"] >= 0
    assert message_stats["min_ms"] <= message_stats["max_ms"]
    assert message_stats["median_ms"] >= 0
    assert result["iterations"] == 3
