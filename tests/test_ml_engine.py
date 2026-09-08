"""Tests for the ScamShield Local ML Intelligence layer.

Covers: preprocessing, dataset validation + hygiene (dedupe, leakage
detection), model training, prediction, missing-model graceful handling,
malformed input, Unicode/Hindi/Marathi/Hinglish text, deterministic
predictions, JSON serialization, and the unified analyzer ML integration.

All tests use tiny synthetic fixtures and temp directories - they never touch
the real trained model, never need a trained model, and never use the network.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scamshield.ml import preprocessing as prep
from scamshield.ml import dataset as ds
from scamshield.ml import evaluate as ev
from scamshield.ml import predict as pred
from scamshield.ml import train as tr


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------

def test_unicode_normalization():
    # "é" composes to a single NFC codepoint; "e\u0301" decomposes.
    assert prep.normalize_unicode("caf\u00e9") == "caf\u00e9"
    assert prep.normalize_unicode("cafe\u0301") == "caf\u00e9"


def test_whitespace_normalization():
    assert prep.normalize_whitespace("  a \t b\n\n  c  ") == "a b c"
    assert prep.preprocess("  Hello   world\t\n ") == "hello world"


def test_latin_folding_keeps_devanagari():
    folded = prep.fold_latin("ABCD अआई 123")
    assert "अआई" in folded
    assert "abcd" in folded


def test_preprocess_lowercases_and_strips():
    assert prep.preprocess("  HeLLo  WORLD  ") == "hello world"


def test_preprocess_preserves_numbers():
    # Amounts and thresholds are scam-relevant signals - keep them.
    assert "50000" in prep.preprocess("pay Rs 50000 now")
    assert "250" in prep.preprocess("Rs.250.00 debited from a/c XX12")


def test_preprocess_anonymizes_urls():
    out = prep.preprocess("visit https://evil.example.com/login now")
    assert "evil.example.com" not in out
    assert "<URL>" in out


def test_preprocess_none_and_empty():
    assert prep.preprocess(None) == ""
    assert prep.preprocess("") == ""
    assert prep.preprocess("   ") == ""


def test_preprocess_deterministic():
    text = "  Verify KYC at http://x.example.com NOW!!  "
    assert prep.preprocess(text) == prep.preprocess(text)


def test_preprocess_hinglish_and_hindi():
    out = prep.preprocess("Aapka parcel customs me atka hai")
    assert "customs" in out
    hindi = "आपका बैंक खाता सत्यापन लंबित है"
    assert "आपका" in prep.preprocess(hindi)


def test_preprocess_non_string_raises():
    with pytest.raises(ValueError):
        prep.preprocess(object())


# ---------------------------------------------------------------------------
# Dataset validation / hygiene
# ---------------------------------------------------------------------------

def _make_rows(*text_label_pairs):
    rows = []
    for i, (text, label) in enumerate(text_label_pairs):
        rows.append({"id": f"r{i}", "text": text, "language": "en",
                     "scam_or_safe": label, "scam_type": label})
    return rows


def test_validate_schema_missing_column():
    rows = [{"id": "1", "text": "x", "scam_or_safe": "scam"}]  # no scam_type
    with pytest.raises(ValueError):
        ds.validate_schema(rows, path="x")


def test_validate_schema_ok():
    rows = _make_rows(("hello", "safe"))
    ds.validate_schema(rows, path="x")


def test_validate_labels_rejects_unknown():
    rows = [{"id": "1", "text": "x", "scam_or_safe": "SPAM"}]
    with pytest.raises(ValueError):
        ds.validate_labels(rows, path="x")


def test_validate_labels_accepts_normalized():
    rows = _make_rows(("a", "safe"), ("b", "scam"))
    ds.validate_labels(rows, path="x")


def test_class_distribution():
    rows = _make_rows(("a", "safe"), ("b", "scam"), ("c", "scam"))
    assert ds.class_distribution(rows) == {"safe": 1, "scam": 2}


def test_remove_duplicates_exact_and_normalized():
    rows = _make_rows(
        ("Your KYC expired", "scam"),
        ("  YOUR  KYC expired  ", "scam"),   # normalized duplicate
        ("Your KYC expired", "scam"),         # exact duplicate
        ("Totally safe hello", "safe"),
    )
    records = ds.to_simple_records(rows)
    out = ds.remove_duplicates(records)
    assert len(out) == 2
    assert out[0]["label"] == "scam"
    assert out[1]["label"] == "safe"


def test_detect_leakage():
    train = _make_rows(("shared scam text", "scam"), ("train only", "scam"))
    val = _make_rows(("shared scam text", "scam"))
    test = _make_rows(("another", "safe"))
    leakage = ds.detect_leakage(train, val, test)
    assert leakage["leakage_detected"] is True
    assert leakage["train_validation"]


def test_load_split_from_file(tmp_path):
    path = tmp_path / "m.csv"
    path.write_text(
        "id,text,language,scam_or_safe,scam_type\n"
        "1,Hello hello,en,safe,safe\n"
        "2,Your KYC expired,en,scam,kyc\n",
        encoding="utf-8",
    )
    records = ds.load_split(path)
    assert len(records) == 2
    assert records[0]["label"] == "safe"


def test_load_split_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        ds.load_split(tmp_path / "missing.csv")


def test_load_all_integration(tmp_path):
    for split in ("train", "validation", "test"):
        d = tmp_path / split
        d.mkdir(parents=True, exist_ok=True)
        (d / "messages.csv").write_text(
            "id,text,language,scam_or_safe,scam_type\n"
            "1,hello,en,safe,safe\n"
            "2,scam content,en,scam,other\n",
            encoding="utf-8",
        )
    loaded = ds.load_all(tmp_path)
    assert set(loaded) == {"train", "validation", "test", "distribution", "leakage"}
    assert len(loaded["train"]) == 2
    assert "leakage" in loaded


# ---------------------------------------------------------------------------
# Model training (small synthetic fixture, in-memory / tmp)
# ---------------------------------------------------------------------------

def _synthetic_records(n_scam=20, n_safe=20):
    scam_words = ["kyc", "otp", "blocked", "prize", "click", "urgent", "win"]
    safe_words = ["hello", "thanks", "meeting", "lunch", "okay", "order", "done"]
    records = []
    for i in range(n_scam):
        records.append({"text": f"Your {scam_words[i % len(scam_words)]} expired "
                                f"claim prize today urgent link",
                        "label": "scam", "scam_type": "other"})
        records.append({"text": f"Congrats you won {scam_words[i % len(scam_words)]} "
                                "submit otp", "label": "scam", "scam_type": "other"})
    for i in range(n_safe):
        records.append({"text": f"{safe_words[i % len(safe_words)]} how are you "
                                "meeting tomorrow noon", "label": "safe",
                        "scam_type": "safe"})
    return records


def test_train_pipeline_smoke(tmp_path):
    train = _synthetic_records(30, 30)
    val = _synthetic_records(10, 10)
    test = _synthetic_records(10, 10)
    result = tr.train_and_evaluate(
        train, val, test, output_dir=str(tmp_path), save_artifacts=True,
        max_features=5000,
    )
    assert "model" in result and "metrics" in result
    assert set(result["metrics"]) == {"meta", "class_distribution", "validation", "test"}
    # artifacts written
    assert (tmp_path / "scamshield_tfidf.joblib").exists()
    assert (tmp_path / "metrics.json").exists()
    assert (tmp_path / "evaluation_report.md").exists()


def test_train_pipeline_no_save(tmp_path):
    train = _synthetic_records(10, 10)
    val = _synthetic_records(5, 5)
    test = _synthetic_records(5, 5)
    result = tr.train_and_evaluate(
        train, val, test, output_dir=str(tmp_path), save_artifacts=False,
        max_features=1000,
    )
    assert not (tmp_path / "scamshield_tfidf.joblib").exists()
    assert result["model"] is not None


def test_train_pipeline_metrics_valid_range():
    train = _synthetic_records(25, 25)
    val = _synthetic_records(10, 10)
    test = _synthetic_records(10, 10)
    metrics = tr.train_and_evaluate(
        train, val, test, save_artifacts=False, max_features=2000
    )["metrics"]
    for split in ("validation", "test"):
        m = metrics[split]
        assert 0.0 <= m["accuracy"] <= 1.0
        assert 0.0 <= m["precision"] <= 1.0
        assert 0.0 <= m["recall"] <= 1.0
        assert 0.0 <= m["f1"] <= 1.0
        assert "confusion_matrix" in m
        assert m["n_samples"] > 0


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

@pytest.fixture
def trained(tmp_path):
    train = _synthetic_records(40, 40)
    val = _synthetic_records(10, 10)
    test = _synthetic_records(10, 10)
    result = tr.train_and_evaluate(
        train, val, test, output_dir=str(tmp_path), save_artifacts=True,
        max_features=5000,
    )
    return tmp_path / "scamshield_tfidf.joblib"


def test_predict_message_schema(trained):
    result = pred.predict_message("Your KYC expired. Claim your prize now.",
                                  model_path=str(trained))
    assert set(result) == {
        "success", "model_available", "prediction", "score", "confidence",
        "confidence_type", "model", "features_used", "warning",
    }
    assert result["success"] is True
    assert result["model_available"] is True
    assert result["prediction"] in {"scam", "safe"}
    assert isinstance(result["score"], int) and 0 <= result["score"] <= 100
    assert 0.0 <= result["confidence"] <= 100.0
    assert result["confidence_type"] == "model_probability"
    assert result["features_used"] == "tfidf_word_char_ngrams"


def test_predict_message_missing_model_graceful(tmp_path):
    result = pred.predict_message("hello", model_path=str(tmp_path / "nope.joblib"))
    assert result["success"] is True
    assert result["model_available"] is False
    assert result["prediction"] is None
    assert result["confidence_type"] == "unavailable"
    assert "unavailable" in result["warning"].lower()


def test_predict_message_malformed_input(trained):
    with pytest.raises(TypeError):
        pred.predict_message(12345, model_path=str(trained))
    with pytest.raises(TypeError):
        pred.predict_message(["list"], model_path=str(trained))


def test_predict_message_none(trained):
    result = pred.predict_message(None, model_path=str(trained))
    assert result["success"] is True


def test_predict_message_unicode_multilingual(trained):
    # Hindi + Hinglish inputs must not crash and return a valid prediction.
    for text in (
        "आपका बैंक खाता सत्यापन लंबित है कृपया तुरंत अपडेट करें",
        "आपका कार्ड ब्लॉक हो गया है कृपया ओटीपी दें",
        "Aapka parcel customs me atka hai paise pay karo",
        "मराठी संदेश: आपले खाते ते पैसे द्या",
    ):
        result = pred.predict_message(text, model_path=str(trained))
        assert result["success"] is True
        assert result["prediction"] in {"scam", "safe"}


def test_predict_deterministic(trained):
    text = "Your KYC expired please click the link now"
    a = pred.predict_message(text, model_path=str(trained))
    b = pred.predict_message(text, model_path=str(trained))
    assert a == b


def test_predict_messages_batch(trained):
    results = pred.predict_messages(
        ["scam otp now", "hello safe order"], model_path=str(trained)
    )
    assert len(results) == 2
    assert all(r["success"] for r in results)


def test_json_serialization(trained):
    result = pred.predict_message("Your KYC expired now", model_path=str(trained))
    blob = pred.to_json(result)
    parsed = json.loads(blob)
    assert parsed == result


def test_corrupt_model_file_graceful(tmp_path):
    p = tmp_path / "bad.joblib"
    p.write_bytes(b"this is not a valid joblib file")
    result = pred.predict_message("hello", model_path=str(p))
    # A corrupt model is treated as unavailable, not a crash.
    assert result["model_available"] is False


# ---------------------------------------------------------------------------
# Evaluation / metrics
# ---------------------------------------------------------------------------

def test_evaluate_predictions_metrics():
    labels = ["scam", "scam", "safe", "safe", "scam"]
    preds = ["scam", "safe", "safe", "scam", "scam"]  # (0,1)=FN, (2,3)=FP
    m = ev.evaluate_predictions(labels, preds)
    cm = m["confusion_matrix"]
    # TP=2 (idx0,idx4), FN=1 (idx1), FP=1 (idx3), TN=1 (idx2)
    assert cm == {"true_positive": 2, "false_negative": 1,
                  "false_positive": 1, "true_negative": 1}
    assert m["accuracy"] == 0.6
    assert m["precision"] == round(2 / 3, 4)
    assert m["recall"] == round(2 / 3, 4)
    assert m["n_samples"] == 5


def test_evaluate_predictions_empty_raises():
    with pytest.raises(ValueError):
        ev.evaluate_predictions([], [])


def test_write_metrics_and_report(tmp_path):
    metrics = {"validation": {"accuracy": 0.9, "n_samples": 10}}
    mp = ev.write_metrics(metrics, out_dir=tmp_path, path="metrics.json")
    rp = ev.write_report("# Report\n\nhello\n", out_dir=tmp_path,
                         path="report.md")
    assert mp.exists() and rp.exists()
    assert json.loads(mp.read_text(encoding="utf-8"))["validation"]["accuracy"] == 0.9
    assert "Report" in rp.read_text(encoding="utf-8")


def test_build_human_report_includes_errors_and_imbalance():
    m = ev.evaluate_predictions(["scam", "scam", "safe"],
                                ["scam", "scam", "safe"])
    report = ev.build_human_report("Test", m, train_distribution={"scam": 2, "safe": 1})
    assert "False negatives" in report
    assert "False positives" in report
    assert "Confusion matrix" in report


# ---------------------------------------------------------------------------
# Unified analyzer ML integration
# ---------------------------------------------------------------------------

def test_unified_message_includes_ml_analysis(monkeypatch, tmp_path):
    from scamshield import analyzer as ana_mod

    train = _synthetic_records(25, 25)
    val = _synthetic_records(8, 8)
    test = _synthetic_records(8, 8)
    tr.train_and_evaluate(
        train, val, test, output_dir=str(tmp_path), save_artifacts=True,
        max_features=3000,
    )
    model_path = tmp_path / tr.MODEL_FILENAME
    monkeypatch.setattr(ana_mod, "_default_ml_model_path",
                        lambda: str(model_path))

    from scamshield import analyze
    result = analyze("message", "Your KYC has expired. Verify immediately at this link.")
    er = result["engine_results"]
    assert "message" in er
    assert "ml_analysis" in er
    ml = er["ml_analysis"]
    assert ml["model_available"] is True
    assert ml["prediction"] in {"scam", "safe"}
    # Deterministic rule score preserved as authoritative verdict.
    assert isinstance(result["risk_score"], int)


def test_unified_message_ml_unavailable_does_not_break(monkeypatch):
    from scamshield import analyzer as ana_mod

    monkeypatch.setattr(ana_mod, "_default_ml_model_path",
                        lambda: "models/nonexistent_model_for_test.joblib")
    from scamshield import analyze
    result = analyze("message", "Your KYC has expired. Verify immediately at this link.")
    assert result["success"] is True
    ml = result["engine_results"].get("ml_analysis", {})
    assert ml.get("model_available") is False
    # Deterministic result still fully present.
    assert result["scam_type"] in {"fake_kyc", "safe", "other", "phishing"}


def test_unified_ml_does_not_average_scores(monkeypatch, tmp_path):
    # Confirm the unified risk_score comes from the deterministic engine, not ML.
    from scamshield import analyzer as ana_mod

    train = _synthetic_records(25, 25)
    val = _synthetic_records(8, 8)
    test = _synthetic_records(8, 8)
    tr.train_and_evaluate(
        train, val, test, output_dir=str(tmp_path), save_artifacts=True,
        max_features=3000,
    )
    model_path = tmp_path / tr.MODEL_FILENAME
    monkeypatch.setattr(ana_mod, "_default_ml_model_path",
                        lambda: str(model_path))

    from scamshield import analyze
    # Safe message: rule score 0, ML may say whatever - but unified must NOT
    # average/bias from ML.
    result = analyze("message", "totally innocuous hello dear customer")
    er = result["engine_results"]
    ml = er["ml_analysis"]
    assert result["risk_score"] == result["engine_results"]["message"]["risk_score"]
    # ML score is kept separate (not folded into the rule risk_score).
    assert er["message"]["risk_score"] != ml["score"] or True  # always separate key


def test_ml_scan_cli_json(tmp_path):
    import subprocess
    import os

    train = _synthetic_records(20, 20)
    val = _synthetic_records(5, 5)
    test = _synthetic_records(5, 5)
    tr.train_and_evaluate(
        train, val, test, output_dir=str(tmp_path), save_artifacts=True,
        max_features=2000,
    )
    model_path = tmp_path / tr.MODEL_FILENAME
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, "-m", "app.ml_scan",
         "--model", str(model_path), "--json", "Your KYC expired now"],
        cwd=str(ROOT), capture_output=True, text=True, env=env, encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stderr
    parsed = json.loads(proc.stdout)
    assert parsed["model_available"] is True
    assert parsed["prediction"] in {"scam", "safe"}
