"""Tests for the Unified ScamShield Analyzer orchestration layer.

Covers routing, input-type detection, unified schema normalization,
risk/level normalization, scam-type normalization, summary + evidence
generation, confidence handling, error paths, batch analysis, determinism,
the no-network guarantee, and preservation of the original engine results.
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

from scamshield import analyze, analyze_batch, detect_input_type
from scamshield.analyzer import (
    CONFIDENCE_NOTE,
    RISK_LEVELS,
    SCAM_TYPE_VOCABULARY,
)

FIXTURE_DIR = str(ROOT / "tests" / "fixtures" / "qr")
URL_SUSPICIOUS = f"{FIXTURE_DIR}/url_suspicious.png"
UPI_NORMAL = f"{FIXTURE_DIR}/upi_normal.png"
URL_BENIGN = f"{FIXTURE_DIR}/url_benign.png"
TEXT_SCAM = f"{FIXTURE_DIR}/text_scam.png"
NO_QR = f"{FIXTURE_DIR}/no_qr_blank.png"
MISSING = f"{FIXTURE_DIR}/does_not_exist.png"

TOP_LEVEL_KEYS = {
    "success", "input_type", "status", "risk_score", "risk_level",
    "is_suspicious", "scam_type", "confidence", "confidence_type",
    "confidence_note", "summary", "indicators", "explanation",
    "recommendations", "evidence", "engine_results", "warnings",
    # Additive safety-zone / explainability presentation (derived from the
    # existing authoritative score + engine evidence; never a second scorer).
    "zone", "zone_label", "zone_description", "recommended_action",
    "risk_assessment", "risk_breakdown",
    # Additive Indian scam-intelligence interpretation (deterministic,
    # evidence-driven, offline; purely additive - see scam_intel.py).
    "scam_intelligence",
}


# ---------------------------------------------------------------------------
# Schema / routing basics
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("itype,content", [
    ("message", "Your KYC has expired. Click the link now."),
    ("url", "https://example.com/login"),
    ("qr", URL_SUSPICIOUS),
    ("upi", "upi://pay?pa=merchant@upi&pn=Store&am=60&cu=INR"),
])
def test_top_level_schema_present(itype, content):
    result = analyze(itype, content)
    assert set(result) == TOP_LEVEL_KEYS, set(result) ^ TOP_LEVEL_KEYS
    assert result["input_type"] == itype
    assert result["success"] is True
    assert result["status"] is not None
    assert result["confidence_type"] == "heuristic"
    assert result["confidence_note"] == CONFIDENCE_NOTE


@pytest.mark.parametrize("itype,content", [
    ("message", "Your KYC has expired. Click the link now."),
    ("url", "https://example.com/login"),
    ("qr", URL_SUSPICIOUS),
    ("upi", "upi://pay?pa=merchant@upi&pn=Store&am=60&cu=INR"),
])
def test_original_engine_result_preserved(itype, content):
    result = analyze(itype, content)
    engine_results = result["engine_results"]
    assert isinstance(engine_results, dict)
    assert itype in engine_results
    engine_result = engine_results[itype]
    assert isinstance(engine_result, dict)
    # The unified risk score is derived from the underlying engine score.
    assert result["risk_score"] == max(
        0, min(100, round(float(engine_result.get("risk_score", 0))))
    )


@pytest.mark.parametrize("alias,cannon", [
    ("msg", "message"), ("text", "message"), ("Message", "message"),
    ("link", "url"), ("URL", "url"),
    ("qrcode", "qr"), ("qr_image", "qr"), ("Image", "qr"),
    ("upi_uri", "upi"),
])
def test_input_type_aliases(alias, cannon):
    result = analyze(alias, "upi://pay?pa=a@upi" if cannon == "upi"
                     else "https://example.com" if cannon == "url"
                     else f"{URL_SUSPICIOUS}" if cannon == "qr"
                     else "hello world")
    assert result["input_type"] == cannon


def test_unsupported_type_error():
    result = analyze("email", "x@y.com")
    assert result["success"] is False
    assert result["error_type"] == "unsupported_type"
    assert result["status"] == "ERROR"
    assert result["error"]
    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"


def test_unsupported_type_non_string():
    result = analyze(123, "x")
    assert result["success"] is False
    assert result["error_type"] == "unsupported_type"


# ---------------------------------------------------------------------------
# detect_input_type
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("content,expected", [
    ("https://example.com", "url"),
    ("http://Example.com/path", "url"),
    ("HTTP://x.io", "url"),
    ("upi://pay?pa=a@upi", "upi"),
    ("upi:pay?pa=a@upi", "upi"),
    ("UPI://PAY?PA=a@upi", "upi"),
    ("Your account is suspended", "message"),
    ("example.com", "message"),
    ("tests/fixtures/qr/url_suspicious.png", "message"),
    ("", "message"),
    ("   ", "message"),
    (None, "message"),
    (123, "message"),
    (["a"], "message"),
])
def test_detect_input_type(content, expected):
    assert detect_input_type(content) == expected


# ---------------------------------------------------------------------------
# Risk score / level normalization
# ---------------------------------------------------------------------------

def test_risk_score_bounds():
    for itype, content in [
        ("url", "https://example.com"),
        ("upi", "upi://pay?pa=a@upi&am=1"),
    ]:
        result = analyze(itype, content)
        assert 0 <= result["risk_score"] <= 100


@pytest.mark.parametrize("score", [0, 1, 24, 25, 49, 50, 74, 75, 99, 100])
def test_risk_level_buckets(score):
    from scamshield.analyzer import _risk_level
    expected = (
        "LOW" if score < 25 else
        "MEDIUM" if score < 50 else
        "HIGH" if score < 75 else
        "CRITICAL"
    )
    assert _risk_level(score) == expected


def test_risk_level_in_vocabulary():
    for itype, content in [
        ("message", "Your KYC has expired. Click the link now."),
        ("url", "https://example.com"),
        ("qr", URL_SUSPICIOUS),
        ("upi", "upi://pay?pa=a@upi&am=10"),
    ]:
        assert analyze(itype, content)["risk_level"] in RISK_LEVELS


# ---------------------------------------------------------------------------
# Suspicious flag / scam-type normalization
# ---------------------------------------------------------------------------

def test_scam_type_vocabulary_contains_all_families():
    expected = {
        "phishing", "fake_kyc", "upi_payment", "bank_impersonation",
        "fake_customer_care", "job_scam", "investment_scam", "loan_scam",
        "delivery_scam", "lottery_prize", "social_media_impersonation",
        "government_impersonation", "credential_theft", "other", "safe",
    }
    assert expected.issubset(SCAM_TYPE_VOCABULARY)


@pytest.mark.parametrize("itype,content,exp_suspicious,exp_type", [
    ("url", "https://example.com", False, "safe"),
    ("url", "https://secure-sbi-verify.example.com/login", True, "phishing"),
    ("upi", "upi://pay?pa=a@upi&am=10", False, "safe"),
    ("upi", "upi://pay?pa=scam@refunds&am=50000&tn=reward", True, "upi_payment"),
    ("qr", URL_SUSPICIOUS, True, "phishing"),
    ("qr", UPI_NORMAL, False, "safe"),
    ("qr", URL_BENIGN, False, "safe"),
])
def test_scam_type_and_suspicious(itype, content, exp_suspicious, exp_type):
    result = analyze(itype, content)
    assert result["is_suspicious"] is exp_suspicious
    assert result["scam_type"] == exp_type


def test_message_scam_types_normalized():
    result = analyze(
        "message", "Your KYC has expired. Verify immediately at this link."
    )
    assert result["is_suspicious"] is True
    assert result["scam_type"] in SCAM_TYPE_VOCABULARY


def test_not_decoded_is_safe():
    result = analyze("qr", NO_QR)
    assert result["success"] is True
    assert result["is_suspicious"] is False
    assert result["scam_type"] == "safe"


# ---------------------------------------------------------------------------
# Message specifics
# ---------------------------------------------------------------------------

def test_message_suspicious_summary_and_indicators():
    result = analyze(
        "message", "Your KYC has expired. Verify immediately at this link."
    )
    assert result["is_suspicious"] is True
    assert result["indicators"]
    assert result["scam_type"] in SCAM_TYPE_VOCABULARY


def test_message_safe_summary():
    result = analyze("message", "Totally innocuous hello dear customer")
    assert result["is_suspicious"] is False
    assert "No scam patterns" in result["summary"]


def test_message_empty_body_error_free():
    result = analyze("message", "")
    assert result["success"] is True
    assert result["is_suspicious"] is False
    assert result["risk_score"] == 0
    # Must never crash on an empty message.
    assert "No scam patterns" in result["summary"]


# ---------------------------------------------------------------------------
# URL specifics
# ---------------------------------------------------------------------------

def test_url_never_exposes_parsed_credentials():
    u = "https://user:pass@example.com/login"
    result = analyze("url", u)
    evidence = result["evidence"]
    # The parsed credential fields are intentionally omitted from evidence.
    assert "username" not in evidence
    assert "password" not in evidence
    assert "url_userinfo" not in evidence
    # Parsed userinfo credentials only appear inside the raw url string, never
    # as a dedicated field.
    assert evidence["url_hostname"] == "example.com"


def test_malformed_url_does_not_crash():
    for bad in ["not a url at all", "http://", "https://", "   ", ""]:
        result = analyze("url", bad)
        assert result["success"] is True
        assert 0 <= result["risk_score"] <= 100


# ---------------------------------------------------------------------------
# QR specifics
# ---------------------------------------------------------------------------

def test_qr_success_schema():
    result = analyze("qr", URL_SUSPICIOUS)
    assert result["success"] is True
    assert result["evidence"]["source"] == "qr"
    assert result["evidence"]["file"] == URL_SUSPICIOUS
    assert result["evidence"]["content_type"] == "url"


def test_qr_missing_file_returns_error():
    result = analyze("qr", MISSING)
    assert result["success"] is False
    assert result["error_type"] == "engine_error"
    assert result["status"] == "ERROR"
    assert result["scam_type"] is None
    assert result["risk_score"] == 0
    # Original engine result retained even on failure.
    assert result["engine_results"]["qr"].get("success") is False


def test_qr_upi_evidence():
    result = analyze("qr", UPI_NORMAL)
    assert result["success"] is True
    assert result["evidence"]["content_type"] == "upi"
    assert result["evidence"]["upi"]["payee_address"]


# ---------------------------------------------------------------------------
# UPI specifics
# ---------------------------------------------------------------------------

def test_upi_evidence_and_scam_type():
    result = analyze(
        "upi", "upi://pay?pa=scam@refunds&am=50000&tn=Claim reward"
    )
    assert result["scam_type"] == "upi_payment"
    assert result["is_suspicious"] is True
    evidence = result["evidence"]
    assert evidence["upi"]["payee_address"] == "scam@refunds"
    assert evidence["upi"]["amount"] == 50000


def test_upi_safe():
    result = analyze("upi", "upi://pay?pa=merchant@upi&pn=Store&am=60&cu=INR")
    assert result["is_suspicious"] is False
    assert result["scam_type"] == "safe"
    assert result["summary"]


# ---------------------------------------------------------------------------
# Confidence handling
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("itype,content", [
    ("message", "Your KYC has expired."),
    ("url", "https://example.com"),
    ("qr", URL_SUSPICIOUS),
    ("upi", "upi://pay?pa=a@upi&am=10"),
])
def test_confidence_present_and_type_heuristic(itype, content):
    result = analyze(itype, content)
    assert isinstance(result["confidence"], float)
    assert 0 <= result["confidence"] <= 100
    assert result["confidence_type"] == "heuristic"
    assert result["confidence_note"] == CONFIDENCE_NOTE


# ---------------------------------------------------------------------------
# Summary / evidence generation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("itype,content", [
    ("message", "Your KYC has expired. Please verify at http://x.com."),
    ("url", "https://example.com"),
    ("qr", URL_SUSPICIOUS),
    ("upi", "upi://pay?pa=a@upi&am=10"),
])
def test_summary_and_evidence_non_empty(itype, content):
    result = analyze(itype, content)
    assert isinstance(result["summary"], str) and result["summary"]
    assert isinstance(result["evidence"], dict) and result["evidence"]
    assert isinstance(result["recommendations"], list)
    assert isinstance(result["explanation"], list)


def test_url_evidence_fields():
    result = analyze("url", "https://secure-sbi-verify.example.com/login")
    evidence = result["evidence"]
    assert evidence["url_scheme"] == "https"
    assert evidence["url_root_domain"] == "example.com"
    assert "login" in evidence["url_path"]
    assert "sbi" not in [evidence.get("url_userinfo", "")]


# ---------------------------------------------------------------------------
# Batch analysis
# ---------------------------------------------------------------------------

def test_analyze_batch_dict_and_tuple():
    items = [
        {"type": "url", "content": "https://example.com"},
        {"content": "upi://pay?pa=a@upi&am=10"},
        ("qr", URL_SUSPICIOUS),
        {"type": "message", "content": "Your KYC has expired."},
    ]
    results = analyze_batch(items)
    assert len(results) == 4
    assert [r["input_type"] for r in results] == ["url", "upi", "qr", "message"]
    assert all(r["success"] for r in results)


def test_analyze_batch_invalid_item():
    results = analyze_batch([{"content": "https://example.com"},
                             "not-a-dict"])
    assert results[0]["input_type"] == "url"
    assert results[1]["success"] is False
    assert results[1]["error_type"] == "validation"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("itype,content", [
    ("message", "Your KYC has expired. Verify now."),
    ("url", "https://secure-sbi-verify.example.com/login"),
    ("qr", URL_SUSPICIOUS),
    ("upi", "upi://pay?pa=scam@refunds&am=50000&tn=reward"),
])
def test_deterministic(itype, content):
    first = analyze(itype, content)
    repeats = [analyze(itype, content) for _ in range(3)]
    for repeat in repeats:
        assert repeat == first


# ---------------------------------------------------------------------------
# No-network guarantee
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("itype,content", [
    ("message", "Your KYC has expired. Verify http://suspicious.example.com"),
    ("url", "https://secure-sbi-verify.example.com/login"),
    ("qr", URL_SUSPICIOUS),
    ("upi", "upi://pay?pa=scam@refunds&am=50000&tn=reward"),
])
def test_no_network_calls(monkeypatch, itype, content):
    blocked = []

    def fake_socket(*args, **kwargs):
        blocked.append(1)
        raise AssertionError(f"socket attempted: {args}, {kwargs}")

    import socket
    monkeypatch.setattr(socket, "socket", fake_socket)
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("network attempted")))
    result = analyze(itype, content)
    assert result["success"] is True
    assert blocked == []