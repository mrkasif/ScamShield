"""Unit and integration tests for the ScamShield QR Security Analyzer.

Run with:
    python -m pytest tests/test_qr_engine.py -v

Security posture: all payloads below are synthetic (.example.com, @upi test
IDs, harmless text). We never scan a real malicious QR image, never execute a
payload and never open a decoded URL. Several tests monkeypatch the network
and process-execution primitives to prove the analyzer cannot reach out.
"""

import os
import socket
import subprocess
import sys
import urllib.request
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

cv2 = pytest.importorskip("cv2")
qrcode = pytest.importorskip("qrcode")

from scamshield.qr import (  # noqa: E402
    analyze_qr,
    analyze_qr_content,
    analyze_upi,
    classify_content,
    combine_risk_scores,
    decode_qr_image,
    parse_upi_uri,
)

FIXTURES = ROOT / "tests" / "fixtures" / "qr"

REQUIRED_KEYS = (
    "success", "status", "content_type", "decoded_content", "risk_score",
    "risk_level", "is_suspicious", "confidence", "indicators", "explanation",
    "recommendations", "url_analysis", "message_analysis", "upi_analysis",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def render_qr(payload: str) -> np.ndarray:
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    return np.array(qr.make_image().convert("RGB"))


def write_qr(tmp_path: Path, payload: str, name: str = "qr.png", fmt: str = "png"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    cv2.imwrite(str(path), render_qr(payload))
    return path


# ---------------------------------------------------------------------------
# 1. Content classification
# ---------------------------------------------------------------------------

def test_classify_url():
    assert classify_content("https://example.com/a") == "url"
    assert classify_content("HTTP://EXAMPLE.COM") == "url"
    assert classify_content("http://x.co/1") == "url"


def test_classify_upi():
    assert classify_content("upi://pay?pa=a@upi") == "upi"
    assert classify_content("upi:pay?pa=a@upi") == "upi"
    assert classify_content("UPI://PAY?pa=a@upi") == "upi"


def test_classify_plain_text():
    assert classify_content("Hello, please verify your account") == "text"
    assert classify_content("  meet at 5pm  ") == "text"


def test_classify_multiline_text():
    payload = "BEGIN:VCARD\nFN:Test User\nEMAIL:x@example.com\nEND:VCARD"
    assert classify_content(payload) == "text"


def test_classify_unknown_scheme():
    assert classify_content("mailto:user@example.com") == "unknown"
    assert classify_content("geo:0,0?q=place") == "unknown"
    assert classify_content("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "unknown"


def test_classify_empty():
    assert classify_content("") == "unknown"
    assert classify_content(None) == "unknown"


# ---------------------------------------------------------------------------
# 2. UPI parsing
# ---------------------------------------------------------------------------

def test_parse_upi_full_fields():
    p = parse_upi_uri(
        "upi://pay?pa=merchant%40upi&pn=Tea+Store&am=60.50&cu=INR"
        "&tn=Order+%23123&mc=0000&tr=TXN99"
    )
    assert p["scheme"] == "upi"
    assert p["action"] == "pay"
    assert p["is_pay"] is True
    assert p["payee_address"] == "merchant@upi"
    assert p["payee_name"] == "Tea Store"
    assert p["amount"] == 60.5
    assert p["currency"] == "INR"
    assert p["transaction_note"] == "Order #123"
    assert p["merchant_code"] == "0000"
    assert p["transaction_ref"] == "TXN99"
    assert p["malformed"] is False


def test_parse_upi_amount_variants():
    assert parse_upi_uri("upi://pay?am=100")["amount"] == 100
    assert parse_upi_uri("upi://pay?am=1,000")["amount"] == 1000
    assert parse_upi_uri("upi://pay?am=50.25")["amount"] == 50.25
    assert parse_upi_uri("upi://pay?am=abc")["amount"] is None
    assert parse_upi_uri("upi://pay?am=-5")["amount"] is None
    assert parse_upi_uri("upi://pay?am=nan")["amount"] is None
    assert parse_upi_uri("upi://pay?am=")["amount"] is None


def test_parse_upi_uppercase_and_colon_form():
    p = parse_upi_uri("UPI:PAY?pa=a@upi&pn=Shop")
    assert p["scheme"] == "upi"
    assert p["is_pay"] is True
    assert p["payee_address"] == "a@upi"


def test_parse_upi_malformed_non_upi_scheme():
    assert parse_upi_uri("https://example.com/")["malformed"] is True


def test_parse_upi_pay_without_recipient_is_malformed():
    p = parse_upi_uri("upi://pay?am=100")
    assert p["is_pay"] is True
    assert p["malformed"] is True
    assert p["valid_upi"] is False


# ---------------------------------------------------------------------------
# 3. UPI scoring behaviour
# ---------------------------------------------------------------------------

def test_upi_normal_payment_low():
    r = analyze_upi(
        "upi://pay?pa=store@upi&pn=Tea+Store&am=60.00&cu=INR&tn=Order"
    )
    assert r["risk_score"] <= 24
    assert r["risk_level"] == "LOW"
    assert r["is_suspicious"] is False
    assert "payment_destination_detected" in r["indicators"]
    assert "embedded_payment_amount" in r["indicators"]


def test_upi_destination_and_amount_explained():
    r = analyze_upi("upi://pay?pa=store@upi&am=60")
    reasons = " ".join(e["reason"] for e in r["explanation"])
    assert r["risk_score"] == 28  # 8 + 10 + combo 4 + recipient_not_named 6
    assert "payment destination and amount are embedded" in reasons


def test_upi_amount_thresholds():
    assert "payment_amount_threshold_1" in analyze_upi("upi://pay?pa=a@upi&am=10000")["indicators"]
    assert "payment_amount_threshold_2" in analyze_upi("upi://pay?pa=a@upi&am=50000")["indicators"]
    assert "payment_amount_threshold_3" in analyze_upi("upi://pay?pa=a@upi&am=100000")["indicators"]
    assert "payment_amount_threshold_1" not in analyze_upi("upi://pay?pa=a@upi&am=9999")["indicators"]


def test_upi_note_language_families():
    assert "urgent_payment_request" in analyze_upi("upi://pay?pa=a@upi&tn=Act+now")["indicators"]
    assert "refund_reward_prize_language" in analyze_upi(
        "upi://pay?pa=a@upi&tn=Claim+your+refund+prize")["indicators"]
    assert "kyc_unblock_account_language" in analyze_upi(
        "upi://pay?pa=a@upi&tn=Update+your+KYC")["indicators"]
    assert "otp_credential_request" in analyze_upi(
        "upi://pay?pa=a@upi&tn=Enter+your+OTP+now")["indicators"]


def test_upi_note_family_capped_at_45():
    r = analyze_upi(
        "upi://pay?pa=a@upi&tn=Claim+refund+prize+now+urgently+update+KYC+unblock"
        "+enter+OTP+password+verification+cvv"
    )
    note_names = {"urgent_payment_request", "refund_reward_prize_language",
                  "kyc_unblock_account_language", "otp_credential_request"}
    note_total = sum(
        e["score"] for e in r["explanation"]
        if e["indicator"] in note_names
    )
    assert note_total <= 45.0 + 1e-6
    assert 0 <= r["risk_score"] <= 100


def test_upi_social_engineering_cluster():
    r = analyze_upi(
        "upi://pay?pa=a@upi&am=50000&tn=Urgent+refund+claim+validate+KYC+nothing"
    )
    # urgent + refund + kyc families -> cluster bonus present
    assert "social_engineering_cluster" in r["indicators"]
    assert r["is_suspicious"] is True


def test_upi_malformed_input_never_raises():
    for payload in (None, "", "https://example.com", "upi://pay?pa=", "not a uri at all"):
        r = analyze_upi(payload)
        assert 0 <= r["risk_score"] <= 100
        assert r["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_upi_deterministic():
    a = analyze_upi("upi://pay?pa=store@upi&am=60&tn=Claim+urgently")
    b = analyze_upi("upi://pay?pa=store@upi&am=60&tn=Claim+urgently")
    assert a == b


# ---------------------------------------------------------------------------
# 4. analyze_qr_content (decoded-payload routing)
# ---------------------------------------------------------------------------

def test_content_url_routing():
    payload = "https://secure-sbi-verify.example.com/login"
    r = analyze_qr_content(payload)
    assert r["content_type"] == "url"
    assert r["decoded_content"] == payload
    assert r["url_analysis"] is not None
    assert r["risk_score"] == r["url_analysis"]["risk_score"]
    assert r["risk_score"] >= 50
    assert r["is_suspicious"] is True
    assert r["indicators"][0] == "embedded_url_in_qr"


def test_content_benign_url_low():
    r = analyze_qr_content("https://example.com/")
    assert r["risk_score"] <= 24
    assert r["risk_level"] == "LOW"
    assert r["url_analysis"]["url"] == "https://example.com/"


def test_content_upi_routing():
    r = analyze_qr_content("upi://pay?pa=merchant@upi&pn=Store&am=60&cu=INR")
    assert r["content_type"] == "upi"
    assert r["upi_analysis"] is not None
    assert r["upi_analysis"]["parse"]["payee_address"] == "merchant@upi"
    assert r["risk_level"] == "LOW"


def test_content_text_routing():
    r = analyze_qr_content("Lunch at noon sounds good.")
    assert r["content_type"] == "text"
    assert r["message_analysis"] is not None
    assert r["message_analysis"]["is_scam"] is False
    assert r["risk_score"] <= 24


def test_content_scam_text_high():
    r = analyze_qr_content("Your KYC is blocked. Verify immediately, enter the OTP.")
    assert r["content_type"] == "text"
    assert r["risk_score"] >= 50
    assert r["is_suspicious"] is True
    assert r["message_analysis"]["is_scam"] is True


def test_content_scam_text_with_url_integration():
    r = analyze_qr_content(
        "Verify your account now at https://secure-sbi-verify.example.com/login"
    )
    assert r["content_type"] == "text"
    assert r["message_analysis"] is not None
    assert r["message_analysis"]["detected_urls"]
    assert r["url_analysis"] is not None


def test_content_unknown_neutral():
    r = analyze_qr_content("mailto:user@example.com")
    assert r["content_type"] == "unknown"
    assert r["risk_score"] == 0
    assert r["risk_level"] == "LOW"
    assert r["is_suspicious"] is False
    assert r["indicators"] == []


def test_content_empty_neutral():
    r = analyze_qr_content("")
    assert r["content_type"] == "unknown"
    assert r["risk_score"] == 0


def test_content_risk_bounds():
    payloads = [
        "https://example.com/",
        "https://secure-sbi-verify.example.com/login?otp=123",
        "upi://pay?pa=store@upi&pn=Store&am=60&cu=INR",
        "upi://pay?pa=a@upi&am=100000&tn=Urgent+claim+refund+now+OTP",
        "hello",
        "Your account block. Enter OTP now.",
        "mailto:x@y.com",
        "",
        None,
    ]
    for payload in payloads:
        r = analyze_qr_content(payload)
        assert 0 <= r["risk_score"] <= 100
        assert r["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert isinstance(r["indicators"], list)


def test_content_deterministic():
    payload = "upi://pay?pa=a@upi&am=60&tn=Claim+urgently"
    assert analyze_qr_content(payload) == analyze_qr_content(payload)


def test_content_result_schema():
    for payload in ("https://example.com/", "upi://pay?pa=a@upi", "hi there"):
        r = analyze_qr_content(payload)
        for key in REQUIRED_KEYS:
            assert key in r, f"missing key {key!r}"


# ---------------------------------------------------------------------------
# 5. analyze_qr (image decoding)
# ---------------------------------------------------------------------------

def test_image_benign_url():
    r = analyze_qr(str(FIXTURES / "url_benign.png"))
    assert r["status"] == "DECODED"
    assert r["content_type"] == "url"
    assert r["decoded"] is True
    assert r["error"] is None
    assert r["risk_score"] <= 24
    assert r["url_analysis"]["url"] == "https://example.com/offer"


def test_image_suspicious_url():
    r = analyze_qr(str(FIXTURES / "url_suspicious.png"))
    assert r["status"] == "DECODED"
    assert r["content_type"] == "url"
    assert r["risk_score"] >= 50
    assert r["is_suspicious"] is True
    assert "brand_impersonation" in r["url_analysis"]["indicators"]


def test_image_normal_upi():
    r = analyze_qr(str(FIXTURES / "upi_normal.png"))
    assert r["status"] == "DECODED"
    assert r["content_type"] == "upi"
    assert r["risk_score"] <= 24
    assert r["upi_analysis"]["parse"]["payee_address"] == "merchant@upi"


def test_image_suspicious_upi():
    r = analyze_qr(str(FIXTURES / "upi_refund_scan.png"))
    assert r["status"] == "DECODED"
    assert r["content_type"] == "upi"
    assert r["risk_score"] >= 50
    assert r["is_suspicious"] is True
    assert "refund_reward_prize_language" in r["upi_analysis"]["indicators"]


def test_image_scam_text():
    r = analyze_qr(str(FIXTURES / "text_scam.png"))
    assert r["status"] == "DECODED"
    assert r["content_type"] == "text"
    assert r["risk_score"] >= 50
    assert r["message_analysis"]["is_scam"] is True


def test_image_plain_text_low():
    r = analyze_qr(str(FIXTURES / "text_plain.png"))
    assert r["content_type"] == "text"
    assert r["risk_score"] <= 24


def test_image_unknown_scheme_neutral():
    r = analyze_qr(str(FIXTURES / "unknown_scheme.png"))
    assert r["content_type"] == "unknown"
    assert r["status"] == "DECODED"
    assert r["risk_score"] == 0


def test_image_without_qr_is_safe():
    r = analyze_qr(str(FIXTURES / "no_qr_blank.png"))
    assert r["status"] == "NOT DECODED"
    assert r["decoded"] is False
    assert r["success"] is True
    assert r["risk_score"] == 0


def test_image_missing_file_error():
    r = analyze_qr(str(FIXTURES / "does_not_exist.png"))
    assert r["status"] == "ERROR"
    assert r["success"] is False
    assert r["risk_score"] == 0
    assert r["error"]


def test_image_invalid_contents_error(tmp_path):
    bad = tmp_path / "bad.png"
    bad.write_bytes(b"this is definitely not an image")
    r = analyze_qr(str(bad))
    assert r["status"] == "ERROR"
    assert r["success"] is False
    assert r["risk_score"] == 0


@pytest.mark.parametrize("fmt", ["png", "jpg", "webp"])
def test_image_formats(tmp_path, fmt):
    path = write_qr(tmp_path, f"https://example.com/fmt/{fmt}", f"qr.{fmt}", fmt)
    r = analyze_qr(str(path))
    assert r["status"] == "DECODED"
    assert r["content_type"] == "url"


def test_image_multiple_codes_combined():
    r = analyze_qr(str(FIXTURES / "multi_two_codes.png"))
    assert r["status"] == "DECODED"
    assert r["decoded_count"] == 2
    assert r["multiple_codes"] is True
    assert len(r["codes"]) == 2
    assert len(r["code_analyses"]) == 2
    combined = combine_risk_scores([a["risk_score"] for a in r["code_analyses"]])
    assert r["risk_score"] == round(combined)
    assert r["risk_score"] >= max(a["risk_score"] for a in r["code_analyses"])
    assert "multiple_qr_codes" in " ".join(e["indicator"] for e in r["explanation"])


def test_image_deterministic():
    a = analyze_qr(str(FIXTURES / "upi_refund_scan.png"))
    b = analyze_qr(str(FIXTURES / "upi_refund_scan.png"))
    assert a == b


def test_decode_multi_and_rejects_blank():
    dec = decode_qr_image(str(FIXTURES / "multi_two_codes.png"))
    assert dec["ok"] is True and dec["count"] == 2
    blank = decode_qr_image(str(FIXTURES / "no_qr_blank.png"))
    assert blank["ok"] is True and blank["decoded"] is False


# ---------------------------------------------------------------------------
# 6. Combined-risk rule
# ---------------------------------------------------------------------------

def test_combine_single_unchanged():
    assert combine_risk_scores([42]) == 42


def test_combine_order_independent():
    assert combine_risk_scores([72, 40]) == combine_risk_scores([40, 72])


def test_combine_never_below_strongest():
    strongest = max(combine_risk_scores(scores) for scores in ([72, 40], [30, 90, 50]))
    assert strongest >= 90


def test_combine_bounds():
    assert combine_risk_scores([0, 0, 0]) == 0
    assert combine_risk_scores([100, 100]) == 100
    assert 0 <= combine_risk_scores([13, 7, 42, 88]) <= 100


def test_combine_empty():
    assert combine_risk_scores([]) == 0


# ---------------------------------------------------------------------------
# 7. Security guards - no network, no execution, no payment
# ---------------------------------------------------------------------------

def test_analyze_qr_without_network(monkeypatch):
    def deny(_family, _type, *a, **k):
        raise AssertionError("network call attempted")
    monkeypatch.setattr(socket, "socket", deny)
    r = analyze_qr(str(FIXTURES / "url_suspicious.png"))
    assert r["status"] == "DECODED"
    assert r["risk_score"] >= 50


def test_analyze_content_without_network(monkeypatch):
    def deny(_family, _type, *a, **k):
        raise AssertionError("network call attempted")
    monkeypatch.setattr(socket, "socket", deny)
    r = analyze_qr_content("upi://pay?pa=a@upi&am=100000&tn=Urgent")
    assert r["risk_score"] >= 50


def test_analyze_qr_never_executes_payload(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("execution primitive called")
    monkeypatch.setattr("builtins.eval", boom)
    monkeypatch.setattr("builtins.exec", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "system", boom)
    r = analyze_qr(str(FIXTURES / "url_suspicious.png"))
    assert r["status"] == "DECODED"


def test_analyze_qr_never_opens_url(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("url open attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    r = analyze_qr(str(FIXTURES / "multi_two_codes.png"))
    assert r["status"] == "DECODED"
    assert r["risk_score"] >= 0


def test_upi_info_is_not_executed_by_monkeypatched_api(monkeypatch):
    # The UPI analysis is pure string parsing - it must not even import/use
    # any payment SDK. Patch the payment-app import surface to explode.
    import builtins
    real_import = builtins.__import__

    def guarded(name, *a, **k):
        if "upi" in name.lower() or "npci" in name.lower():
            raise AssertionError("payment SDK import attempted")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", guarded)
    r = analyze_qr_content("upi://pay?pa=store@upi&pn=Store&am=60&cu=INR")
    assert r["content_type"] == "upi"
    assert r["risk_score"] <= 24