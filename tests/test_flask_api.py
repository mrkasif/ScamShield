"""Integration tests for the final Flask Web Command Center.

These tests exercise the REAL ScamShield engines through the HTTP/API layer
using Flask's in-process test client (no server, no live network). They cover
every endpoint, malformed-input handling, QR temp-file cleanup, and prove the
Flask layer never performs network access.
"""
from __future__ import annotations

import io
import os
import socket
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# Import the REAL app factory (this also imports scamshield).
sys.path.insert(0, str(_REPO_ROOT))
from web import app as web_app_module  # noqa: E402
from web.app import create_app  # noqa: E402


FIXTURES = _REPO_ROOT / "tests" / "fixtures" / "qr"

SUSPICIOUS_URL = "https://secure-sbi-verify.example.com/login"
BENIGN_URL = "https://www.sbi.co.in/personal"


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_index_page_served(client) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert r.content_type.startswith("text/html")
    assert r.headers.get("Cache-Control") == "no-store"
    html = r.get_data(as_text=True)
    assert "ScamShield" in html
    assert "app.js" in html
    assert "style.css" in html
    assert "identity.css" in html
    # Frontend assets are fingerprinted so deployments cannot reuse stale CSS/JS.
    assert "v=" in html


def test_health_endpoint(client) -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["service"] == "scamshield-web"
    assert data["status"] == "ok"
    assert data["offline"] is True
    assert isinstance(data["ml_model_available"], bool)
    assert data["version"]


# ---------------------------------------------------------------------------
# Message
# ---------------------------------------------------------------------------

def test_message_scam(client) -> None:
    r = client.post("/api/analyze/message",
                    json={"message": "Your KYC has expired. Click now to verify."})
    assert r.status_code == 200
    data = r.get_json()
    assert data["success"] is True
    assert data["is_suspicious"] is True
    assert data["scam_type"] in ("fake_kyc", "phishing", "other")
    # The unified result must carry the fields the frontend renders.
    for field in ("risk_score", "risk_level", "scam_type", "confidence",
                  "indicators", "explanation", "recommendations",
                  "evidence", "engine_results", "warnings"):
        assert field in data, f"missing {field}"


def test_message_safe(client) -> None:
    r = client.post("/api/analyze/message",
                    json={"message": "Your SBI account received a credit of Rs 500."})
    data = r.get_json()
    assert data["success"] is True
    assert data["is_suspicious"] is False
    assert data["risk_score"] <= 24


def test_message_local_ml_present(client) -> None:
    r = client.post("/api/analyze/message", json={"message": "Win a free prize now"})
    data = r.get_json()
    ml = data["engine_results"].get("ml_analysis")
    assert ml is not None
    assert "model_available" in ml


def test_message_missing_field(client) -> None:
    r = client.post("/api/analyze/message", json={})
    assert r.status_code == 400
    assert r.get_json()["error_type"] == "validation"


def test_message_non_json_body(client) -> None:
    r = client.post("/api/analyze/message",
                    data="not json", content_type="text/plain")
    assert r.status_code == 400
    assert r.get_json()["error_type"] == "validation"


def test_message_empty(client) -> None:
    r = client.post("/api/analyze/message", json={"message": "   "})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# URL (must never open/resolve)
# ---------------------------------------------------------------------------

def test_url_suspicious(client) -> None:
    r = client.post("/api/analyze/url", json={"url": SUSPICIOUS_URL})
    assert r.status_code == 200
    data = r.get_json()
    assert data["success"] is True
    assert data["is_suspicious"] is True
    assert data["risk_score"] >= 50
    assert data["input_type"] == "url"
    # The web layer never opens the URL (proven by the no-network test in
    # test_flask_layer_makes_no_network_requests); the summary must not claim a
    # live/reputational verification it did not perform.
    summary = (data.get("summary") or "").lower()
    assert "verified" not in summary or "not" in summary


def test_url_benign(client) -> None:
    r = client.post("/api/analyze/url", json={"url": BENIGN_URL})
    data = r.get_json()
    assert data["success"] is True
    assert data["is_suspicious"] is False


def test_url_missing(client) -> None:
    r = client.post("/api/analyze/url", json={"url": ""})
    assert r.status_code == 400


def test_url_wrong_type(client) -> None:
    r = client.post("/api/analyze/url", json={"url": 42})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# UPI
# ---------------------------------------------------------------------------

def test_upi_normal(client) -> None:
    r = client.post("/api/analyze/upi",
                    json={"upi": "upi://pay?pa=merchant@upi&pn=Store&am=60&cu=INR"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["success"] is True
    assert data["input_type"] == "upi"
    assert data["is_suspicious"] is False


def test_upi_suspicious(client) -> None:
    r = client.post("/api/analyze/upi",
                    json={"upi": "upi://pay?pa=refund.prize@upi&am=50000&tn=Claim your refund prize now urgently"})
    data = r.get_json()
    assert data["success"] is True
    assert data["is_suspicious"] is True


def test_upi_malformed(client) -> None:
    r = client.post("/api/analyze/upi", json={"upi": None})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# QR
# ---------------------------------------------------------------------------

def _qr_upload(client, filename: str, fmt: str = "png"):
    data = (FIXTURES / filename).read_bytes() if filename else b""
    return client.post(
        "/api/analyze/qr",
        data={"qr_image": (io.BytesIO(data), filename or "x.png")},
        content_type="multipart/form-data",
    )


def test_qr_suspicious_url_image(client) -> None:
    r = _qr_upload(client, "url_suspicious.png")
    assert r.status_code == 200
    data = r.get_json()
    assert data["success"] is True
    assert data["input_type"] == "qr"
    assert data["is_suspicious"] is True


def test_qr_temp_file_cleaned_up(client) -> None:
    r = _qr_upload(client, "url_suspicious.png")
    data = r.get_json()
    assert data["success"] is True
    evidence = data.get("evidence", {}) or {}
    tmp_path = evidence.get("file")
    assert tmp_path, "QR result should expose the temp file path in evidence"
    assert os.path.exists(tmp_path) is False, \
        "temporary QR file must be deleted after analysis"


def test_qr_invalid_image_graceful(client) -> None:
    r = client.post(
        "/api/analyze/qr",
        data={"qr_image": (io.BytesIO(b"this is not an image"), "bad.png")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 200
    data = r.get_json()
    # Structured, never a crash: success False or NOT DECODED.
    assert isinstance(data, dict)
    assert "risk_score" in data


def test_qr_missing_file(client) -> None:
    r = client.post("/api/analyze/qr", data={},
                    content_type="multipart/form-data")
    assert r.status_code == 400


def test_qr_unsupported_extension(client) -> None:
    r = client.post(
        "/api/analyze/qr",
        data={"qr_image": (io.BytesIO(b"123"), "x.exe")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 400


def test_qr_oversized_rejected(monkeypatch) -> None:
    app = create_app()
    app.config["TESTING"] = True
    app.config["MAX_CONTENT_LENGTH"] = 2048
    monkeypatch.setattr(web_app_module, "MAX_QR_UPLOAD_BYTES", 1000)
    client = app.test_client()
    blob = b"0" * 1500
    r = client.post(
        "/api/analyze/qr",
        data={"qr_image": (io.BytesIO(blob), "big.png")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 413


# ---------------------------------------------------------------------------
# Chain
# ---------------------------------------------------------------------------

def test_chain_works_through_api(client) -> None:
    msg = client.post("/api/analyze/message",
                      json={"message": "Your KYC has expired. Verify now: https://secure-sbi-verify.example.com/login"}).get_json()
    url = client.post("/api/analyze/url", json={"url": SUSPICIOUS_URL}).get_json()
    cred = client.post("/api/analyze/message",
                       json={"message": "Enter your OTP and Aadhaar to unblock your account."}).get_json()
    r = client.post("/api/analyze/chain", json={"stages": [msg, url, cred]})
    assert r.status_code == 200
    data = r.get_json()
    assert data["success"] is True
    assert data["input_type"] == "chain"
    for field in ("classification", "chain_pattern", "stages",
                  "relationships", "risk_score"):
        assert field in data


def test_chain_empty_list(client) -> None:
    r = client.post("/api/analyze/chain", json={"stages": []})
    assert r.status_code == 200
    assert r.get_json()["success"] is True


def test_chain_not_a_list(client) -> None:
    r = client.post("/api/analyze/chain", json={"stages": "not-a-list"})
    assert r.status_code == 400


def test_chain_missing_stages(client) -> None:
    r = client.post("/api/analyze/chain", json={})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# General error handling
# ---------------------------------------------------------------------------

def test_unknown_route_404(client) -> None:
    assert client.get("/nope").status_code == 404


def test_wrong_method_405(client) -> None:
    assert client.get("/api/analyze/message").status_code == 405


# ---------------------------------------------------------------------------
# The Flask layer must not introduce network access
# ---------------------------------------------------------------------------

def test_flask_layer_makes_no_network_requests(client, monkeypatch) -> None:
    def _boom(*_args, **_kwargs):
        raise AssertionError("network access attempted from Flask layer")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket.socket, "send", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)

    assert client.post("/api/analyze/message",
                       json={"message": "Win a free prize now"}).status_code == 200
    assert client.post("/api/analyze/url", json={"url": SUSPICIOUS_URL}).status_code == 200
    assert client.post("/api/analyze/upi",
                       json={"upi": "upi://pay?pa=a@upi&am=10&tn=hi"}).status_code == 200
    r = _qr_upload(client, "url_suspicious.png")
    assert r.status_code == 200
    assert client.post("/api/analyze/chain", json={"stages": []}).status_code == 200
    assert client.post("/api/analyze/link-change",
                       json={"url": SUSPICIOUS_URL}).status_code == 200


# ---------------------------------------------------------------------------
# Link Purifier / Link Safety Monitor (link_change) endpoint
# ---------------------------------------------------------------------------

def test_link_change_purify_endpoint(client) -> None:
    r = client.post("/api/analyze/link-change",
                    json={"url": "https://example.com/support"})
    data = r.get_json()
    assert r.status_code == 200
    assert data["success"] is True
    assert data["input_type"] == "link_change"
    assert data["mode"] == "purify"
    assert data["comparison"]["compared"] is False


def test_link_change_compare_endpoint(client) -> None:
    r = client.post("/api/analyze/link-change",
                    json={"baseline_url": "https://example.com/support",
                          "current_url": "https://example.com/support?redirect=evil.example"})
    data = r.get_json()
    assert r.status_code == 200
    assert data["mode"] == "compare"
    assert data["comparison"]["compared"] is True
    assert data["comparison"]["change_count"] >= 1
    assert data["purifier"]["redirect_detected"] is True


def test_link_change_alias_keys(client) -> None:
    r = client.post("/api/analyze/link-change",
                    json={"baseline": "https://example.com/a",
                          "current": "https://example.com/a?x=1"})
    assert r.status_code == 200
    assert r.get_json()["mode"] == "compare"


def test_link_change_validation_errors(client) -> None:
    assert client.post("/api/analyze/link-change", json={}).status_code == 400
    assert client.post("/api/analyze/link-change",
                       json={"url": 123}).status_code == 400
    r = client.post("/api/analyze/link-change", data="nope",
                    content_type="text/plain")
    assert r.status_code == 400