"""Focused tests for the unified Safety-Zone System + explainable risk
presentation (risk_assessment / risk_breakdown).

Guarantees covered:
* exact GREEN/YELLOW/RED boundary behaviour (0/24/25/59/60/100)
* the zone is a pure function of the EXISTING authoritative risk score
* reasons come from actual detected evidence (never fabricated)
* risk_breakdown numbers are the engine's own per-detector contributions only
* existing schemas/behavior for every legacy input type remain compatible
* the Link Purifier / Link Safety Monitor keeps working with the same zones
* Flask endpoints return the new keys and still validate
* no network access is introduced anywhere
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from web.app import create_app  # noqa: E402

from scamshield import analyze  # noqa: E402
from scamshield.safetyzones import (  # noqa: E402
    ZONES,
    _reason_for,
    build_risk_breakdown,
    build_risk_assessment,
    zone_for_score,
)

FIXTURES = _REPO_ROOT / "tests" / "fixtures" / "qr"
URL_SUSPICIOUS = f"{FIXTURES}/url_suspicious.png"

SUSPICIOUS_URL = (
    "https://secure-sbi-verify.example.com/login"
    "?redirect=https%3A%2F%2Fsuspicious.example%2Flogin"
)
BENIGN_URL = "https://example.com/hello"
SUSPICIOUS_MESSAGE = (
    "Your KYC has expired. Click this link "
    "http://verify-kyc.example.in/update to submit your OTP now."
)
UPI_SUSPICIOUS = "upi://pay?pa=scam@refunds&am=50000&tn=reward"


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


# ---------------------------------------------------------------------------
# Exact boundary behaviour (0-24 GREEN / 25-59 YELLOW / 60-100 RED)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,expected", [
    (0, "green"),
    (24, "green"),
    (25, "yellow"),
    (59, "yellow"),
    (60, "red"),
    (100, "red"),
])
def test_zone_boundaries_exact(score, expected):
    z = zone_for_score(score)
    assert z["zone"] == expected
    assert z["score"] == score
    assert z["zone_range"] == ZONES[expected]["range"]


def test_zone_labels_and_actions():
    assert ZONES["green"]["label"] == "MINIMAL / NO THREAT"
    assert ZONES["green"]["recommended_action"] == "Continue normally."
    assert ZONES["yellow"]["label"] == "RISK / CAUTION"
    assert ZONES["yellow"]["recommended_action"] == \
        "Continue only after verifying the source."
    assert ZONES["red"]["label"] == "DANGEROUS / HIGH RISK"
    assert ZONES["red"]["recommended_action"] == "STOP — Do not proceed."


def test_zone_deterministic_and_offline():
    first = zone_for_score(42)
    second = zone_for_score("42")
    assert first == second
    assert first["zone"] == "yellow"
    assert "network" not in repr(first).lower()


def test_zone_monotonic_no_overlap():
    assert zone_for_score(23)["zone"] == "green"
    assert zone_for_score(24)["zone"] == "green"
    assert zone_for_score(25)["zone"] == "yellow"
    assert zone_for_score(59)["zone"] == "yellow"
    assert zone_for_score(60)["zone"] == "red"
    assert zone_for_score(61)["zone"] == "red"


# ---------------------------------------------------------------------------
# The zone is derived from the authoritative score, never a second scorer
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("itype,content", [
    ("message", SUSPICIOUS_MESSAGE),
    ("url", SUSPICIOUS_URL),
    ("upi", UPI_SUSPICIOUS),
    ("qr", URL_SUSPICIOUS),
    ("link_change", {"url": SUSPICIOUS_URL}),
])
def test_zone_matches_authoritative_score(itype, content):
    result = analyze(itype, content)
    expected = zone_for_score(result["risk_score"])
    assert result["zone"] == expected["zone"]
    assert result["zone_label"] == expected["zone_label"]
    assert result["zone_description"] == expected["zone_description"]
    assert result["recommended_action"] == expected["recommended_action"]
    # risk_score itself is identical to the underlying engine's score.
    # For link_change the authoritative verdict comes from engine_results.url.
    engine = result["engine_results"][
        "url" if itype == "link_change" else itype
    ]
    assert result["risk_score"] == max(
        0, min(100, round(float(engine.get("risk_score", 0))))
    )


def test_suspicious_url_is_red_and_mesage_is_red():
    r = analyze("url", SUSPICIOUS_URL)
    assert r["zone"] == "red"
    assert r["zone_label"] == "DANGEROUS / HIGH RISK"
    assert r["recommended_action"].startswith("STOP")
    m = analyze("message", SUSPICIOUS_MESSAGE)
    assert m["zone"] == "red"
    assert m["risk_score"] >= 60


def test_benign_url_is_green_with_no_invented_evidence():
    r = analyze("url", BENIGN_URL)
    assert r["zone"] == "green"
    assert r["zone_label"] == "MINIMAL / NO THREAT"
    assert not r["risk_assessment"]["reasons"]
    assert r["risk_breakdown"]["factors"] == []
    assert r["risk_breakdown"]["total_contributions"] is None


# ---------------------------------------------------------------------------
# risk_assessment - structured, deterministic, evidence-backed
# ---------------------------------------------------------------------------

def test_risk_assessment_structured():
    r = analyze("url", SUSPICIOUS_URL)
    ra = r["risk_assessment"]
    for key in ("score", "zone", "level", "confidence", "summary", "reasons"):
        assert key in ra
    assert ra["score"] == r["risk_score"]
    assert ra["zone"] == r["zone"]
    assert ra["level"] == r["risk_level"]
    assert ra["reasons"]


def test_risk_assessment_deterministic():
    a = analyze("url", SUSPICIOUS_URL)["risk_assessment"]
    b = analyze("url", SUSPICIOUS_URL)["risk_assessment"]
    assert a == b


@pytest.mark.parametrize("itype,content", [
    ("url", SUSPICIOUS_URL),
    ("message", SUSPICIOUS_MESSAGE),
    ("upi", UPI_SUSPICIOUS),
    ("link_change", {"url": SUSPICIOUS_URL}),
])
def test_reasons_derive_only_from_actual_indicators(itype, content):
    r = analyze(itype, content)
    indicators = list(r["indicators"] or ())
    for e in r["explanation"] or []:
        if isinstance(e, dict) and e.get("indicator"):
            indicators.append(e["indicator"])
    assert indicators, "test sample must produce indicators"
    rebuild = {_reason_for(i) for i in indicators}
    reasons = set(r["risk_assessment"]["reasons"])
    assert reasons <= rebuild, (
        "a reason appeared that no detected indicator supports: "
        f"{reasons - rebuild}"
    )
    assert all(isinstance(x, str) and x for x in reasons)


def test_suspicious_url_reasons_cover_expected_categories():
    r = analyze("url", SUSPICIOUS_URL)
    reasons = " | ".join(r["risk_assessment"]["reasons"]).lower()
    assert "brand impersonation" in reasons
    assert "redirect" in reasons


# ---------------------------------------------------------------------------
# risk_breakdown - truthful numbers or explicit "detected factors" only
# ---------------------------------------------------------------------------

def test_breakdown_url_contributions_come_from_engine_scores():
    r = analyze("url", SUSPICIOUS_URL)
    bd = r["risk_breakdown"]
    assert bd["type"] == "engine_score_contributions"
    assert bd["authoritative_score"] == r["risk_score"]
    engine = r["engine_results"]["url"]
    expected_total = round(sum(
        max(0, float(e.get("score") or 0.0))
        for e in engine["explanation"]
    ))
    assert bd["total_contributions"] == expected_total
    assert bd["total_contributions"] >= r["risk_score"]  # engines cap their total


def test_breakdown_upi_contributions_sum_to_authoritative_score():
    r = analyze("upi", UPI_SUSPICIOUS)
    bd = r["risk_breakdown"]
    assert bd["type"] == "engine_score_contributions"
    assert bd["total_contributions"] == r["risk_score"]


def test_breakdown_message_no_fabricated_numbers():
    r = analyze("message", SUSPICIOUS_MESSAGE)
    bd = r["risk_breakdown"]
    assert bd["type"] == "detected_factors"
    assert bd["total_contributions"] is None
    assert bd["factors"]
    for factor in bd["factors"]:
        assert factor["contribution"] is None
        assert factor["indicators"]
        assert bd["authoritative_score"] == r["risk_score"]


def test_breakdown_never_alters_authoritative_score():
    for itype, content in [
        ("url", BENIGN_URL), ("url", SUSPICIOUS_URL),
        ("message", SUSPICIOUS_MESSAGE), ("upi", UPI_SUSPICIOUS),
        ("link_change", {"url": SUSPICIOUS_URL}),
    ]:
        r = analyze(itype, content)
        assert r["risk_breakdown"]["authoritative_score"] == r["risk_score"]


# ---------------------------------------------------------------------------
# Existing schemas / behavior preserved
# ---------------------------------------------------------------------------

def test_legacy_schema_keys_still_present():
    for itype, content in [
        ("message", "hello there"),
        ("url", BENIGN_URL),
        ("qr", URL_SUSPICIOUS),
        ("upi", "upi://pay?pa=a@upi&am=10&tn=hi"),
    ]:
        r = analyze(itype, content)
        for key in ("success", "input_type", "risk_score", "risk_level",
                    "is_suspicious", "scam_type", "confidence", "summary",
                    "indicators", "explanation", "recommendations", "evidence",
                    "engine_results", "warnings"):
            assert key in r, (itype, key)
        assert r["input_type"] == itype or (itype == "qr" and r["input_type"] == "qr")


def test_engine_results_identical_to_direct_engine_call():
    from scamshield.url import analyze_url
    r = analyze("url", SUSPICIOUS_URL)
    assert r["engine_results"]["url"] == analyze_url(SUSPICIOUS_URL)


def test_all_existing_types_produce_presentation():
    for itype, content in [
        ("message", "voucher gift for you"),
        ("url", "http://example.com/login"),
        ("upi", "upi://pay?pa=x@upi&am=5&cu=INR"),
        ("qr", URL_SUSPICIOUS),
        ("link_change", {"url": BENIGN_URL}),
    ]:
        r = analyze(itype, content)
        assert r["zone"] in ("green", "yellow", "red")
        assert isinstance(r["risk_assessment"], dict)
        assert isinstance(r["risk_breakdown"], dict)


# ---------------------------------------------------------------------------
# Link Purifier / Link Safety Monitor keeps working with the same zones
# ---------------------------------------------------------------------------

def test_link_change_purify_zone_and_verdict_unchanged():
    r = analyze("link_change", {"url": SUSPICIOUS_URL})
    assert r["mode"] == "purify"
    assert r["zone"] == zone_for_score(r["risk_score"])["zone"]
    # authoritative verdict still comes from the URL engine, not change_impact
    url_score = r["engine_results"]["url"]["risk_score"]
    assert r["risk_score"] == url_score
    assert r["purifier"]["redirect_detected"] is True
    assert isinstance(r["risk_assessment"]["reasons"], list)


def test_link_change_compare_monitor_unchanged():
    r = analyze("link_change", {
        "baseline_url": "https://example.com/support",
        "current_url": "https://example.com/support"
        "?redirect=https%3A%2F%2Fsuspicious.example%2Flogin",
    })
    assert r["comparison"]["compared"] is True
    assert r["comparison"]["change_count"] >= 1
    assert r["comparison"]["risk_increasing_changes"]
    assert isinstance(r["change_impact"], int) and 0 <= r["change_impact"] <= 70
    assert isinstance(r["risk_delta"], int)
    assert isinstance(r["risk_increased"], bool)
    assert r["zone"] == zone_for_score(r["risk_score"])["zone"]
    # change_impact is supplementary and never overrides the verdict
    assert r["risk_score"] == r["engine_results"]["url"]["risk_score"]


# ---------------------------------------------------------------------------
# Flask endpoints return the new keys and keep validating
# ---------------------------------------------------------------------------

def test_flask_url_endpoint_includes_safety_zone(client):
    resp = client.post("/api/analyze/url", json={"url": SUSPICIOUS_URL})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["zone"] == "red"
    assert "risk_assessment" in data
    assert "risk_breakdown" in data
    assert data["zone_label"] == "DANGEROUS / HIGH RISK"


def test_flask_link_change_endpoint_includes_safety_zone(client):
    resp = client.post("/api/analyze/link-change", json={
        "baseline_url": "https://example.com/support",
        "current_url": "https://example.com/support?redirect=suspicious.example",
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["mode"] == "compare"
    assert data["zone"] in ("green", "yellow", "red")
    assert data["comparison"]["compared"] is True
    assert "risk_assessment" in data


def test_flask_validation_errors_preserved(client):
    assert client.post("/api/analyze/url", json={"url": 123}).status_code == 400
    assert client.post("/api/analyze/link-change", json={}).status_code == 400


# ---------------------------------------------------------------------------
# No network access is introduced
# ---------------------------------------------------------------------------

def test_safety_zone_layer_makes_no_network_requests(monkeypatch):
    def _boom(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket.socket, "send", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)

    assert zone_for_score(80)["zone"] == "red"
    build_risk_assessment({"risk_score": 55, "indicators": ["urgency"]})
    build_risk_breakdown({"risk_score": 55, "indicators": ["urgency"],
                          "explanation": []})
    r = analyze("url", SUSPICIOUS_URL)
    assert r["zone"] == "red"
    analyze("link_change", {"url": SUSPICIOUS_URL})


def test_safety_zone_endpoints_make_no_network_requests(client, monkeypatch):
    def _boom(*_args, **_kwargs):
        raise AssertionError("network access attempted from Flask layer")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket.socket, "send", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)

    assert client.post("/api/analyze/url",
                       json={"url": SUSPICIOUS_URL}).status_code == 200
    assert client.post("/api/analyze/link-change",
                       json={"url": SUSPICIOUS_URL}).status_code == 200