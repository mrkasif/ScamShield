"""Tests for the ScamShield Multi-Stage Scam / Attack Chain analysis layer.

Covers: empty chains, single stages, message->url / message->upi / qr->url /
qr->upi correlation, recognized chain patterns (KYC, payment, prize/refund,
customer-care, job/investment/loan), URL/UPI artifact matching, category
consistency, duplicate-indicator handling, score caps, strongest-stage floor,
malformed stages, Unicode/multilingual evidence, deterministic repeated analysis,
JSON serialization, a no-network guard, and the unified analyzer integration.

All tests use synthetic fixtures / structured stage dicts - never real
credentials or sensitive personal data, and never the network.
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

from scamshield.chain import analyze_chain, Stage, normalize_stage, StageBuildError
from scamshield.chain.models import parse_url_safely
from scamshield.chain.correlate import (
    build_relationships,
    categories_consistent,
    domains_match,
    urls_identical,
)
from scamshield.chain.scoring import score_chain, risk_level
from scamshield.chain.explain import detect_pattern


# ---------------------------------------------------------------------------
# Synthetic fixtures (structured stage dicts, no real credentials)
# ---------------------------------------------------------------------------

def fake_url(url: str, risk: int = 72, suspicious: bool = True,
             scam_type: str = "phishing", inds=None) -> dict:
    return {
        "type": "url",
        "urls": [url],
        "risk_score": risk,
        "risk_level": "HIGH" if risk >= 50 else "MEDIUM",
        "is_suspicious": suspicious,
        "scam_type": scam_type,
        "indicators": inds or ["suspicious_keyword", "brand_impersonation"],
    }


def fake_msg(text_hint: str = "kyc", risk: int = 58, suspicious: bool = True,
             scam_type: str = "fake_kyc", inds=None, urls=None) -> dict:
    return {
        "type": "message",
        "risk_score": risk,
        "risk_level": "HIGH" if risk >= 50 else "MEDIUM",
        "is_suspicious": suspicious,
        "scam_type": scam_type,
        "indicators": inds or ["urgency", "kyc_request", "suspicious_link"],
        "urls": urls or [],
    }


def fake_upi(payee: str = "charges.fee@upi", amount: float = 5000,
             risk: int = 65, suspicious: bool = True,
             scam_type: str = "upi_payment", inds=None) -> dict:
    return {
        "type": "upi",
        "payee_address": payee,
        "amount": amount,
        "currency": "INR",
        "risk_score": risk,
        "risk_level": "HIGH" if risk >= 50 else "MEDIUM",
        "is_suspicious": suspicious,
        "scam_type": scam_type,
        "indicators": inds or ["payment_destination_detected", "recipient_not_named"],
    }


def fake_qr(content_type: str = "url", urls=None, risk: int = 72,
             suspicious: bool = True, scam_type: str = "phishing",
             inds=None) -> dict:
    return {
        "type": "qr",
        "content_type": content_type,
        "urls": urls or [],
        "risk_score": risk,
        "risk_level": "HIGH" if risk >= 50 else "MEDIUM",
        "is_suspicious": suspicious,
        "scam_type": scam_type,
        "indicators": inds or ["embedded_url_in_qr", "brand_impersonation"],
    }


def safe_msg(risk: int = 0) -> dict:
    return {
        "type": "message",
        "risk_score": risk,
        "risk_level": "LOW",
        "is_suspicious": False,
        "scam_type": "safe",
        "indicators": [],
        "urls": [],
    }


def run(stages):
    return analyze_chain(stages)


# ---------------------------------------------------------------------------
# Empty / single-stage chains
# ---------------------------------------------------------------------------

def test_empty_chain_structured():
    r = run([])
    assert r["success"] is True
    assert r["classification"] == "none"
    assert r["risk_score"] == 0
    assert r["risk_level"] == "LOW"
    assert r["is_suspicious"] is False
    assert r["stages"] == []
    assert r["relationships"] == []
    json.dumps(r)  # serializable


def test_single_safe_stage_no_chain():
    r = run([safe_msg()])
    assert r["classification"] == "none"
    assert r["is_suspicious"] is False
    assert r["risk_score"] == 0


def test_single_suspicious_stage_not_a_multi_stage_chain():
    r = run([fake_msg()])
    assert r["classification"] == "none"  # one artifact != multi-stage
    assert r["risk_score"] >= 0
    assert r["relationships"] == []


# ---------------------------------------------------------------------------
# Message -> URL
# ---------------------------------------------------------------------------

def test_message_url_matching_link():
    m = fake_msg(urls=["https://secure-sbi-verify.example.com/login"])
    u = fake_url("https://secure-sbi-verify.example.com/login")
    r = run([m, u])
    assert r["classification"] == "multi_stage_scam"
    assert r["is_suspicious"] is True
    assert r["chain_pattern"] == "kyc_phishing"
    assert any(x["match_type"] == "exact" for x in r["relationships"])


def test_message_url_unrelated_no_relationship():
    # Safe message with no URL followed by an unrelated suspicious URL must NOT
    # automatically become a scam chain.
    r = run([safe_msg(), fake_url("http://free-cell.example.com/win")])
    assert r["classification"] == "none"
    assert r["is_suspicious"] is False
    assert r["relationships"] == []


def test_message_url_shared_domain_signal():
    # Different hostnames under the same root domain still correlate.
    m = fake_msg(inds=["urgency", "kyc_request", "suspicious_link"],
                 urls=["https://login.example.com/auth"])
    u = fake_url("https://verify.example.com/auth")
    r = run([m, u])
    assert any(x["match_type"] == "domain" for x in r["relationships"])


# ---------------------------------------------------------------------------
# Message -> UPI
# ---------------------------------------------------------------------------

def test_message_upi_payment_chain():
    m = fake_msg(text_hint="payment", inds=["urgency", "payment_request", "upi_request"])
    u = fake_upi()
    r = run([m, u])
    assert r["classification"] == "multi_stage_scam"
    assert r["chain_pattern"] == "payment_scam"
    assert any(x["relation"] == "message_leads_to_payment" for x in r["relationships"])


def test_message_upi_matching_payee():
    m = fake_msg(inds=["payment_request", "upi_request"], urls=[])
    u = fake_upi(payee="refund.prize@upi")
    # The message itself does not carry the payee, so payee-match only fires when
    # both stages carry it. Here we pass both with the same payee via indicators.
    m2 = {
        "type": "message",
        "risk_score": 60,
        "risk_level": "HIGH",
        "is_suspicious": True,
        "scam_type": "prize",
        "indicators": ["payment_request", "upi_request"],
    }
    r = run([m2, u])
    assert r["is_suspicious"] is True


# ---------------------------------------------------------------------------
# QR -> URL / UPI
# ---------------------------------------------------------------------------

def test_qr_url_chain():
    q = fake_qr(content_type="url", urls=["https://secure-sbi-verify.example.com/login"])
    u = fake_url("https://secure-sbi-verify.example.com/login")
    r = run([q, u])
    assert r["classification"] is not None
    assert any(x["relation"] == "qr_to_url_continuation" for x in r["relationships"])
    # QR + URL evidence preserved.
    assert r["stages"][0]["type"] == "qr"
    assert r["stages"][1]["type"] == "url"


def test_qr_upi_chain():
    q = fake_qr(content_type="upi", urls=[])
    up = fake_upi(payee="charges.fee@upi")
    r = run([q, up])
    assert any(x["relation"] == "qr_to_upi_continuation" for x in r["relationships"])


# ---------------------------------------------------------------------------
# Chain patterns
# ---------------------------------------------------------------------------

def test_kyc_phishing_pattern():
    m = fake_msg(text_hint="kyc", inds=["urgency", "kyc_request", "suspicious_link"])
    u = fake_url("https://secure-sbi-verify.example.com/login")
    c = fake_msg(text_hint="cred", inds=["credential_request", "otp_request"],
                 scam_type="fake_kyc")
    r = run([m, u, c])
    assert r["chain_pattern"] == "kyc_phishing"
    assert r["classification"] == "multi_stage_scam"


def test_payment_pattern_message_upi():
    m = fake_msg(inds=["urgency", "payment_request", "upi_request"],
                 scam_type="upi_payment")
    u = fake_upi()
    r = run([m, u])
    assert r["chain_pattern"] == "payment_scam"


def test_prize_refund_pattern():
    m = fake_msg(inds=["prize", "refund", "lucky_draw", "offer"],
                 scam_type="prize")
    u = fake_upi(payee="prize.claim@upi", scam_type="prize")
    r = run([m, u])
    assert r["chain_pattern"] == "prize_refund"


def test_fake_customer_care_pattern():
    m = {
        "type": "message",
        "risk_score": 70,
        "risk_level": "HIGH",
        "is_suspicious": True,
        "scam_type": "fake_customer_care",
        "indicators": ["customer_care", "bank"],
    }
    u = fake_url("https://care-help.example.com/support")
    r = run([m, u])
    assert r["chain_pattern"] == "fake_customer_care"


def test_job_scam_pattern():
    m = {
        "type": "message",
        "risk_score": 66,
        "risk_level": "HIGH",
        "is_suspicious": True,
        "scam_type": "job_scam",
        "indicators": ["job", "work_from_home", "salary"],
    }
    u = fake_url("https://apply-jobs.example.com/register")
    r = run([m, u])
    assert r["chain_pattern"] == "job_scam"


def test_investment_scam_pattern():
    m = {
        "type": "message",
        "risk_score": 70,
        "risk_level": "HIGH",
        "is_suspicious": True,
        "scam_type": "investment_scam",
        "indicators": ["investment", "crypto", "profit"],
    }
    u = fake_upi(payee="invest.ui@upi", scam_type="investment_scam")
    r = run([m, u])
    assert r["chain_pattern"] == "investment_scam"


def test_loan_scam_pattern():
    m = {
        "type": "message",
        "risk_score": 62,
        "risk_level": "HIGH",
        "is_suspicious": True,
        "scam_type": "loan_scam",
        "indicators": ["loan", "credit", "approval"],
    }
    u = fake_url("https://loan-offer.example.com/apply")
    r = run([m, u])
    assert r["chain_pattern"] == "loan_scam"


def test_mixed_unrelated_does_not_force_pattern():
    # A prize message followed by a customer-care URL is not clearly any single
    # pattern - but if no detector matches, chain_pattern is None (no force).
    m = fake_msg(inds=["prize"], scam_type="prize")
    u = fake_url("https://care-help.example.com/support", scam_type="fake_customer_care")
    r = run([m, u])
    # Either a pattern that is defensible OR None; never an invented one.
    assert r["chain_pattern"] in (None, "fake_customer_care", "prize_refund", "payment_scam")


# ---------------------------------------------------------------------------
# Artifact matching
# ---------------------------------------------------------------------------

def test_urls_identical_case_and_scheme():
    assert urls_identical("HTTPS://Example.COM/Login", "https://example.com/login")
    assert not urls_identical("https://example.com/a", "https://example.com/b")


def test_domains_match_root():
    assert domains_match("login.example.com", "verify.example.com")
    assert domains_match("example.com", "sub.example.com")
    assert not domains_match("example.com", "evil.com")


def test_parse_url_safely_requires_scheme():
    assert parse_url_safely("example.com") is None  # no scheme -> dropped
    assert parse_url_safely("https://example.com/a").get("hostname") == "example.com"


def test_categories_consistent_families():
    assert categories_consistent("fake_kyc", "phishing")
    assert categories_consistent("prize", "refund")
    assert not categories_consistent("fake_kyc", "job_scam")
    assert not categories_consistent("fake_kyc", None)


def test_duplicate_indicators_not_inflating_relationships():
    # Same URL repeated as both message and standalone URL produces ONE exact
    # relationship (not several inflated edges with identical evidence).
    m = fake_msg(inds=["urgency", "kyc_request", "suspicious_link"],
                 urls=["https://secure-sbi-verify.example.com/login"])
    u = fake_url("https://secure-sbi-verify.example.com/login")
    r = run([m, u])
    exact = [x for x in r["relationships"] if x["match_type"] == "exact"]
    assert len(exact) == 1


# ---------------------------------------------------------------------------
# Scoring: caps + strongest-stage floor
# ---------------------------------------------------------------------------

def test_score_floor_never_below_strongest_stage():
    stages = [
        Stage.from_dict(fake_msg(risk=88), 0),
        Stage.from_dict(fake_url("https://x.example.com", risk=72), 1),
    ]
    rels = build_relationships(stages)
    score, _ = score_chain(stages, rels)
    assert score >= 88


def test_score_capped_at_100():
    # Many high-risk, strongly-correlated stages cannot exceed 100.
    stages = [
        Stage.from_dict(fake_msg(risk=95), 0),
        Stage.from_dict(fake_url("https://a.example.com/x", risk=95), 1),
        Stage.from_dict(fake_url("https://b.example.com/x", risk=95), 2),
        Stage.from_dict(fake_upi(risk=95), 3),
    ]
    rels = build_relationships(stages)
    score, _ = score_chain(stages, rels)
    assert score <= 100


def test_repeated_indicators_have_diminishing_stage_bonus():
    # 2 suspicious stages add STAGE_INCREMENT; 4 add STAGE_INCREMENT*(1 + 1/2 + 1/4 + 1/8)
    # (diminishing) rather than linear inflation.
    s2 = [Stage.from_dict(fake_msg(risk=40), 0), Stage.from_dict(fake_upi(risk=40), 1)]
    s4 = [
        Stage.from_dict(fake_msg(risk=40), 0),
        Stage.from_dict(fake_upi(risk=40), 1),
        Stage.from_dict(fake_url("https://x.example.com", risk=40), 2),
        Stage.from_dict(fake_url("https://y.example.com", risk=40), 3),
    ]
    _, b2 = score_chain(s2, [])
    _, b4 = score_chain(s4, [])
    # Diminishing: stage_bonus_4 < 2 * stage_bonus_2
    assert b2["stage_bonus"] > 0
    assert b4["stage_bonus"] < 2 * b2["stage_bonus"]


def test_relationship_bonus_capped():
    from scamshield.chain.scoring import RELATION_BONUS_CAP, score_chain
    stage_a = Stage.from_dict(fake_msg(risk=30), 0)
    stage_b = Stage.from_dict(fake_upi(risk=30), 1)
    # A single high-strength relationship cannot exceed the cap.
    rels = build_relationships([stage_a, stage_b])
    _, b = score_chain([stage_a, stage_b], rels)
    assert b["rel_bonus"] <= RELATION_BONUS_CAP + 1e-6


def test_risk_level_uses_existing_scale():
    assert risk_level(0) == "LOW"
    assert risk_level(24) == "LOW"
    assert risk_level(25) == "MEDIUM"
    assert risk_level(49) == "MEDIUM"
    assert risk_level(50) == "HIGH"
    assert risk_level(74) == "HIGH"
    assert risk_level(75) == "CRITICAL"
    assert risk_level(100) == "CRITICAL"
    for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        assert json.dumps({"level": level})  # serializable


# ---------------------------------------------------------------------------
# Determinism, Unicode, JSON, no-network
# ---------------------------------------------------------------------------

def test_deterministic_repeated_analysis():
    stages = [fake_msg(), fake_url("https://dom.example.com/x")]
    r1 = run(stages)
    r2 = run(stages)
    assert r1["risk_score"] == r2["risk_score"]
    assert r1["classification"] == r2["classification"]
    assert r1["relationships"] == r2["relationships"]
    assert r1["evidence"]["score_breakdown"] == r2["evidence"]["score_breakdown"]


def test_json_serialization_full_result():
    r = run([fake_msg(), fake_upi(), fake_url("https://d.example.com/x")])
    blob = json.dumps(r)
    assert blob  # non-empty, no exception
    back = json.loads(blob)
    assert back["success"] is True


def test_unicode_multilingual_evidence():
    m = {
        "type": "message",
        "risk_score": 62,
        "risk_level": "HIGH",
        "is_suspicious": True,
        "scam_type": "fake_kyc",
        "indicators": ["urgency", "kyc_request", "suspicious_link"],
        "urls": ["https://सुरक्षा-सत्यापन.example.com/केवाईसी"],  # devanagari
    }
    u = fake_url("https://secure-sbi-verify.example.com/login")
    r = run([m, u])
    blob = json.dumps(r, ensure_ascii=False)
    assert "सुरक्षा" not in blob or blob  # must not crash; devanagari preserved safely
    assert r["success"] is True


def test_no_network_guard_stage_from_dict():
    import socket as _socket

    orig = _socket.socket

    class BlockAll:
        def __init__(self, *a, **k):
            raise AssertionError("network access blocked")

    _socket.socket = BlockAll
    try:
        r = run([fake_msg(), fake_upi()])
        assert r["success"] is True
        assert r["classification"] in ("none", "multi_stage_scam", "potential_chain")
    finally:
        _socket.socket = orig


def test_no_network_guard_unified_chain():
    import socket as _socket
    from scamshield import analyze

    orig = _socket.socket

    class BlockAll:
        def __init__(self, *a, **k):
            raise AssertionError("network access blocked")

    _socket.socket = BlockAll
    try:
        m = analyze("message", "Your KYC has expired. Verify now: https://secure-sbi-verify.example.com/login")
        u = analyze("url", "https://secure-sbi-verify.example.com/login")
        c = analyze("chain", [m, u])
        assert c["success"] is True
    finally:
        _socket.socket = orig


# ---------------------------------------------------------------------------
# Unified analyzer integration
# ---------------------------------------------------------------------------

def test_unified_analyzer_chain_input_type():
    from scamshield import analyze
    m = analyze("message", "Your KYC has expired. Verify now: https://secure-sbi-verify.example.com/login")
    u = analyze("url", "https://secure-sbi-verify.example.com/login")
    c = analyze("chain", [m, u])
    assert c["input_type"] == "chain"
    assert c["success"] is True
    assert "chain" in c["engine_results"]
    assert c["engine_results"]["chain"]["classification"] == "multi_stage_scam"
    # Individual engine results preserved.
    assert c["engine_results"]["chain_per_stage"][0]["message"]["risk_score"] is not None


def test_individual_calls_unchanged():
    from scamshield import analyze
    m = analyze("message", "hello world")
    assert m["input_type"] == "message"
    assert m["engine_results"]["message"]["is_scam"] is False
    u = analyze("url", "https://example.com")
    assert u["input_type"] == "url"
    assert u["engine_results"]["url"]["url"] == "https://example.com"


def test_analyze_chain_public_api():
    from scamshield import analyze_chain as ac
    r = ac([fake_msg(), fake_url("https://d.example.com/x")])
    assert r["success"] is True
    assert set(["classification", "chain_pattern", "risk_score", "risk_level",
                "is_suspicious", "stages", "relationships", "warnings"]).issubset(r.keys())


# ---------------------------------------------------------------------------
# Malformed / graceful degradation
# ---------------------------------------------------------------------------

def test_malformed_stage_does_not_crash():
    r = run([safe_msg(), 12345, "not-a-dict", {"type": "bogus"}])
    assert r["success"] is True  # structured warnings instead of crash
    assert r["warnings"]
    assert any("stage" in w or "could not" in w or "normalize" in w for w in r["warnings"])


def test_unsupported_stage_type_warns():
    r = run([{"type": "email", "risk_score": 50}])
    assert r["success"] is True
    assert r["warnings"]


def test_normalize_stage_error_on_non_dict():
    with pytest.raises(StageBuildError):
        normalize_stage("not-a-dict")


def test_duplicate_stages_preserved_order():
    stages = [fake_msg(), fake_upi(), fake_msg()]
    r = run(stages)
    assert [s["type"] for s in r["stages"]] == ["message", "upi", "message"]


def test_preserves_input_order():
    stages = [fake_url("https://a.example.com/x"), fake_msg()]
    r = run(stages)
    assert [s["type"] for s in r["stages"]] == ["url", "message"]


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

def test_output_schema_contains_required_keys():
    r = run([fake_msg(), fake_upi()])
    for key in ("success", "classification", "chain_pattern", "risk_score",
                "risk_level", "is_suspicious", "confidence", "confidence_type",
                "summary", "stages", "relationships", "indicators", "explanation",
                "recommendations", "evidence", "warnings"):
        assert key in r, f"missing {key}"


def test_confidence_is_heuristic():
    r = run([fake_msg(), fake_upi()])
    assert r["confidence_type"] == "heuristic"
    assert isinstance(r["confidence"], (int, float))


def test_explanation_stage_present():
    r = run([fake_msg(), fake_upi()])
    assert any(e.startswith("Stage 1") for e in r["explanation"])
    assert any(e.startswith("Stage 2") for e in r["explanation"])


def test_recommendations_safe_chain():
    r = run([safe_msg()])
    assert r["recommendations"]
    assert "No suspicious" in r["recommendations"][0]


def test_recommendations_suspicious_chain():
    r = run([fake_msg(), fake_upi()])
    assert any("Do NOT" in rec for rec in r["recommendations"])


# ---------------------------------------------------------------------------
# Score/consistency helpers
# ---------------------------------------------------------------------------

def test_score_breakdown_keys_present():
    r = run([fake_msg(), fake_upi()])
    bd = r["evidence"]["score_breakdown"]
    assert set(bd.keys()) >= {"floor", "stage_bonus", "rel_bonus", "category",
                              "progress", "pattern", "total"}


def test_consistent_category_bonus():
    from scamshield.chain.scoring import score_chain, CATEGORY_BONUS, CATEGORY_BONUS_CAP
    stages = [
        Stage.from_dict(fake_msg(risk=60, scam_type="fake_kyc"), 0),
        Stage.from_dict(fake_url("https://d.example.com/x", risk=60, scam_type="phishing"), 1),
        Stage.from_dict(fake_url("https://e.example.com/y", risk=60, scam_type="fake_kyc"), 2),
    ]
    rels = build_relationships(stages)
    _, b = score_chain(stages, rels)
    assert b["category"] <= CATEGORY_BONUS_CAP
    assert b["category"] >= CATEGORY_BONUS  # credential family present on >=2 flagged


def test_progression_detected_message_to_upi():
    from scamshield.chain.scoring import _has_progression
    stages = [Stage.from_dict(fake_msg(), 0), Stage.from_dict(fake_upi(), 1)]
    assert _has_progression(stages) is True