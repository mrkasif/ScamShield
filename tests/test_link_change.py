"""Tests for the ScamShield Phishing Link Purifier / Link Safety Monitor.

Covers: single-link purification, baseline-vs-current change monitoring across
all planned change categories, purifier flags, risk-impact semantics, unified
analyzer + batch integration, schema stability, determinism, no-network
guarantee, and graceful handling of malformed/empty/long inputs.

Every URL is synthetic (.example domains, RFC 5737 test IPs) - nothing is ever
opened, resolved or followed.
"""
from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scamshield import analyze, analyze_batch  # noqa: E402
from scamshield.link_change import (  # noqa: E402
    analyze_link_change,
    compare_urls,
    normalize_url,
    purify_url,
)

TOP_LEVEL_KEYS = {
    "success", "input_type", "status", "risk_score", "risk_level",
    "is_suspicious", "scam_type", "confidence", "confidence_type",
    "confidence_note", "summary", "indicators", "explanation",
    "recommendations", "evidence", "engine_results", "warnings",
    # Additive safety-zone / explainability presentation (shared with every
    # unified analyzer result).
    "zone", "zone_label", "zone_description", "recommended_action",
    "risk_assessment", "risk_breakdown",
    # Additive Indian scam-intelligence interpretation (deterministic,
    # evidence-driven, offline; purely additive - see scam_intel.py).
    "scam_intelligence",
}

LINK_CHANGE_EXTRA_KEYS = {
    "mode", "original_url", "current_url", "normalized_url", "baseline_url",
    "baseline_normalized_url", "comparison", "purifier", "change_impact",
    "risk_delta", "risk_increased",
}


def _cats(result) -> list[str]:
    return [c["category"] for c in result["comparison"]["changes"]]


# ---------------------------------------------------------------------------
# Single-link purification (mode 1)
# ---------------------------------------------------------------------------

def test_purify_benign_single_link():
    r = purify_url("https://example.com/support")
    assert r["success"] is True
    assert r["mode"] == "purify"
    assert r["input_type"] == "link_change"
    assert r["risk_score"] <= 24
    assert r["risk_level"] == "LOW"
    assert r["is_suspicious"] is False
    assert r["comparison"]["compared"] is False
    assert r["comparison"]["change_count"] == 0
    # normalized representation shows the input, never rewrites it into a link
    assert r["normalized_url"] == "https://example.com/support"
    assert r["original_url"] == "https://example.com/support"
    for flag in ("redirect_detected", "nested_url_detected",
                 "encoded_destination_detected", "obfuscation_detected"):
        assert r["purifier"][flag] is False


def test_purify_redirect_flag():
    r = purify_url(
        "https://example.com/support?redirect=https%3A%2F%2Fsuspicious.example%2Flogin"
    )
    assert r["purifier"]["redirect_detected"] is True
    assert "redirect_parameter_present" in r["indicators"]
    assert r["risk_score"] >= 50


def test_purify_embedded_destination_detected():
    r = purify_url("https://example.com/out?url=https%3A%2F%2Fexample.com%2Flogin%2Fx")
    assert r["purifier"]["encoded_destination_detected"] is True
    assert r["purifier"]["nested_url_detected"] is True


def test_purify_obfuscation_flag_multiple_at():
    r = purify_url("http://bank.example.com@evil.example/login")
    assert r["purifier"]["obfuscation_detected"] is True
    assert r["is_suspicious"] is True


def test_unified_analyzer_link_change_schema():
    r = analyze("link_change", {"url": "https://example.com/support"})
    assert TOP_LEVEL_KEYS <= set(r)
    assert LINK_CHANGE_EXTRA_KEYS <= set(r)
    assert r["success"] is True
    assert r["input_type"] == "link_change"
    assert r["status"] == "ANALYSED"


def test_unified_analyzer_compare_str_and_dict_forms():
    d = analyze("link_change", {"baseline_url": "https://example.com/support",
                                "current_url": "https://example.com/support?x=1"})
    assert d["mode"] == "compare"
    assert d["comparison"]["compared"] is True


# ---------------------------------------------------------------------------
# The existing unified schema is unchanged (no extra keys on legacy types)
# ---------------------------------------------------------------------------

def test_legacy_url_schema_unchanged():
    r = analyze("url", "https://example.com/login")
    assert set(r) == TOP_LEVEL_KEYS


def test_existing_url_analyzer_output_unchanged():
    from scamshield.url import analyze_url
    a = analyze_url("https://secure-sbi-verify.example.com/login")
    assert a["risk_score"] >= 50
    assert a["indicators"] == sorted(set(a["indicators"]))
    # link_change added no detectors/indicators to the URL engine itself
    b = analyze_url("https://example.com/login")
    assert b["risk_score"] <= 24


# ---------------------------------------------------------------------------
# Comparison (mode 2) - change categories
# ---------------------------------------------------------------------------

def test_unchanged_url():
    r = compare_urls("https://example.com/support", "https://example.com/support")
    assert r["mode"] == "compare"
    assert r["comparison"]["compared"] is True
    assert r["comparison"]["change_count"] == 0
    assert r["comparison"]["risk_increasing_changes"] == []
    assert r["normalized_url"] == r["baseline_normalized_url"]


def test_domain_change():
    r = compare_urls("https://example.com/support",
                     "https://other-example.net/support")
    cats = _cats(r)
    assert {"hostname_changed", "root_domain_changed", "tld_changed"} <= set(cats)
    assert r["comparison"]["change_count"] >= 3


def test_subdomain_change():
    r = compare_urls("https://example.com/x", "https://login.example.com/x")
    assert "subdomain_changed" in _cats(r)
    assert "hostname_changed" in _cats(r)


def test_path_change():
    r = compare_urls("https://example.com/support", "https://example.com/invoice")
    assert "path_changed" in _cats(r)


def test_scheme_downgrade_risk_increasing():
    r = compare_urls("https://example.com/login", "http://example.com/login")
    assert "scheme_changed" in _cats(r)
    assert "scheme_changed" in r["comparison"]["risk_increasing_changes"]


def test_port_change():
    r = compare_urls("https://example.com/login",
                     "https://example.com:8080/login")
    assert "port_changed" in _cats(r)
    assert "port_changed" in r["comparison"]["risk_increasing_changes"]


def test_fragment_change():
    r = compare_urls("https://example.com/page#top",
                     "https://example.com/page#bottom")
    assert "fragment_changed" in _cats(r)


def test_query_parameter_added():
    r = compare_urls("https://example.com/x", "https://example.com/x?a=1")
    assert "query_parameter_added" in _cats(r)
    assert r["comparison"]["risk_increasing_changes"] == []


def test_query_parameter_removed():
    r = compare_urls("https://example.com/x?a=1", "https://example.com/x")
    assert "query_parameter_removed" in _cats(r)


def test_query_parameter_value_changed():
    r = compare_urls("https://example.com/x?a=1", "https://example.com/x?a=2")
    assert "query_parameter_value_changed" in _cats(r)
    assert r["comparison"]["risk_increasing_changes"] == []


def test_query_value_changed_to_destination_risk_increasing():
    r = compare_urls(
        "https://example.com/x?continue=https%3A%2F%2Fexample.com%2Fhome",
        "https://example.com/x?continue=https%3A%2F%2Fsuspicious.example%2Flogin",
    )
    assert "query_parameter_value_changed" in _cats(r)
    assert "query_parameter_value_changed" in r["comparison"]["risk_increasing_changes"]


def test_encoded_nested_url_in_compare():
    r = compare_urls(
        "https://example.com/redirect",
        "https://example.com/redirect?url=https%3A%2F%2Fsuspicious.example%2Flogin",
    )
    assert r["comparison"]["change_count"] >= 1
    assert r["purifier"]["encoded_destination_detected"] is True
    assert r["change_impact"] > 0


def test_redirect_parameter_added():
    r = compare_urls(
        "https://example.com/support",
        "https://example.com/support?redirect=https%3A%2F%2Fsuspicious.example%2Flogin",
    )
    assert "redirect_parameter_added" in _cats(r)
    assert "redirect_parameter_present" in _cats(r)
    assert r["comparison"]["risk_increasing_changes"] != []
    assert r["purifier"]["redirect_detected"] is True
    assert r["risk_delta"] > 0


def test_suspicious_parameter_removed_is_negative():
    r = compare_urls(
        "https://example.com/x?redirect=evil.example",
        "https://example.com/x",
    )
    removed = [c for c in r["comparison"]["changes"] if c["kind"] == "removed"]
    assert any(c["risk_impact"] == "negative" for c in removed)


def test_unicode_homoglyph_change():
    r = compare_urls("https://example.com/login", "https://payрal.example.com/login")
    assert "unicode_or_homoglyph_introduced" in _cats(r)
    assert "unicode_or_homoglyph_introduced" in r["comparison"]["risk_increasing_changes"]


def test_ip_host_transition():
    r = compare_urls("https://example.com/login", "http://203.0.113.7/login")
    assert "host_became_ip" in _cats(r)
    assert "host_became_ip" in r["comparison"]["risk_increasing_changes"]
    assert r["is_suspicious"] is True
    assert r["risk_delta"] > 0


def test_brand_impersonation_introduced():
    r = compare_urls("https://example.com/payment",
                     "https://secure-sbi-verify.example.com/payment")
    assert "brand_similarity_introduced" in _cats(r)
    assert "brand_similarity_introduced" in r["comparison"]["risk_increasing_changes"]
    assert r["is_suspicious"] is True


def test_benign_tracking_parameter_neutral():
    r = compare_urls(
        "https://example.com/page?utm_source=newsletter&ref=back",
        "https://example.com/page?utm_source=newsletter&ref=back&utm_campaign=launch",
    )
    assert "tracking_parameter_added" in _cats(r)
    assert r["comparison"]["risk_increasing_changes"] == []
    assert r["is_suspicious"] is False


def test_domain_complexity_increased():
    r = compare_urls(
        "https://example.com/login",
        "https://secure.login.verify.account.example.com/login",
    )
    assert "domain_complexity_increased" in _cats(r)
    assert r["comparison"]["risk_increasing_changes"] != []


def test_suspicious_tld_introduced():
    r = compare_urls("https://example.com/login", "https://bank-details.tk/login")
    assert "suspicious_tld_introduced" in _cats(r)


def test_multiple_comparison_cases_parametrized():
    cases = [
        ("https://example.com/a", "https://example.com/a?x=1&y=2",
         {"query_parameter_added"}),
        ("https://example.com/a", "https://sub.example.com/a",
         {"hostname_changed", "subdomain_changed"}),
        ("https://example.com/a", "https://example.com/b/c",
         {"path_changed"}),
        ("https://example.com/a#top", "https://example.com/a",
         {"fragment_changed"}),
        ("https://example.com:443/a", "https://example.com:8443/a",
         {"port_changed"}),
        ("http://example.com/a", "https://example.com/a",
         {"scheme_changed"}),
    ]
    for baseline, current, expected in cases:
        r = compare_urls(baseline, current)
        assert expected <= set(_cats(r)), (baseline, current, _cats(r))


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------

def test_very_long_input_graceful():
    long_url = "https://example.com/" + "a" * 5000
    r = purify_url(long_url)
    assert r["success"] is True
    assert 0 <= r["risk_score"] <= 100
    assert r["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_malformed_url_never_crashes():
    for garbage in ("<>", "http://", "%%%", "not a url at all", "://broken"):
        r = purify_url(garbage)
        assert isinstance(r, dict)
        assert 0 <= r["risk_score"] <= 100
        assert "normalized_url" in r


def test_empty_input_errors():
    for call in (lambda: purify_url(""), lambda: purify_url("   "),
                 lambda: compare_urls("", "https://example.com/x"),
                 lambda: analyze("link_change", {}),
                 lambda: analyze_link_change({"url": "  "})):
        r = call()
        assert r["success"] is False
        assert r["status"] == "ERROR"
        assert r["error_type"] == "validation"


def test_non_string_content_validation():
    r = analyze("link_change", 12345)
    assert r["success"] is False
    assert r["status"] == "ERROR"


def test_normalization_exposes_hidden_components():
    n = normalize_url("https://example.com/r?next=https%3A%2F%2Fevil.example%2Flogin")
    assert n["decoded_query"]
    assert any("hides a complete web address" in h for h in n["hidden_components"])


def test_determinism():
    a = compare_urls("https://example.com/a?x=1",
                     "https://example.com/a?redirect=evil.example&x=2")
    b = compare_urls("https://example.com/a?x=1",
                     "https://example.com/a?redirect=evil.example&x=2")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_analyze_batch_integrates_link_change():
    results = analyze_batch([
        {"type": "link_change", "content": {"url": "https://example.com/support"}},
        {"type": "link_change", "content": {"baseline_url": "https://example.com/a",
                                            "current_url": "https://example.com/a?x=1"}},
    ])
    assert len(results) == 2
    assert results[0]["input_type"] == "link_change"
    assert results[0]["mode"] == "purify"
    assert results[1]["comparison"]["compared"] is True


# ---------------------------------------------------------------------------
# Offline guarantee (no DNS / HTTP / socket of any kind)
# ---------------------------------------------------------------------------

def test_link_change_makes_no_network_requests(monkeypatch):
    def _boom(*_args, **_kwargs):
        raise AssertionError("network access attempted from link_change layer")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket.socket, "send", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)

    purify_url("https://example.com/support?redirect=evil.example")
    compare_urls("https://example.com/a",
                 "https://example.com/a?url=https%3A%2F%2Fsuspicious.example%2Flogin")
    analyze("link_change", {"url": "https://example.com/x"})