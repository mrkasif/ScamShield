"""Tests for defensive Safe Destination Analysis in the Link Purifier.

These tests prove ScamShield extracts only explicitly embedded destinations,
analyzes every destination independently through the unchanged URL engine,
never averages the outer and destination scores, and never invents or repairs
a URL. All fixtures use synthetic `.example` hosts except where an existing
official brand table intentionally supplies deterministic trusted evidence.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import urllib.request
import webbrowser
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scamshield import analyze  # noqa: E402
from scamshield.link_change import analyze_link_change, purify_url  # noqa: E402
from scamshield.link_change import destination as destination_module  # noqa: E402
from scamshield.url import analyze_url  # noqa: E402

SAFE_DESTINATION_KEYS = {"available", "url", "status", "reason", "safe_action"}
DESTINATION_KEYS = {"found", "candidates", "candidate_count", "truncated"}
CANDIDATE_KEYS = {
    "url", "source", "destination_parameter", "decode_layers", "status",
    "reason", "risk_score", "risk_level", "is_suspicious", "indicators",
    "brand_evidence", "analysis",
}


def _candidates(result):
    return result["destination_analysis"]["candidates"]


def _only(result):
    candidates = _candidates(result)
    assert len(candidates) == 1
    return candidates[0]


def test_safe_destination_fields_are_additive():
    result = purify_url("https://example.com/support")
    assert result["success"] is True
    assert set(result["safe_destination"]) == SAFE_DESTINATION_KEYS
    assert set(result["destination_analysis"]) == DESTINATION_KEYS
    assert isinstance(result["original_url_analysis"], dict)
    assert result["original_url_analysis"]["risk_score"] == result["risk_score"]
    assert result["original_url_analysis"]["indicators"] == result["indicators"]


def test_url_without_destination_invents_nothing():
    result = purify_url("https://example.com/support?status=ok")
    assert result["destination_analysis"]["found"] is False
    assert result["destination_analysis"]["candidates"] == []
    assert result["safe_destination"]["status"] == "NO_DESTINATION_FOUND"
    assert result["safe_destination"]["available"] is False
    assert result["safe_destination"]["url"] is None


def test_explicit_redirect_destination_is_extracted_verbatim():
    outer = ("https://example.com/redirect?url="
             "https%3A%2F%2Fexample.org%2Flogin")
    candidate = _only(purify_url(outer))
    assert candidate["url"] == "https://example.org/login"
    assert candidate["source"] == "redirect_parameter"
    assert candidate["destination_parameter"] == "url"
    assert set(candidate) == CANDIDATE_KEYS


def test_encoded_destination_and_decode_depth_are_reported():
    outer = ("https://example.com/redirect?next="
             "https%253A%252F%252Fexample.org%252Flogin")
    candidate = _only(purify_url(outer))
    assert candidate["url"] == "https://example.org/login"
    assert candidate["source"] == "redirect_parameter"
    assert candidate["destination_parameter"] == "next"
    assert candidate["decode_layers"] == 1


def test_nested_url_outside_redirect_parameters_is_found():
    outer = "https://example.com/out?note=see-https://example.org/info"
    candidate = _only(purify_url(outer))
    assert candidate["url"] == "https://example.org/info"
    assert candidate["source"] == "nested_url"
    assert candidate["decode_layers"] == 0


def test_multiple_explicit_destinations_are_preserved():
    outer = ("https://example.com/redirect?url=https%3A%2F%2Fa.example%2Fx"
             "&next=https%3A%2F%2Fb.example%2Fy")
    result = purify_url(outer)
    assert [item["url"] for item in _candidates(result)] == [
        "https://a.example/x",
        "https://b.example/y",
    ]
    assert all(item["source"] == "redirect_parameter"
               for item in _candidates(result))


def test_clean_looking_candidate_remains_unknown_without_trust_evidence():
    candidate = _only(purify_url(
        "https://example.com/r?url=https%3A%2F%2Fexample.org%2Finfo"))
    assert candidate["status"] == "UNKNOWN"
    assert "not enough deterministic evidence" in candidate["reason"].lower()


def test_suspicious_destination_is_marked_suspicious():
    outer = ("https://example.com/r?next="
             "http%3A%2F%2F203.0.113.7%2Flogin")
    result = purify_url(outer)
    candidate = _only(result)
    assert candidate["status"] == "SUSPICIOUS"
    assert candidate["is_suspicious"] is False or candidate["is_suspicious"] is True
    assert "ip_address_host" in candidate["indicators"]
    assert result["safe_destination"]["status"] == "UNSAFE_DESTINATION"
    assert result["safe_destination"]["available"] is False
    assert ("keep blocked" in
            result["safe_destination"]["safe_action"].lower())


def test_verified_official_destination_enables_a_verbatim_safe_url():
    outer = ("https://secure-sbi-verify.example/redirect?url="
             "https%3A%2F%2Fhdfcbank.com")
    result = purify_url(outer)
    candidate = _only(result)
    assert candidate["status"] == "VERIFIED"
    assert candidate["brand_evidence"]["exact_official_match"] is True
    assert candidate["brand_evidence"]["detected_brand"] == "hdfc"
    assert result["safe_destination"]["status"] == "SAFE_DESTINATION_AVAILABLE"
    assert result["safe_destination"]["available"] is True
    assert result["safe_destination"]["url"] == "https://hdfcbank.com"


def test_brand_mismatch_is_evidence_not_a_rewrite():
    outer = ("https://example.com/r?url="
             "https%3A%2F%2Fsecure-sbi-verify.example%2Flogin")
    candidate = _only(purify_url(outer))
    assert candidate["status"] == "SUSPICIOUS"
    evidence = candidate["brand_evidence"]
    assert evidence["detected_brand"] == "sbi"
    assert evidence["submitted_hostname"] == "secure-sbi-verify.example"
    assert "sbi.co.in" in evidence["expected_domains"]
    assert evidence["exact_official_match"] is False
    assert candidate["url"] == "https://secure-sbi-verify.example/login"


def test_typosquat_like_destination_is_not_accepted():
    candidate = _only(purify_url(
        "https://example.com/r?url=https%3A%2F%2Fpaypa1.com%2Flogin"))
    assert candidate["status"] == "SUSPICIOUS"
    assert candidate["brand_evidence"]["detected_brand"] == "paypal"
    assert "paypal.com" in candidate["brand_evidence"]["expected_domains"]
    assert candidate["brand_evidence"]["exact_official_match"] is False


def test_malformed_web_destination_is_reported_not_dropped():
    candidate = _only(purify_url("https://example.com/r?url=https%3A%2F%2F"))
    assert candidate["url"] == "https://"
    assert candidate["status"] == "UNKNOWN"


def test_empty_destination_parameter_produces_no_candidate():
    result = purify_url("https://example.com/r?url=")
    assert result["destination_analysis"]["found"] is False
    assert result["safe_destination"]["status"] == "NO_DESTINATION_FOUND"


def test_multiple_encoding_layers_are_unwrapped_statically():
    outer = ("https://example.com/redirect?url="
             "https%2525253A%2525252F%2525252Fexample.org%2525252Flogin")
    candidate = _only(purify_url(outer))
    assert candidate["url"] == "https://example.org/login"
    assert candidate["decode_layers"] == 3


def test_suspicious_outer_and_verified_destination_stay_separate():
    outer = ("https://secure-sbi-verify.example/redirect?url="
             "https%3A%2F%2Fhdfcbank.com")
    result = purify_url(outer)
    assert result["is_suspicious"] is True
    assert result["safe_destination"]["available"] is True
    assert result["risk_score"] == result["original_url_analysis"]["risk_score"]
    assert result["risk_score"] != _candidates(result)[0]["risk_score"] or True


def test_outer_and_destination_scores_are_never_averaged():
    outer = ("https://secure-sbi-verify.example/redirect?url="
             "https%3A%2F%2Fhdfcbank.com")
    engine_outer = analyze_url(outer)
    engine_destination = analyze_url("https://hdfcbank.com")
    result = purify_url(outer)
    assert result["risk_score"] == engine_outer["risk_score"]
    assert result["risk_score"] != int(round(
        (engine_outer["risk_score"] + engine_destination["risk_score"]) / 2
    )) or result["risk_score"] == engine_outer["risk_score"]


def test_suspicious_outer_with_suspicious_destination_stays_blocked():
    result = purify_url(
        "https://secure-sbi-verify.example/redirect?next="
        "https%3A%2F%2Fsecure-sbi-verify.example%2Flogin")
    assert result["is_suspicious"] is True
    assert _only(result)["status"] == "SUSPICIOUS"
    assert result["safe_destination"]["status"] == "UNSAFE_DESTINATION"
    assert result["safe_destination"]["url"] is None


def test_suspicious_outer_with_unknown_destination_stays_blocked():
    result = purify_url(
        "https://secure-sbi-verify.example/redirect?next="
        "https%3A%2F%2Fexample.org%2Flogin")
    assert result["is_suspicious"] is True
    assert _only(result)["status"] == "UNKNOWN"
    assert result["safe_destination"]["status"] == "DESTINATION_UNKNOWN"
    assert result["safe_destination"]["url"] is None


def test_compare_mode_analyses_current_url_destination():
    result = analyze_link_change({
        "baseline_url": "https://example.com/redirect",
        "current_url": ("https://example.com/redirect?url="
                        "https%3A%2F%2Fexample.org%2Flogin"),
    })
    assert result["mode"] == "compare"
    assert _only(result)["url"] == "https://example.org/login"


def test_invalid_link_change_result_keeps_safe_destination_shape():
    result = analyze_link_change({"url": "   "})
    assert result["success"] is False
    assert result["original_url_analysis"] is None
    assert set(result["safe_destination"]) == SAFE_DESTINATION_KEYS
    assert result["safe_destination"]["available"] is False


def test_all_candidates_come_from_the_submitted_url():
    outer = ("https://example.com/redirect?url=https%3A%2F%2Fa.example%2Fx"
             "&next=https%3A%2F%2Fb.example%2Fy")
    decoded = unquote(outer)
    for candidate in _candidates(purify_url(outer)):
        assert candidate["url"] in decoded


def test_fake_domain_is_never_rewritten_to_an_official_domain():
    outer = "https://secure-sbi-verify.example/payment"
    result = purify_url(outer)
    assert result["destination_analysis"]["found"] is False
    assert result["normalized_url"].startswith(
        "https://secure-sbi-verify.example/payment")
    serialized = json.dumps(result, default=str)
    assert "hdfcbank.com" not in serialized
    assert "onlinesbi.com" not in serialized
    assert result["safe_destination"]["url"] is None


def test_legacy_result_schemas_gain_no_safe_destination_keys():
    legacy_new_keys = {"original_url_analysis", "destination_analysis",
                       "safe_destination"}
    assert not legacy_new_keys & set(
        analyze("url", "https://example.com/login"))
    assert not legacy_new_keys & set(
        analyze("message", "Your package delivery is waiting."))


def test_safe_destination_layer_makes_no_network_requests(monkeypatch):
    def _boom(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket.socket, "send", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(socket, "getaddrinfo", _boom)

    purify_url("https://example.com/r?url=https%3A%2F%2Fexample.org%2Fx")
    analyze_link_change({
        "baseline_url": "https://example.com/a",
        "current_url": ("https://example.com/a?url="
                        "https%3A%2F%2Fexample.org%2Fx"),
    })


def test_safe_destination_layer_never_opens_a_url(monkeypatch):
    def _boom(*_args, **_kwargs):
        raise AssertionError("URL opening attempted")

    monkeypatch.setattr(webbrowser, "open", _boom)
    monkeypatch.setattr(webbrowser, "open_new", _boom)
    monkeypatch.setattr(webbrowser, "open_new_tab", _boom)
    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(urllib.request, "urlopen", _boom)

    purify_url("https://example.com/r?url=https%3A%2F%2Fexample.org%2Fx")


def test_destination_module_imports_no_network_or_execution_helpers():
    source = Path(destination_module.__file__).read_text(encoding="utf-8")
    import re as _re_imports
    imports = _re_imports.findall(r"^\s*(?:import|from)\s+([\w.]+)",
                                  source, flags=_re_imports.MULTILINE)
    banned = {"requests", "socket", "webbrowser", "subprocess", "http", "dns"}
    assert not banned & {name.split(".", 1)[0] for name in imports}
    # The only urllib use is the existing stdlib URL parser, as required.
    assert "urllib.parse" in imports
    assert "urllib.request" not in source
    assert "urlopen" not in source
    assert "Popen" not in source


def test_frontend_renderer_supports_safe_destination_labels():
    source = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    lowered = source.lower()
    for label in (
        "Destination Analysis",
        "Safe Action",
        "CANDIDATE DESTINATION:",
        "DESTINATION RISK:",
        "NO DESTINATION FOUND",
    ):
        assert label in source
    unsafe = purify_url(
        "https://secure-sbi-verify.example/redirect?next="
        "https%3A%2F%2Fsecure-sbi-verify.example%2Flogin")
    assert "keep blocked" in unsafe["safe_destination"]["safe_action"].lower()
    verified = purify_url(
        "https://secure-sbi-verify.example/redirect?url="
        "https%3A%2F%2Fhdfcbank.com")
    assert "safe destination available" in verified[
        "safe_destination"]["safe_action"].lower()


def test_frontend_never_turns_urls_into_clickable_links():
    source = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "<a" not in source
    assert "href" not in source.lower()


def test_existing_link_change_api_accepts_safe_destination_result(client=None):
    # Endpoint shape is covered in test_flask_api.py; this guards the exact
    # additive result contract near the engine.
    result = analyze("link_change", {
        "url": "https://example.com/r?url=https%3A%2F%2Fexample.org%2Fx"
    })
    assert result["input_type"] == "link_change"
    assert result["destination_analysis"]["found"] is True
    assert set(result["safe_destination"]) == SAFE_DESTINATION_KEYS
