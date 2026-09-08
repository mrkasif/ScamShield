"""Unit tests for the ScamShield URL Intelligence Engine.

Run with:
    python -m pytest tests/test_url_engine.py -v

Scope: static URL analysis only. The engine must never open a URL, resolve it,
follow redirects or talk to a network service. All URLs here are synthetic
(.example.com, RFC 5737 test IPs, bit.ly-style placeholders) so no live
destination is ever contacted.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scamshield.url import (  # noqa: E402
    analyze_url,
    analyze_attachment_filename,
    assess_sender,
    combine_message_and_urls,
)
from scamshield.nlp import analyze_message  # noqa: E402


# ---------------------------------------------------------------------------
# 1-2. Normal HTTPS / HTTP URLs
# ---------------------------------------------------------------------------

def test_normal_https_low():
    r = analyze_url("https://example.com/")
    assert r["risk_score"] <= 24
    assert r["risk_level"] == "LOW"
    assert r["is_suspicious"] is False
    assert r["indicators"] == []


def test_normal_http_low_for_https_false_positive_guard():
    # Plain HTTP is a small signal, never a verdict on its own.
    r = analyze_url("http://example.com/")
    assert r["risk_score"] <= 24
    assert "http_scheme" in r["indicators"]


def test_https_official_bank_url_low():
    r = analyze_url("https://www.onlinesbi.com/index.html")
    assert r["risk_score"] <= 24
    assert r["is_suspicious"] is False
    assert "brand_impersonation" not in r["indicators"]
    assert "suspicious_keyword" not in r["indicators"]


# ---------------------------------------------------------------------------
# 3. IPv4 host
# ---------------------------------------------------------------------------

def test_ipv4_url_high():
    r = analyze_url("http://192.168.1.100/login")
    assert "ip_address_host" in r["indicators"]
    assert r["risk_score"] >= 50
    assert r["is_suspicious"] is True


def test_ipv4_without_keywords_medium():
    r = analyze_url("http://54.86.116.163/")
    assert "ip_address_host" in r["indicators"]
    assert 25 <= r["risk_score"] <= 74


# ---------------------------------------------------------------------------
# 4. Punycode / IDN
# ---------------------------------------------------------------------------

def test_punycode_domain():
    r = analyze_url("http://xn--80ak6aa92e.com/pay")
    assert "punycode_domain" in r["indicators"]
    assert 0 <= r["risk_score"] <= 74  # punycode alone is moderate, not critical


# ---------------------------------------------------------------------------
# 5. Embedded credentials
# ---------------------------------------------------------------------------

def test_embedded_credentials():
    r = analyze_url("http://user:pass@example.com/")
    assert "embedded_credentials" in r["indicators"]
    assert r["risk_score"] >= 50
    assert r["is_suspicious"] is True


def test_embedded_userinfo_without_password():
    r = analyze_url("https://someone@example.com/")
    assert "embedded_credentials" in r["indicators"]


def test_host_in_userinfo_confusion():
    r = analyze_url("http://bank.example.com@evil.example/")
    assert "confusing_userinfo" in r["indicators"]
    assert r["risk_score"] >= 50


# ---------------------------------------------------------------------------
# 6. Excessively long URL
# ---------------------------------------------------------------------------

def test_excessively_long_url():
    long_url = "http://example.com/" + "a" * 300
    r = analyze_url(long_url)
    assert "long_url" in r["indicators"]
    assert 0 <= r["risk_score"] <= 100


# ---------------------------------------------------------------------------
# 7. Excessive subdomains
# ---------------------------------------------------------------------------

def test_excessive_subdomains():
    r = analyze_url("http://secure.login.verify.account.example.com/")
    assert "excessive_subdomains" in r["indicators"]
    assert r["risk_score"] >= 50
    assert r["is_suspicious"] is True


def test_normal_two_subdomains_not_flagged():
    r = analyze_url("https://mail.labs.example.com/")
    assert "excessive_subdomains" not in r["indicators"]


# ---------------------------------------------------------------------------
# 8. Suspicious query parameters
# ---------------------------------------------------------------------------

def test_suspicious_query_parameter():
    r = analyze_url("http://example.com/login?redirect=http://evil.example")
    assert "suspicious_redirect_parameter" in r["indicators"]
    assert 25 <= r["risk_score"] <= 74


def test_normal_query_parameter_not_flagged():
    r = analyze_url("https://example.com/search?q=cats")
    assert "suspicious_redirect_parameter" not in r["indicators"]


# ---------------------------------------------------------------------------
# 9. URL shortener
# ---------------------------------------------------------------------------

def test_shortener():
    r = analyze_url("http://bit.ly/xyz123")
    assert "short_url_redirector" in r["indicators"]
    assert r["risk_score"] <= 49  # a shortener alone is moderate, not critical


def test_shortener_hides_destination_explanation():
    r = analyze_url("http://bit.ly/x")
    entry = [e for e in r["explanation"] if e["indicator"] == "short_url_redirector"]
    assert entry
    assert "hides the final destination" in entry[0]["reason"]


# ---------------------------------------------------------------------------
# 10-12. Suspicious KYC / banking / brand impersonation URLs
# ---------------------------------------------------------------------------

def test_suspicious_kyc_url_keywords_only_medium():
    # Keywords alone must never be treated as a definitive scam.
    r = analyze_url("http://update-kyc.example.com/verify")
    assert "suspicious_keyword" in r["indicators"]
    assert r["risk_score"] <= 49
    assert r["is_suspicious"] is False


def test_banking_phish_url():
    r = analyze_url("http://hdfc-login.example.net/secure")
    assert "brand_impersonation" in r["indicators"]
    assert "suspicious_keyword" in r["indicators"]
    assert r["risk_score"] >= 50
    assert r["is_suspicious"] is True


def test_brand_impersonation_url():
    r = analyze_url("https://secure-sbi-verify.example.com/")
    assert "brand_impersonation" in r["indicators"]
    assert r["risk_score"] >= 50
    assert r["is_suspicious"] is True


def test_brand_token_alone_is_conservative():
    # A brand-like term on its own (no security keyword) must stay weak.
    r = analyze_url("http://sbi.example.com/")
    assert "brand_impersonation" in r["indicators"]
    assert r["risk_score"] <= 49


def test_generic_upi_token_needs_keyword():
    # "upi" is a generic token - upi.com must not be flagged.
    r = analyze_url("https://www.upi.com/")
    assert "brand_impersonation" not in r["indicators"]
    assert r["risk_score"] <= 24


# ---------------------------------------------------------------------------
# 13. Legitimate-looking
# ---------------------------------------------------------------------------

def test_legitimate_looking_bank_url_not_malicious():
    for url in ("https://www.sbi.co.in/personal",
                "https://hdfcbank.com/netbanking",
                "https://icicibank.com/nri-banking"):
        r = analyze_url(url)
        assert r["risk_score"] <= 24, f"{url} scored {r['risk_score']}"
        assert "brand_impersonation" not in r["indicators"]
        assert r["is_suspicious"] is False


# ---------------------------------------------------------------------------
# 14. Invalid / malformed URLs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "", "   ", "not a url", "::::", "http://", "://garbage",
    "http://[::1", "http://:80", "http://example.com:99999/login",
])
def test_malformed_urls_do_not_crash(bad):
    r = analyze_url(bad)
    assert 0 <= r["risk_score"] <= 100
    assert r["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ---------------------------------------------------------------------------
# 15. Unusual vs normal ports
# ---------------------------------------------------------------------------

def test_unusual_port():
    r = analyze_url("http://example.com:8080/login")
    assert "unusual_port" in r["indicators"]
    assert 25 <= r["risk_score"] <= 74


def test_normal_ports_not_suspicious():
    r1 = analyze_url("http://example.com:80/")
    r2 = analyze_url("https://example.com:443/")
    assert "unusual_port" not in r1["indicators"]
    assert "unusual_port" not in r2["indicators"]


# ---------------------------------------------------------------------------
# 16. Encoded characters
# ---------------------------------------------------------------------------

def test_encoded_characters():
    r = analyze_url("http://example.com/%76%65%72%69%66%79")
    assert "encoding_obfuscation" in r["indicators"]
    assert "suspicious_keyword" in r["indicators"]  # decodes to "verify"
    assert 0 <= r["risk_score"] <= 100


# ---------------------------------------------------------------------------
# 17. Multiple indicators together
# ---------------------------------------------------------------------------

def test_multiple_indicators_together():
    r = analyze_url("http://user:pass@192.168.1.5:8080/login?redirect=http://evil.example")
    assert r["risk_score"] >= 75
    assert r["risk_level"] == "CRITICAL"
    assert r["is_suspicious"] is True
    for ind in ("embedded_credentials", "ip_address_host", "unusual_port",
                "suspicious_keyword", "suspicious_redirect_parameter"):
        assert ind in r["indicators"]


# ---------------------------------------------------------------------------
# 18-19. Message + URL integration
# ---------------------------------------------------------------------------

def test_message_with_suspicious_url():
    m = analyze_message(
        "Your KYC has expired. Verify immediately: http://secure-sbi-verify.example.com/login"
    )
    assert isinstance(m["url_analysis"], list)
    assert len(m["url_analysis"]) == 1
    ua = m["url_analysis"][0]
    assert ua["risk_score"] >= 50
    assert ua["is_suspicious"] is True
    # Combined risk is a capped boost, never a plain average.
    assert m["combined_risk"]["score"] >= m["risk_score"]
    assert m["combined_risk"]["score"] >= ua["risk_score"]
    assert 0 <= m["combined_risk"]["score"] <= 100


def test_message_without_url():
    m = analyze_message("Hi mum, I reached campus. Call you after class.")
    assert m["url_analysis"] == []
    assert m["combined_risk"]["score"] == m["risk_score"]
    assert m["combined_risk"]["url_scores"] == []


# ---------------------------------------------------------------------------
# Combined risk rule (documented, capped, deterministic)
# ---------------------------------------------------------------------------

def test_combined_risk_rule():
    # Strong independent evidence yields more than either signal alone.
    c = combine_message_and_urls(65, [70])
    assert 65 < c["score"] < 100
    assert c["score"] > 70 or c["score"] == 100
    assert 0 <= c["score"] <= 100


def test_combined_risk_empty_urls_is_message_score():
    assert combine_message_and_urls(42, [])["score"] == 42


def test_combined_risk_capped():
    assert combine_message_and_urls(95, [95])["score"] <= 100


# ---------------------------------------------------------------------------
# Determinism, bounds and structure
# ---------------------------------------------------------------------------

ALL_URLS = [
    "https://example.com/",
    "http://example.com/",
    "http://192.168.1.100/login",
    "http://xn--80ak6aa92e.com/pay",
    "http://user:pass@example.com/",
    "http://example.com/" + "x" * 250,
    "http://secure.login.verify.account.example.com/",
    "http://example.com:8080/login",
    "http://bit.ly/xyz123",
    "http://secure-sbi-verify.example.com/",
    "https://www.onlinesbi.com/index.html",
    "garbage input",
    "https://paypal.account-verify.com/login",
    "http://paypai.com/verify",
    "https://pay\u0440al.com/x",
    "http://example.com/?next=http%3A%2F%2Fevil.example",
    "http://9876543210.com/",
    "http://7f000001.com/x",
    "https://mail.example.com/login",
]


@pytest.mark.parametrize("url", ALL_URLS)
def test_score_always_in_bounds(url):
    r = analyze_url(url)
    assert 0 <= r["risk_score"] <= 100
    assert r["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert 0 <= r["confidence"] <= 100


def test_deterministic():
    for url in ALL_URLS:
        assert analyze_url(url) == analyze_url(url)


def test_result_structure():
    r = analyze_url("http://secure-sbi-verify.example.com/login")
    for key in ("url", "parse", "risk_score", "risk_level", "is_suspicious",
                "confidence", "indicators", "explanation", "recommendations"):
        assert key in r, f"missing key {key}"
    assert isinstance(r["explanation"], list)
    assert isinstance(r["recommendations"], list)
    # Every explanation entry must be fully explainable.
    for e in r["explanation"]:
        assert "indicator" in e
        assert "severity" in e
        assert "score" in e
        assert "reason" in e


def test_parse_fields():
    r = analyze_url("http://alice:secret@example.com:8080/path?a=b#frag")
    p = r["parse"]
    assert p["scheme"] == "http"
    assert p["hostname"] == "example.com"
    assert p["port"] == 8080
    assert p["username"] == "alice"
    assert p["password"] == "secret"
    assert p["path"] == "/path"
    assert p["query"] == "a=b"
    assert p["fragment"] == "frag"


# ---------------------------------------------------------------------------
# v2. Registrable/root-domain extraction
# ---------------------------------------------------------------------------

def test_root_domain_extraction():
    cases = {
        "https://www.sbi.co.in/personal": ("sbi.co.in", "www", "co.in"),
        "https://www.google.com/": ("google.com", "www", "com"),
        "https://paypal.account-verify.com/login": ("account-verify.com", "paypal", "com"),
        "https://a.b.c.example.co.uk/": ("example.co.uk", "a.b.c", "co.uk"),
    }
    for url, (root, sub, tld) in cases.items():
        p = analyze_url(url)["parse"]
        assert p["root_domain"] == root, url
        assert p["subdomains"] == sub, url
        assert p["tld"] == tld, url


def test_brand_subdomain_placement_in_root_extraction():
    # paypal floats in the sub-domain; the registrable root is unrelated.
    r = analyze_url("https://paypal.account-verify.com/login")
    p = r["parse"]
    assert p["root_domain"] == "account-verify.com"
    assert p["subdomains"] == "paypal"


# ---------------------------------------------------------------------------
# v2. Brand in subdomain (paypal.account-verify.com)
# ---------------------------------------------------------------------------

def test_brand_in_subdomain_detected():
    r = analyze_url("https://paypal.account-verify.com/login")
    assert "brand_impersonation" in r["indicators"]
    assert "brand_in_subdomain" in r["indicators"]
    assert r["risk_score"] >= 50
    assert r["is_suspicious"] is True
    entry = [e for e in r["explanation"]
             if e["indicator"] == "brand_in_subdomain"]
    assert entry and entry[0]["evidence"] == "account-verify.com"


def test_brand_in_subdomain_not_flagged_on_official_domain():
    for url in ("https://paypal.com/signin",
                "https://www.google.co.in/",
                "https://www.paypal.co.in/account"):
        r = analyze_url(url)
        assert "brand_impersonation" not in r["indicators"], url
        assert "brand_in_subdomain" not in r["indicators"], url
        assert r["risk_score"] <= 24, url


# ---------------------------------------------------------------------------
# v2. Typosquatting / look-alike domains
# ---------------------------------------------------------------------------

def test_typosquatting_one_char_off():
    # paypaI -> paypal (homoglyph), gooogle -> google (extra letter).
    for url in ("http://paypai.com/verify", "http://gooogle.com/login"):
        r = analyze_url(url)
        assert "possible_brand_typosquatting" in r["indicators"], url
        assert 25 <= r["risk_score"] <= 49, url
        assert r["is_suspicious"] is False


def test_typosquatting_leetspeak():
    r = analyze_url("http://amaz0n.example.com/account")
    assert "possible_brand_typosquatting" in r["indicators"]
    entry = [e for e in r["explanation"]
             if e["indicator"] == "possible_brand_typosquatting"]
    assert entry and "'amaz0n'" in entry[0]["evidence"]


def test_typosquatting_not_flagged_on_official_domain():
    for url in ("https://www.google.com/",
                "https://paypal.com/",
                "https://amazon.in/"):
        assert "possible_brand_typosquatting" not in analyze_url(url)["indicators"]


def test_typosquatting_mixed_script_brand_read():
    # Cyrillic "p" (U+0440) inside "pay pal" reads as paypal.
    r = analyze_url("https://pay\u0440al.com/x")
    assert "possible_brand_typosquatting" in r["indicators"]
    assert "mixed_script_host" in r["indicators"]
    assert "internationalized_host" in r["indicators"]


# ---------------------------------------------------------------------------
# v2. Unicode / mixed-script hosts
# ---------------------------------------------------------------------------

def test_unicode_only_host_not_mixed_script():
    # All-Cyrillic name under ".com" is internationalized, NOT mixed.
    r = analyze_url("https://\u043f\u0440\u0438\u043c\u0435\u0440.com/")
    assert "internationalized_host" in r["indicators"]
    assert "mixed_script_host" not in r["indicators"]
    assert 0 <= r["risk_score"] <= 24


# ---------------------------------------------------------------------------
# v2. Suspicious query parameters
# ---------------------------------------------------------------------------

def test_suspicious_query_param_names():
    r = analyze_url("https://example.com/login?password=abc&otp=123")
    assert "suspicious_query_param" in r["indicators"]
    assert "suspicious_keyword" in r["indicators"]
    assert 25 <= r["risk_score"] <= 74
    entry = [e for e in r["explanation"]
             if e["indicator"] == "suspicious_query_param"][0]
    assert "password" in entry["evidence"] and "otp" in entry["evidence"]


def test_normal_query_params_not_flagged():
    r = analyze_url("https://example.com/search?q=cats&page=2&sort=asc")
    assert "suspicious_query_param" not in r["indicators"]
    assert "suspicious_redirect_parameter" not in r["indicators"]


# ---------------------------------------------------------------------------
# v2. Nested / encoded URLs
# ---------------------------------------------------------------------------

def test_nested_url_inside_query():
    r = analyze_url("http://example.com/a?next=http://evil.example/x")
    assert "nested_url" in r["indicators"]
    assert "suspicious_redirect_parameter" in r["indicators"]


def test_encoded_nested_url():
    r = analyze_url("http://example.com/?url=http%3A%2F%2Fevil.example")
    assert "encoded_nested_url" in r["indicators"]
    assert "suspicious_redirect_parameter" in r["indicators"]


# ---------------------------------------------------------------------------
# v2. Hex-encoded hosts
# ---------------------------------------------------------------------------

def test_hex_encoded_loopback_host():
    r = analyze_url("http://7f000001.com/x")
    assert "hex_encoded_host" in r["indicators"]
    entry = [e for e in r["explanation"] if e["indicator"] == "hex_encoded_host"]
    assert entry and "127.0.0.1" in entry[0]["evidence"]


def test_hex_public_address_not_flagged():
    # deadbeef.dec = 222.173.190.239 (a public address) - not a cloaking host.
    r = analyze_url("http://deadbeef.com/x")
    assert "hex_encoded_host" not in r["indicators"]
    assert r["risk_score"] <= 24


# ---------------------------------------------------------------------------
# v2. Hyphens, numeric domains, cheap TLDs
# ---------------------------------------------------------------------------

def test_excessive_hyphens():
    r = analyze_url("http://pay-pal-login-verify.example.com/")
    assert "excessive_hyphens" in r["indicators"]
    assert r["is_suspicious"] is False


def test_numeric_domain():
    r = analyze_url("http://9876543210.com/")
    assert "numeric_domain" in r["indicators"]
    assert r["risk_score"] <= 24


def test_unusual_tld():
    r = analyze_url("http://example.tk/login")
    assert "unusual_tld" in r["indicators"]
    assert r["risk_score"] <= 24


# ---------------------------------------------------------------------------
# v2. HTTPS is not a free pass; legit pages stay calm
# ---------------------------------------------------------------------------

def test_https_phishing_still_suspicious():
    r = analyze_url("https://secure-login-sbi.example.com/verify")
    assert "brand_impersonation" in r["indicators"]
    assert r["risk_score"] >= 50
    assert r["is_suspicious"] is True


def test_normal_login_url_not_suspicious():
    r = analyze_url("https://mail.example.com/login")
    assert "suspicious_keyword" in r["indicators"]
    assert r["risk_score"] <= 24
    assert r["is_suspicious"] is False


def test_no_indicator_url():
    r = analyze_url("https://example.com/")
    assert r["indicators"] == []
    assert r["risk_score"] == 0


# ---------------------------------------------------------------------------
# v2. Complexity cap (size alone must never push a URL to HIGH)
# ---------------------------------------------------------------------------

def test_complexity_family_is_capped():
    host = "a" * 60 + ".example.com"
    url = "http://" + host + "/" + "b" * 2000 + "?q=" + "&z=1" * 10
    r = analyze_url(url)
    fam = {"long_url", "long_hostname", "long_path", "many_query_parameters"}
    fired = [e for e in r["explanation"] if e["indicator"] in fam]
    assert fired, "expected complexity family indicators"
    assert sum(e["score"] for e in fired) <= 20.01
    assert r["risk_score"] <= 49
    assert r["is_suspicious"] is False


# ---------------------------------------------------------------------------
# v2. Message integration: legit URLs and combined-risk bounds
# ---------------------------------------------------------------------------

def test_message_with_legit_url():
    m = analyze_message("Hey, here is my profile https://example.com/about")
    assert len(m["url_analysis"]) == 1
    assert m["url_analysis"][0]["is_suspicious"] is False
    assert m["combined_risk"]["score"] == m["risk_score"]
    assert 0 <= m["combined_risk"]["score"] <= 100


def test_combined_risk_never_below_strongest_signal():
    for m_score, url_scores in ((10, [60]), (50, [78]), (90, [55]), (95, [95])):
        c = combine_message_and_urls(m_score, url_scores)
        strongest = max([m_score] + url_scores)
        assert c["score"] >= strongest, (m_score, url_scores)


# ---------------------------------------------------------------------------
# v2. Attachment metadata architecture (never executes anything)
# ---------------------------------------------------------------------------

def test_attachment_high_risk_executable():
    r = analyze_attachment_filename("invoice_2026.exe")
    assert r["attachment_present"] is True
    assert r["extension"] == ".exe"
    assert r["risk_score"] == 60
    assert r["risk_level"] == "HIGH"
    assert r["is_suspicious"] is True
    assert r["indicators"][0]["indicator"] == "high_risk_attachment"


def test_attachment_moderate_archive():
    r = analyze_attachment_filename("docs.zip")
    assert r["risk_level"] == "MEDIUM"
    assert r["is_suspicious"] is False
    assert r["indicators"][0]["indicator"] == "moderate_risk_attachment"


def test_attachment_safe_or_empty():
    safe = analyze_attachment_filename("notes.txt")
    assert safe["risk_score"] == 0
    assert safe["risk_level"] == "LOW"
    assert safe["indicators"] == []
    empty = analyze_attachment_filename("")
    assert empty["attachment_present"] is False


# ---------------------------------------------------------------------------
# v2. Sender metadata architecture (static, never sends anything)
# ---------------------------------------------------------------------------

def test_sender_brand_mismatch_detected():
    r = assess_sender("SBI Customer Care", sender_email="support@example.com")
    assert r["sender_brand_mismatch"] is True
    assert r["matched_brand"] == "sbi"
    assert any(i["indicator"] == "sender_brand_mismatch" for i in r["indicators"])


def test_sender_brand_consistent():
    r = assess_sender("SBI Customer Care", sender_email="no-reply@sbi.co.in")
    assert r["sender_brand_mismatch"] is False
    assert r["indicators"] == []


def test_sender_empty_information():
    r = assess_sender("", sender_email="")
    assert r["sender_brand_mismatch"] is False
    assert r["risk_score"] == 0


# ---------------------------------------------------------------------------
# v2. Strict offline guarantee: the engine must never touch the network
# ---------------------------------------------------------------------------

def _block_network(monkeypatch):
    import socket

    def _boom(*args, **kwargs):
        raise AssertionError("network call attempted during static analysis")

    for attr in ("socket", "create_connection", "getaddrinfo",
                 "gethostbyname", "getnameinfo"):
        monkeypatch.setattr(socket, attr, _boom)


def test_offline_analyze_url_no_network(monkeypatch):
    _block_network(monkeypatch)
    for url in ALL_URLS:
        r = analyze_url(url)
        assert r["risk_score"] == r["risk_score"]  # just bounds-checked below
        assert 0 <= r["risk_score"] <= 100
    # Determinism is preserved under the network block.
    for url in ALL_URLS:
        assert analyze_url(url) == analyze_url(url)


def test_offline_analyze_message_no_network(monkeypatch):
    _block_network(monkeypatch)
    m = analyze_message(
        "KYC expired, verify immediately http://paypal.account-verify.com/login"
    )
    assert len(m["url_analysis"]) == 1
    assert 0 <= m["combined_risk"]["score"] <= 100


def test_offline_attachment_and_sender(monkeypatch):
    _block_network(monkeypatch)
    r = analyze_attachment_filename("a.exe")
    assert r["is_suspicious"] is True
    s = assess_sender("SBI Help", "x@example.com")
    assert s["sender_brand_mismatch"] is True