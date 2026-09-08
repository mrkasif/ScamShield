"""Contextual safety recommendations for the ScamShield URL engine.

Recommendations are selected from the indicators that actually fired, so the
advice always matches the evidence (this is static analysis - the engine never
opens the link).
"""

from __future__ import annotations

INDICATOR_RECOMMENDATIONS: dict[str, tuple[str, ...]] = {
    "unusual_scheme": (
        "Do not open or click non-http(s) links from unknown messages.",
        "Never run or enable scripts/payloads referenced by such links.",
    ),
    "ip_address_host": (
        "Be very cautious about links that point at raw IP addresses.",
        "Never enter passwords or OTPs on a page reached through such a link.",
    ),
    "punycode_domain": (
        "Internationalized (xn--) domains can imitate trusted names with look-alike characters.",
        "Verify the organisation on its official website before entering anything.",
    ),
    "embedded_credentials": (
        "URLs containing user:password@ are a classic phishing technique.",
        "Never enter passwords or OTPs; do not resue credentials entered via a link.",
    ),
    "long_url": (
        "Long, parameter-stuffed links are often used to hide the real destination.",
    ),
    "excessive_subdomains": (
        "Deep sub-domain stacks (e.g. secure.login.verify.account.example.com) are a phishing pattern.",
    ),
    "unusual_port": (
        "Links on non-standard ports deserve extra scrutiny before you enter data.",
    ),
    "encoding_obfuscation": (
        "Heavily percent-encoded links are often hiding keywords or the real destination.",
    ),
    "confusing_userinfo": (
        "Host-shaped text before '@' can display one site while navigating to another.",
    ),
    "multiple_at": (
        "Multiple '@' symbols are a classic trick to disguise the real destination.",
    ),
    "short_url_redirector": (
        "Shortened links hide the final destination until opened - avoid them when the sender is unknown.",
    ),
    "suspicious_keyword": (
        "Security words (login, verify, kyc, otp, payment, ...) in an unsolicited link deserve suspicion.",
    ),
    "keyword_cluster": (
        "A link stuffed with security words is far more typical of phishing than of a real website.",
    ),
    "suspicious_redirect_parameter": (
        "Do not follow links with redirect parameters from unknown senders.",
    ),
    "brand_impersonation": (
        "Domains that merely contain a brand name are not the brand's website.",
        "Verify the organisation using its official website or app before entering anything.",
        "Report suspected brand impersonation to the brand's official fraud desk.",
    ),
    "http_scheme": (
        "Prefer https:// links; never enter sensitive information over plain HTTP.",
    ),
    "excessive_separators": (
        "Extra path separators can make a link appear to come from a trusted directory.",
    ),
    "brand_in_subdomain": (
        "A brand word in a sub-domain does not make the root domain trustworthy.",
    ),
    "brand_in_path": (
        "Brand words inside a link path add fake credibility - verify the actual host.",
    ),
    "possible_brand_typosquatting": (
        "Near-miss / look-alike domain names of known brands are often phishing.",
        "Double-check the exact spelling before clicking such a link.",
    ),
    "internationalized_host": (
        "Unicode hostnames can spell a trusted brand with foreign letters.",
    ),
    "mixed_script_host": (
        "Domains mixing alphabets (Latin + Cyrillic/Devanagari/...) are a homoglyph phishing trick.",
    ),
    "suspicious_query_param": (
        "Never type passwords, OTPs, PINs or card data into a URL query string.",
    ),
    "nested_url": (
        "A web address buried inside another URL hides the real destination.",
    ),
    "encoded_nested_url": (
        "Percent-encoded '://' sequences are used to hide a nested destination.",
    ),
    "hex_encoded_host": (
        "Hex-encoded hosts can silently point at private/loopback addresses - do not open.",
    ),
    "excessive_hyphens": (
        "Hyphen-heavy domain names are typical of auto-generated scam domains.",
    ),
    "numeric_domain": (
        "Heavily numeric registrable domains are common for fraud registrations.",
    ),
    "unusual_tld": (
        "Cheap TLDs (.tk, .ml, .ga, .cf, .gq, ...) are frequent homes of abuse.",
    ),
    "long_hostname": (
        "Extremely long hostnames are typical of generated scam domains.",
    ),
    "long_path": (
        "Oversized paths are used to bury the real destination or bypass filters.",
    ),
    "many_query_parameters": (
        "Links stuffed with parameters are often obfuscating their true purpose.",
    ),
}

_ALWAYS_SUSPICIOUS: tuple[str, ...] = (
    "Do not enter passwords or OTPs through this link.",
    "Do not make payments through this link.",
    "Report the message to the relevant platform/authority.",
    "Do not open the link; block the sender if possible.",
)


def build_recommendations(findings: list[dict], is_suspicious: bool) -> list[str]:
    """Return a list of actionable recommendations based on fired indicators."""
    seen = {f.get("indicator") for f in findings}
    recs: list[str] = []

    if "embedded_credentials" in seen:
        recs.append("Do not enter passwords or OTPs.")
        recs.append("Do not make payments through the suspicious link.")
    if "unusual_scheme" in seen:
        recs.append("Do not open this link; unusual schemes can launch local programs.")
    if "ip_address_host" in seen:
        recs.append("Be wary of links pointing to a raw IP address instead of a real domain.")
    if "punycode_domain" in seen:
        recs.append("Unicode (xn--) domains can imitate trusted names - verify the real owner.")

    for indicator, tips in INDICATOR_RECOMMENDATIONS.items():
        if indicator in seen:
            for tip in tips:
                if tip not in recs:
                    recs.append(tip)

    if is_suspicious:
        for tip in _ALWAYS_SUSPICIOUS:
            if tip not in recs:
                recs.append(tip)

    if not recs:
        recs.append("The URL did not produce significant risk indicators.")
        recs.append("If you still do not recognise the sender, file it as spam.")
    return recs