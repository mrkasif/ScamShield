"""Change-category detectors for the ScamShield Link Purifier / Monitor.

Every function here is a *pure, deterministic, static* comparison between the
parsed structure of a baseline URL and a current URL (both outputs of
``scamshield.url.parse_url``). Nothing is opened, resolved, fetched or
executed - the comparison is purely lexical/structural and reuses the existing
URL-engine detectors instead of re-implementing them.

Each change record:

    {
        "category":    stable machine-readable change family,
        "kind":        "added" | "removed" | "modified" | "introduced",
        "risk_impact": "risk_increasing" | "neutral" | "negative",
        "detail":      human-readable summary of the change,
        "evidence":    the concrete artefact that changed (safe to display),
    }

``risk_impact`` describes only *whether the change leans defensive or not* -
it never replaces the authoritative URL-engine risk score (see engine.py).
"""

from __future__ import annotations

from urllib.parse import parse_qsl, unquote, urlencode

from ..url import indicators as _ind
from ..url import parse as _parse
from ..url.patterns import (
    DEFAULT_WEB_PORTS,
    SUSPICIOUS_QUERY_PARAMS,
    SUSPICIOUS_REDIRECT_PARAMS,
)

# Inductively reused: benign analytics / tracking parameter families. These
# are common on legitimate links, so changes here are intentionally NEUTRAL.
TRACKING_PARAM_SUFFIXES: tuple[str, ...] = (
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_campaignid",
)
TRACKING_PARAMS: frozenset[str] = frozenset({
    "ref", "referral", "referrer", "source", "medium", "campaign",
    "campaignid", "gclid", "fbclid", "msclkid", "twclid", "yclid",
    "clickid", "affiliate_id", "subid", "partner", "mtm_source",
    "srsltid",
})

# New indicator families that appear in the CURRENT link but not the baseline
# are mapped onto change categories (risk_increasing). Removed families map to
# the same categories with a *negative* (decreasing) impact.
NEW_INDICATOR_CHANGES: dict[str, tuple[str, str]] = {
    "ip_address_host": ("host_became_ip", "modified"),
    "internationalized_host": ("unicode_or_homoglyph_introduced", "introduced"),
    "mixed_script_host": ("unicode_or_homoglyph_introduced", "introduced"),
    "punycode_domain": ("unicode_or_homoglyph_introduced", "introduced"),
    "brand_impersonation": ("brand_similarity_introduced", "introduced"),
    "brand_in_subdomain": ("brand_similarity_introduced", "introduced"),
    "brand_in_path": ("brand_similarity_introduced", "introduced"),
    "possible_brand_typosquatting": ("brand_similarity_introduced", "introduced"),
    "unusual_tld": ("suspicious_tld_introduced", "introduced"),
    "suspicious_redirect_parameter": ("redirect_parameter_present", "introduced"),
    "nested_url": ("nested_url_appeared", "introduced"),
    "encoded_nested_url": ("encoded_destination_appeared", "introduced"),
    "encoding_obfuscation": ("encoding_increased", "introduced"),
    "excessive_subdomains": ("domain_complexity_increased", "introduced"),
    "excessive_hyphens": ("domain_complexity_increased", "introduced"),
    "numeric_domain": ("domain_complexity_increased", "introduced"),
    "long_hostname": ("domain_complexity_increased", "introduced"),
    "long_path": ("path_complexity_increased", "introduced"),
    "many_query_parameters": ("query_complexity_increased", "introduced"),
    "short_url_redirector": ("shortener_introduced", "introduced"),
    "suspicious_query_param": ("sensitive_query_parameter_added", "added"),
    "unusual_scheme": ("unusual_scheme_introduced", "introduced"),
    "http_scheme": ("plain_http_introduced", "introduced"),
}


def _params(query: str) -> dict[str, list[str]]:
    """case-insensitive param name -> ordered list of values."""
    out: dict[str, list[str]] = {}
    try:
        items = parse_qsl(query or "", keep_blank_values=True)
    except Exception:
        return out
    for key, value in items:
        out.setdefault(key.lower(), []).append(value)
    return out


def _is_redirect_param(name: str) -> bool:
    return name in SUSPICIOUS_REDIRECT_PARAMS


def _is_sensitive_param(name: str) -> bool:
    return name in SUSPICIOUS_QUERY_PARAMS


def _is_tracking_param(name: str) -> bool:
    if name in TRACKING_PARAMS:
        return True
    return any(name.endswith(suffix) for suffix in TRACKING_PARAM_SUFFIXES)


def _decoded_destination(value: str) -> bool:
    """True when the (percent-decoded) value embeds a complete web address."""
    lower = unquote(value or "").lower()
    return "://" in lower


def _record(category, kind, impact, detail, evidence) -> dict:
    return {
        "category": category,
        "kind": kind,
        "risk_impact": impact,
        "detail": detail,
        "evidence": evidence or "",
    }


def _query_param_records(b_base: dict, b_cur: dict, baseline, current) -> list[dict]:
    """added / removed / value-changed query parameters (most specific first).

    A single added parameter that is also a redirect parameter yields ONE
    record (the specialised one), never a duplicate generic record.
    """
    recs: list[dict] = []

    def _values(values) -> str:
        return ", ".join(v or "<blank>" for v in values)

    for name in sorted(b_cur):
        added = b_cur[name]
        if name in b_base:
            continue
        vals = _values(added)
        if _is_redirect_param(name):
            recs.append(_record(
                "redirect_parameter_added", "added", "risk_increasing",
                f"Query parameter '{name}' was added; redirect-type parameters "
                "bounce the reader to another location.",
                f"{name}={vals}",
            ))
        elif any(_decoded_destination(v) for v in added):
            recs.append(_record(
                "destination_like_value_added", "added", "risk_increasing",
                f"Added parameter '{name}' carries a value that looks like a "
                "complete web address (possibly encoded).",
                f"{name}={vals}",
            ))
        elif _is_sensitive_param(name):
            recs.append(_record(
                "sensitive_query_parameter_added", "added", "risk_increasing",
                f"Added parameter '{name}' has a name that asks for or carries "
                "sensitive data (password, OTP, card, ...).",
                f"{name}={vals}",
            ))
        elif _is_tracking_param(name):
            recs.append(_record(
                "tracking_parameter_added", "added", "neutral",
                f"Added tracking/analytics parameter '{name}'.",
                f"{name}={vals}",
            ))
        else:
            recs.append(_record(
                "query_parameter_added", "added", "neutral",
                f"Query parameter '{name}' was added.",
                f"{name}={vals}",
            ))

    for name in sorted(b_base):
        if name in b_cur:
            continue
        vals = _values(b_base[name])
        if _is_redirect_param(name) or _is_sensitive_param(name):
            recs.append(_record(
                "suspicious_query_parameter_removed", "removed", "negative",
                f"Suspicious parameter '{name}' was removed.",
                f"{name}={vals}",
            ))
        else:
            recs.append(_record(
                "query_parameter_removed", "removed", "neutral",
                f"Query parameter '{name}' was removed.",
                f"{name}={vals}",
            ))

    for name in sorted(b_cur):
        if name not in b_base:
            continue
        if b_base[name] != b_cur[name]:
            impact = "risk_increasing" if _is_redirect_param(name) or \
                any(_decoded_destination(v) for v in b_cur[name]) else "neutral"
            recs.append(_record(
                "query_parameter_value_changed", "modified", impact,
                f"Value of query parameter '{name}' changed.",
                f"{name}: {_values(b_base[name])} -> {_values(b_cur[name])}",
            ))

    return recs


def _indicator_changes(baseline: dict, current: dict) -> list[dict]:
    """New/removed detected indicators mapped onto change categories.

    Indicator-based records are only produced when the baseline is a usable
    URL so a broken/empty baseline cannot make every detector look 'new'.
    """
    if not baseline.get("ok") or not (baseline.get("hostname") or ""):
        return []

    b_set = {f["indicator"] for f in _ind.detect_all(baseline)}
    c_set = {f["indicator"] for f in _ind.detect_all(current)}
    recs: list[dict] = []
    for name in sorted(c_set - b_set):
        entry = NEW_INDICATOR_CHANGES.get(name)
        if entry is None:
            continue
        category, kind = entry
        reason = _indicator_reason(name)
        recs.append(_record(category, kind, "risk_increasing",
                            f"{reason.capitalize()} in the current link only.",
                            name))
    for name in sorted(b_set - c_set):
        entry = NEW_INDICATOR_CHANGES.get(name)
        if entry is None:
            continue
        category, _kind = entry
        recs.append(_record(category, "removed", "negative",
                            f"A suspicious signal ({name}) present in the "
                            "baseline is gone from the current link.",
                            name))
    return recs


def _indicator_reason(name: str) -> str:
    reasons = {
        "ip_address_host": "the host became a raw IP address",
        "internationalized_host": "raw Unicode characters appeared in the host",
        "mixed_script_host": "the domain label now mixes alphabets (homoglyph risk)",
        "punycode_domain": "an internationalized (xn--) label appeared in the host",
        "brand_impersonation": "possible brand impersonation appeared",
        "brand_in_subdomain": "a brand word appeared in a sub-domain",
        "brand_in_path": "a brand word appeared in the path",
        "possible_brand_typosquatting": "a brand look-alike domain appeared",
        "unusual_tld": "a suspicious top-level domain appeared",
        "suspicious_redirect_parameter": "a redirect-type parameter appeared",
        "nested_url": "another web address is nested inside the link",
        "encoded_nested_url": "an encoded web address is hidden inside the link",
        "encoding_obfuscation": "heavy percent-encoding appeared",
        "excessive_subdomains": "excessive sub-domain nesting appeared",
        "excessive_hyphens": "excessive hyphens appeared in the host",
        "numeric_domain": "a mostly-numeric domain appeared",
        "long_hostname": "an unusually long hostname appeared",
        "long_path": "an unusually long path appeared",
        "many_query_parameters": "a parameter-stuffed query appeared",
        "short_url_redirector": "a URL-shortener host appeared",
        "suspicious_query_param": "sensitive query parameter names appeared",
        "unusual_scheme": "a non-web scheme appeared",
        "http_scheme": "the scheme fell back to plain HTTP",
    }
    return reasons.get(name, f"the '{name}' signal")


def _encoding_change(baseline: dict, current: dict) -> list[dict]:
    b_raw = baseline.get("raw") or ""
    c_raw = current.get("raw") or ""
    b_pct = b_raw.count("%")
    c_pct = c_raw.count("%")
    if c_pct >= 4 and c_pct > b_pct:
        return [_record(
            "encoding_increased", "introduced", "risk_increasing",
            "Percent-encoding (obfuscation) increased between the two links.",
            f"{b_pct} -> {c_pct} encoded characters",
        )]
    return []


def detect_changes(baseline: dict, current: dict) -> list[dict]:
    """Compare two parsed URLs and return ALL detected change records.

    Deterministic: records are sorted by (category, kind) and never reference
    the network.
    """
    b = baseline or {}
    c = current or {}
    recs: list[dict] = []

    b_scheme = b.get("scheme") or ""
    c_scheme = c.get("scheme") or ""
    if b_scheme != c_scheme and b_scheme and c_scheme:
        if c_scheme == "http" and b_scheme == "https":
            impact = "risk_increasing"
        elif c_scheme == "https" and b_scheme == "http":
            impact = "negative"
        else:
            impact = "neutral"
        recs.append(_record("scheme_changed", "modified", impact,
                            f"The scheme changed from '{b_scheme}' to '{c_scheme}'.",
                            f"{b_scheme} -> {c_scheme}"))

    b_host = b.get("hostname") or ""
    c_host = c.get("hostname") or ""
    if b_host and c_host and b_host != c_host:
        recs.append(_record("hostname_changed", "modified", "neutral",
                            "The hostname changed.",
                            f"{b_host} -> {c_host}"))
        b_root = b.get("root_domain") or ""
        c_root = c.get("root_domain") or ""
        if b_root != c_root:
            recs.append(_record("root_domain_changed", "modified", "neutral",
                                "The registrable/root domain changed.",
                                f"{b_root} -> {c_root}"))
        b_sub = b.get("subdomains") or ""
        c_sub = c.get("subdomains") or ""
        if b_sub != c_sub:
            recs.append(_record("subdomain_changed", "modified", "neutral",
                                "The sub-domain structure changed.",
                                f"'{b_sub or '(none)'}' -> '{c_sub or '(none)'}'"))
        b_tld = b.get("tld") or ""
        c_tld = c.get("tld") or ""
        if b_tld != c_tld:
            recs.append(_record("tld_changed", "modified", "neutral",
                                "The top-level domain changed.",
                                f".{b_tld} -> .{c_tld}"))

    b_port = b.get("port")
    c_port = c.get("port")
    if b_port != c_port:
        if c_port is not None and c_port not in DEFAULT_WEB_PORTS:
            impact = "risk_increasing"
        elif b_port is not None and b_port not in DEFAULT_WEB_PORTS:
            impact = "negative"
        else:
            impact = "neutral"
        recs.append(_record("port_changed", "modified", impact,
                            "The explicit port changed.",
                            _port(b_port) + " -> " + _port(c_port)))

    b_path = b.get("path") or ""
    c_path = c.get("path") or ""
    if b_path != c_path:
        recs.append(_record("path_changed", "modified", "neutral",
                            "The path changed.",
                            _short(b_path) + " -> " + _short(c_path)))

    b_frag = b.get("fragment") or ""
    c_frag = c.get("fragment") or ""
    if b_frag != c_frag:
        recs.append(_record("fragment_changed", "modified", "neutral",
                            "The URL fragment changed.",
                            f"#{b_frag or '(none)'} -> #{c_frag or '(none)'}"))

    recs += _query_param_records(_params(b.get("query") or ""),
                                 _params(c.get("query") or ""), b, c)
    recs += _indicator_changes(b, c)
    recs += _encoding_change(b, c)

    # Deduplicate deterministically (keeps the same shape for equal URLs).
    seen: set[tuple] = set()
    out: list[dict] = []
    for r in sorted(recs, key=lambda r: (r["category"], r["kind"])):
        key = (r["category"], r["kind"], r.get("evidence", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _port(port) -> str:
    return "" if port is None else str(port)


def _short(value: str) -> str:
    value = value or ""
    return value if len(value) <= 60 else value[:57] + "..."


__all__ = [
    "detect_changes",
    "TRACKING_PARAMS",
    "TRACKING_PARAM_SUFFIXES",
    "NEW_INDICATOR_CHANGES",
]