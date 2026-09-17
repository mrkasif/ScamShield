"""Defensive safe-destination analysis for the Link Purifier / Safety Monitor.

This is an ADDITIVE interpretation layer on top of the existing URL
Intelligence engine. It never changes URL detection, scoring, schemas for
legacy result types, network behavior, or the authoritative link_change risk
verdict.

Concept:

    suspicious URL
        -> static inspection with the existing URL engine
        -> extract only destinations actually embedded in the submitted URL
        -> analyze each extracted destination independently with analyze_url()
        -> classify the destination as VERIFIED / SUSPICIOUS / UNKNOWN
        -> choose a conservative safe action

Critical non-goals, enforced by design and tests:

* never guess, repair, rewrite, canonicalize, or fuzzy-match a phishing URL
  into a presumed legitimate URL;
* never open, resolve, download, follow, execute, or otherwise access a URL;
* never claim a destination is safe merely because it parses, uses HTTPS,
  looks normal, or has no detected indicators. There must also be exact,
  deterministic trusted-domain evidence.

The trusted-domain evidence reuses the official-domain tables already used by
the existing brand-impersonation detectors (``BRAND_PROFILES``). No separate
trusted-domain registry was needed: destinations are VERIFIED only when their
exact hostname appears in an official-domain table that the existing engine
already maintains. Everything else is UNKNOWN unless the destination's own
URL analysis independently reports it as suspicious.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote

from ..url import analyze_url as _analyze_url
from ..url import domains as _domains
from ..url import indicators as _url_indicators
from ..url import parse as _parse
from ..url.patterns import (
    BRAND_PROFILES,
    COMPOUND_BRANDS,
    SUSPICIOUS_REDIRECT_PARAMS,
    WEB_SCHEMES,
)

DESTINATION_STATUSES = ("VERIFIED", "SUSPICIOUS", "UNKNOWN")
CANDIDATE_SOURCES = ("redirect_parameter", "nested_url", "encoded_url")
SAFE_DESTINATION_STATUSES = (
    "SAFE_DESTINATION_AVAILABLE",
    "UNSAFE_DESTINATION",
    "DESTINATION_UNKNOWN",
    "NO_DESTINATION_FOUND",
)

# Bounded, deterministic text handling. These are extraction limits only: they
# never suppress the existing URL detections, which inspect the whole URL.
MAX_DECODE_LAYERS = 5
MAX_DESTINATION_CANDIDATES = 5
MAX_CANDIDATE_CHARS = 2048

# Only web destinations can become a safe destination. Other schemes are left
# to the existing unusual-scheme detector on the submitted URL. The final
# character class may match zero characters so that a syntactically broken
# web destination (for example, "https://") is still reported as UNKNOWN
# rather than silently ignored.
_WEB_DESTINATION_RE = re.compile(r"https?://[^\s\"'<>`]*", re.IGNORECASE)
_TRAILING_DECORATORS = "\"'<>` \t\r\n"

# Brand signals that already carry an independent destination verdict. These
# names are copied from the existing URL engine's explanation records; the
# corresponding detector behavior is never duplicated here.
_BRAND_SIGNAL_INDICATORS = frozenset({
    "brand_impersonation",
    "brand_in_subdomain",
    "brand_in_path",
    "possible_brand_typosquatting",
})

# Destination indicators that are meaningful on their own, even when the
# destination's combined score stays below the URL engine's suspicious
# threshold. Ordinary descriptive signals (a lone security keyword, size and
# complexity measurements, a plain-HTTP scheme, or an unusual TLD) remain
# UNKNOWN rather than becoming unsupported safety claims.
_DECISIVE_DESTINATION_INDICATORS = frozenset({
    *_BRAND_SIGNAL_INDICATORS,
    "ip_address_host",
    "punycode_domain",
    "mixed_script_host",
    "hex_encoded_host",
    "embedded_credentials",
    "multiple_at",
    "confusing_userinfo",
    "unusual_scheme",
    "suspicious_redirect_parameter",
    "short_url_redirector",
    "nested_url",
    "encoded_nested_url",
    "suspicious_query_param",
})
_BRAND_TOKEN_PATTERNS = (
    re.compile(r"brand (?:term|word) '([^']+)'"),
    re.compile(r"brand name '([^']+)'"),
    re.compile(r"of the brand '([^']+)'"),
)

# Conservative Safety-Zone-aligned ceiling for a destination that has no
# indicators at all. A low score is never enough by itself; it is combined
# below with exact trusted-domain evidence.
_LOW_RISK_MAX = 24


def _official_destination_brands() -> dict[str, str]:
    """Exact official hostname -> brand key, derived from BRAND_PROFILES."""
    mapping: dict[str, str] = {}
    for brand, profile in BRAND_PROFILES.items():
        for domain in profile.get("official") or ():
            host = str(domain or "").strip().lower().rstrip(".")
            if host and host not in mapping:
                mapping[host] = brand
    return mapping


def _decode_layers(value: str) -> tuple[str, int]:
    """Percent-decode a query value a bounded number of times."""
    current = (value or "").strip()
    layers = 0
    for _ in range(MAX_DECODE_LAYERS):
        try:
            decoded = unquote(current)
        except Exception:
            break
        if decoded == current:
            break
        current = decoded
        layers += 1
        if len(current) > MAX_CANDIDATE_CHARS:
            break
    return current, layers


def _web_candidates_in_text(text: str) -> list[str]:
    """Extract complete http(s) destinations exactly as written in text."""
    found: list[str] = []
    for match in _WEB_DESTINATION_RE.finditer(text or ""):
        candidate = match.group(0).rstrip(_TRAILING_DECORATORS)
        if not candidate or len(candidate) > MAX_CANDIDATE_CHARS:
            continue
        if candidate not in found:
            found.append(candidate)
    return found


def _query_items(raw_query: str) -> list[tuple[str, str]]:
    try:
        return parse_qsl(raw_query or "", keep_blank_values=True)
    except Exception:
        return []


def _redirect_param_name(name: str) -> bool:
    """Whether a query parameter uses an existing redirect-parameter name."""
    return (name or "").lower() in SUSPICIOUS_REDIRECT_PARAMS


def _extract_parameter_candidates(raw_query: str, *, redirect_only: bool) -> list[dict]:
    """Collect destinations literally present in query-parameter values."""
    records: list[dict] = []
    seen: set[str] = set()
    for key, value in _query_items(raw_query):
        is_redirect = _redirect_param_name(key)
        if redirect_only != is_redirect:
            continue
        text = (value or "").strip()
        if not text:
            continue
        decoded, layers = _decode_layers(text)
        if len(decoded) > MAX_CANDIDATE_CHARS:
            continue
        for candidate in _web_candidates_in_text(decoded):
            if candidate in seen:
                continue
            seen.add(candidate)
            records.append({
                "url": candidate,
                "source": "redirect_parameter" if is_redirect else (
                    "encoded_url" if layers else "nested_url"
                ),
                "parameter": key,
                "decode_layers": layers,
            })
    return records


def _extract_whole_string_candidates(raw: str, have: set[str]) -> list[dict]:
    """Collect destinations from redirect-like structures outside parameters.

    This runs only when the EXISTING detectors already report a nested or
    encoded nested URL in the whole submitted string. It extracts the embedded
    addresses exactly as they appear after bounded decoding; the first match is
    the outer URL itself and is never treated as a destination.
    """
    parts = _parse.parse_url(raw)
    nested = bool(_url_indicators.detect_nested_url(raw))
    encoded = bool(_url_indicators.detect_encoded_nested_url(raw))
    if not (nested or encoded):
        return []

    decoded, layers = _decode_layers(raw)
    records: list[dict] = []
    matches = _web_candidates_in_text(decoded)
    for candidate in matches[1:]:
        if candidate in have:
            continue
        have.add(candidate)
        records.append({
            "url": candidate,
            # Exact textual nesting wins over encoding metadata: if the final
            # candidate is already present in the submitted string, call it a
            # nested URL; otherwise it was hidden by percent-encoding.
            "source": "nested_url" if candidate in raw else "encoded_url",
            "parameter": None,
            "decode_layers": layers,
            "outer_nested_url_detected": nested,
            "outer_encoded_url_detected": encoded,
            "outer_redirect_parameter_detected": bool(
                _url_indicators.detect_redirect_parameter(parts)
            ),
        })
    return records


def _candidate_records(current_url: str) -> tuple[list[dict], dict]:
    """Extract all explicit destination routes without inventing any URL."""
    raw = (current_url or "").strip()
    if not raw:
        return [], {"redirect": False, "nested": False, "encoded": False}

    parts = _parse.parse_url(raw)
    signals = {
        "redirect": bool(_url_indicators.detect_redirect_parameter(parts)),
        "nested": bool(_url_indicators.detect_nested_url(raw)),
        "encoded": bool(_url_indicators.detect_encoded_nested_url(raw)),
    }
    records = _extract_parameter_candidates(parts.get("query") or "",
                                            redirect_only=True)
    non_redirect = _extract_parameter_candidates(parts.get("query") or "",
                                                 redirect_only=False)
    have = {record["url"] for record in records}
    for record in non_redirect:
        if record["url"] in have:
            continue
        have.add(record["url"])
        records.append(record)
    records.extend(_extract_whole_string_candidates(raw, have))

    truncated = len(records) > MAX_DESTINATION_CANDIDATES
    return records[:MAX_DESTINATION_CANDIDATES], {
        "signals": signals,
        "truncated": truncated,
    }


def _brand_mention(text: str, token: str) -> bool:
    """Whether an existing brand token literally occurs in host/path text."""
    candidates = {token}
    for alias in COMPOUND_BRANDS.get(token, ()):
        if alias != token:
            candidates.add(alias.replace(" ", "-"))
    for candidate in candidates:
        if re.search(r"(?<!\w)" + re.escape(candidate) + r"(?!\w)",
                     text or "", re.IGNORECASE):
            return True
    return False


def _token_from_engine_reason(analysis: dict) -> str | None:
    """Recover the brand named by an existing brand explanation, if any."""
    for entry in analysis.get("explanation") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("indicator") not in _BRAND_SIGNAL_INDICATORS:
            continue
        reason = str(entry.get("reason") or "")
        for pattern in _BRAND_TOKEN_PATTERNS:
            match = pattern.search(reason)
            if not match:
                continue
            token = match.group(1).strip().lower()
            if token in BRAND_PROFILES and not BRAND_PROFILES[token].get("need_keyword"):
                return token
    return None


def _brand_token(candidate_url: str, analysis: dict) -> str | None:
    """Brand named by existing URL evidence, never invented by this layer."""
    indicators = set(analysis.get("indicators") or [])
    if not (indicators & _BRAND_SIGNAL_INDICATORS):
        return None
    parts = _parse.parse_url(candidate_url)
    host = (parts.get("hostname") or "").lower()
    path = (parts.get("path") or "").lower()
    for token, profile in BRAND_PROFILES.items():
        if profile.get("need_keyword"):
            continue
        if _brand_mention(host, token) or _brand_mention(path, token):
            return token
    return _token_from_engine_reason(analysis)


def _brand_evidence(url: str, analysis: dict, official: dict[str, str]) -> dict | None:
    """Evidence-only brand comparison; never rewrites the submitted domain."""
    parts = _parse.parse_url(url)
    hostname = (parts.get("hostname") or "").lower()
    if not hostname:
        return None
    token = official.get(hostname) or _brand_token(url, analysis)
    if not token:
        return None
    profile = BRAND_PROFILES.get(token) or {}
    expected = sorted({str(item) for item in profile.get("official") or () if item})
    return {
        "detected_brand": token,
        "submitted_hostname": hostname,
        "submitted_root_domain": parts.get("root_domain") or "",
        "expected_domains": expected,
        "exact_official_match": hostname in official,
    }


def _verified_destination(hostname: str, root_domain: str,
                          analysis: dict, official: dict[str, str]) -> tuple[bool, str]:
    """Conservative VERIFIED gate: trusted evidence plus clean analysis."""
    if not hostname or hostname not in official:
        return False, (
            "The destination hostname is not exactly one of the official "
            "domains already maintained by ScamShield's brand evidence."
        )
    if not root_domain:
        return False, "The destination does not expose a usable domain."
    if analysis.get("is_suspicious") is True:
        return False, (
            "Although the hostname is officially listed, the destination's own "
            "URL analysis independently reports it as suspicious."
        )
    try:
        score = int(analysis.get("risk_score", 0))
    except (TypeError, ValueError):
        return False, "The destination risk score is unavailable."
    if score > _LOW_RISK_MAX or list(analysis.get("indicators") or []):
        return False, (
            "Although the hostname is officially listed, its independent "
            "analysis contains residual risk indicators."
        )
    return True, (
        f"The destination host exactly matches {hostname}, an official domain "
        f"for {official[hostname]} in ScamShield's existing brand evidence, "
        "and its independent static analysis reports no indicators."
    )


def _classify_candidate(url: str, analysis: dict,
                        official: dict[str, str]) -> dict:
    """Classify one independently analyzed destination."""
    parts = _parse.parse_url(url)
    hostname = (parts.get("hostname") or "").lower()
    root_domain = parts.get("root_domain") or ""
    scheme = parts.get("scheme") or ""
    evidence = _brand_evidence(url, analysis, official)

    if analysis.get("is_suspicious") is True:
        indicators = sorted(set(analysis.get("indicators") or []))
        detail = ", ".join(indicators[:6]) or "independent risk verdict"
        return {
            "status": "SUSPICIOUS",
            "reason": (
                "The embedded destination itself triggered ScamShield URL "
                f"indicators ({detail}). The outer URL was not averaged with "
                "this result."
            ),
            "brand_evidence": evidence,
        }

    indicators = sorted(set(analysis.get("indicators") or []))
    decisive = sorted(set(indicators) & _DECISIVE_DESTINATION_INDICATORS)
    if decisive:
        return {
            "status": "SUSPICIOUS",
            "reason": (
                "The embedded destination itself triggered meaningful "
                f"ScamShield URL indicators ({', '.join(decisive)}), even "
                "though its combined score stayed below the URL engine's "
                "suspicious threshold. The outer URL was not averaged with "
                "this result."
            ),
            "brand_evidence": evidence,
        }

    if scheme in WEB_SCHEMES:
        trusted, reason = _verified_destination(hostname, root_domain,
                                                analysis, official)
        if trusted:
            return {"status": "VERIFIED", "reason": reason,
                    "brand_evidence": evidence}

    return {
        "status": "UNKNOWN",
        "reason": (
            "There is not enough deterministic evidence to establish this "
            "destination as safe. HTTPS, normal appearance, successful "
            "parsing, and the absence of detected indicators are not, by "
            "themselves, proof of safety."
        ),
        "brand_evidence": evidence,
    }


def _fallback_analysis(url: str) -> dict:
    return {
        "url": url,
        "parse": _parse.parse_url(url),
        "risk_score": 0,
        "risk_level": "LOW",
        "is_suspicious": False,
        "confidence": 0,
        "indicators": [],
        "explanation": [{
            "indicator": "destination_analysis_unavailable",
            "severity": "low",
            "score": 0.0,
            "reason": "The embedded destination could not be analyzed.",
        }],
        "recommendations": [],
    }


def analyze_url_destination(current_url: str) -> dict:
    """Extract and independently analyze explicit destinations in current_url.

    Returns ``original_url_analysis``, ``destination_analysis`` and
    ``safe_destination`` evidence objects. The original URL is never scored
    here, destination verdicts are never averaged, and no URL is ever opened.
    """
    raw = (current_url or "").strip()
    official = _official_destination_brands()
    empty = {
        "found": False,
        "candidates": [],
        "candidate_count": 0,
        "truncated": False,
    }
    if not raw:
        return {
            "input_url": "",
            "original_url_analysis": None,
            "destination_analysis": empty,
            "safe_destination": {
                "available": False,
                "url": None,
                "status": "NO_DESTINATION_FOUND",
                "reason": "No URL was supplied for destination inspection.",
                "safe_action": "No embedded destination detected.",
            },
        }

    records, context = _candidate_records(raw)
    candidates: list[dict] = []
    for record in records:
        candidate_url = record["url"]
        try:
            analysis = _analyze_url(candidate_url)
            if not isinstance(analysis, dict):
                raise TypeError("URL engine returned a non-dict result")
        except Exception:
            analysis = _fallback_analysis(candidate_url)
        classified = _classify_candidate(candidate_url, analysis, official)
        candidates.append({
            "url": candidate_url,
            "source": record["source"],
            "destination_parameter": record.get("parameter"),
            "decode_layers": record.get("decode_layers", 0),
            "status": classified["status"],
            "reason": classified["reason"],
            "risk_score": int(analysis.get("risk_score", 0) or 0),
            "risk_level": analysis.get("risk_level") or "LOW",
            "is_suspicious": bool(analysis.get("is_suspicious")),
            "indicators": sorted(set(analysis.get("indicators") or [])),
            "brand_evidence": classified.get("brand_evidence"),
            "analysis": analysis,
        })

    destination_analysis = {
        "found": bool(candidates),
        "candidates": candidates,
        "candidate_count": len(candidates),
        "truncated": bool(context.get("truncated")),
    }

    if not candidates:
        safe = {
            "available": False,
            "url": None,
            "status": "NO_DESTINATION_FOUND",
            "reason": (
                "No explicit embedded destination was present in the "
                "submitted URL. Nothing was invented or reconstructed."
            ),
            "safe_action": "No embedded destination detected.",
        }
    else:
        verified = [item for item in candidates if item["status"] == "VERIFIED"]
        suspicious = [item for item in candidates if item["status"] == "SUSPICIOUS"]
        if verified:
            safe = {
                "available": True,
                "url": verified[0]["url"],
                "status": "SAFE_DESTINATION_AVAILABLE",
                "reason": verified[0]["reason"],
                "safe_action": (
                    "Safe destination available. It was extracted verbatim "
                    "from the submitted URL and analyzed independently; "
                    "ScamShield does not open it automatically."
                ),
            }
        elif suspicious:
            safe = {
                "available": False,
                "url": None,
                "status": "UNSAFE_DESTINATION",
                "reason": (
                    "At least one independently analyzed destination is "
                    "itself suspicious. The outer URL score was not changed."
                ),
                "safe_action": "Destination appears suspicious — keep blocked.",
            }
        else:
            safe = {
                "available": False,
                "url": None,
                "status": "DESTINATION_UNKNOWN",
                "reason": (
                    "Embedded destination(s) were analyzed independently, "
                    "but none had enough deterministic trusted-domain "
                    "evidence to be accepted."
                ),
                "safe_action": "Destination could not be verified — keep blocked.",
            }

    return {
        "input_url": raw,
        "original_url_analysis": {
            "url": raw,
            "note": (
                "Reserved for the existing URL verdict already carried by the "
                "link_change result; destination scores are never averaged "
                "into it."
            ),
        },
        "destination_analysis": destination_analysis,
        "safe_destination": safe,
    }


__all__ = [
    "analyze_url_destination",
    "CANDIDATE_SOURCES",
    "DESTINATION_STATUSES",
    "SAFE_DESTINATION_STATUSES",
]
