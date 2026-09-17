"""Phishing Link Purifier / Link Safety Monitor - engine entry point.

Static, local, deterministic defensive analysis of URL structure. It supports
two modes:

* ``purify_url(url)``             - MODE 1 (single-link purification): safely
  normalize + inspect one URL, surface hidden/encoded components and reuse the
  existing URL Intelligence detectors for the authoritative risk verdict.

* ``compare_urls(baseline, current)`` - MODE 2 (link change monitor): compare a
  previously observed link against the current one and report structural
  changes, redirect-like parameters, nested/encoded destinations and risk
  trends.

Security model (identical to the rest of ScamShield):

    * never opens, resolves, crawls, downloads, executes or follows a URL;
    * no DNS lookups, no HTTP requests, no browser automation, no redirect
      following, no downloading, no execution, no external threat-intel API,
      no paid API - analysis is 100% offline and operates on the URL string.

"Purified" means *safe normalization and inspection only*. This module never
repairs, generates, mutates, disguises or weaponizes URLs; the normalized
representation's only purpose is to expose the structure so a human can inspect
it. ``normalized_url`` always keeps the input separate from the normalized
form and never "fixes" a dangerous URL into a working one.

Scoring principle: the authoritative ``risk_score`` / ``risk_level`` /
``is_suspicious`` are ALWAYS the existing URL Intelligence engine's verdict on
the current link (``scamshield.url.analyze_url``). The comparison produces an
informative ``change_impact`` (capped) and a list of
``risk_increasing_changes`` that can never override the engine verdict.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, unquote, urlencode

from ..url import analyze_url as _analyze_url
from ..url import parse as _parse
from ..url.patterns import DEFAULT_WEB_PORTS, WEB_SCHEMES
from .destination import analyze_url_destination

CONFIDENCE_NOTE = (
    "Heuristic confidence estimate, not a calibrated statistical probability."
)

RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# Per-category heuristic weighting for the informative change-impact number.
# The impact is capped well below CRITICAL so it can never replace the
# authoritative URL-engine score (which is what drives risk_score/level).
CHANGE_IMPACT_POINTS: dict[str, float] = {
    "redirect_parameter_added": 12.0,
    "redirect_parameter_present": 12.0,
    "destination_like_value_added": 12.0,
    "encoded_destination_appeared": 12.0,
    "nested_url_appeared": 10.0,
    "host_became_ip": 20.0,
    "brand_similarity_introduced": 14.0,
    "unicode_or_homoglyph_introduced": 10.0,
    "encoding_increased": 8.0,
    "domain_complexity_increased": 6.0,
    "suspicious_tld_introduced": 6.0,
    "shortener_introduced": 10.0,
    "sensitive_query_parameter_added": 8.0,
    "unusual_scheme_introduced": 12.0,
    "plain_http_introduced": 4.0,
    "path_complexity_increased": 4.0,
    "query_complexity_increased": 4.0,
}
CHANGE_IMPACT_CAP: int = 70

OBFUSCATION_INDICATORS = frozenset({
    "encoding_obfuscation", "hex_encoded_host", "punycode_domain",
    "internationalized_host", "mixed_script_host", "multiple_at",
    "confusing_userinfo", "embedded_credentials", "excessive_separators",
})


# ---------------------------------------------------------------------------
# Safe normalization / purification (display-only; never repairs)
# ---------------------------------------------------------------------------

def _is_default_port(parts: dict) -> bool:
    port = parts.get("port")
    if port is None:
        return True
    if port in DEFAULT_WEB_PORTS:
        return True
    scheme = parts.get("scheme") or ""
    return (scheme == "http" and port == 80) or (scheme == "https" and port == 443)


def normalize_url(url: str) -> dict:
    """Return a safe, display-oriented normalized representation of a URL.

    Normalization is for INSPECTION ONLY. It lower-cases the host, drops a
    bare default port, re-orders query parameters deterministically and
    percent-decodes a copy of the path/query to expose hidden components. It
    NEVER repairs the URL: a malformed or dangerous URL is returned verbatim
    (in ``normalized_url``) so the reader can see the gap.
    """
    parts = _parse.parse_url(url)
    raw = parts.get("raw") or ""
    if not raw:
        return {
            "raw": "", "ok": False, "normalized": "", "hostname": "",
            "root_domain": "", "decoded_path": "", "decoded_query": "",
            "decoded_values": [], "hidden_components": [],
        }

    scheme = parts.get("scheme") or ""
    hostname = parts.get("hostname") or ""
    path = parts.get("path") or ""
    query = parts.get("query") or ""
    fragment = parts.get("fragment") or ""

    decoded_path = unquote(path)
    decoded_query = unquote(query)
    decoded_values = [
        {"name": k, "value": unquote(v)}
        for k, v in parse_qsl(query, keep_blank_values=True)
    ]

    hidden: list[str] = []
    for kv in decoded_values:
        value = kv["value"].lower()
        if "://" in value:
            hidden.append(
                f"parameter '{kv['name']}' hides a complete web address "
                "in its (decoded) value"
            )
    if (parts.get("raw") or "").count("://") > 1 or \
            unquote(parts.get("raw") or "").count("://") > 1:
        hidden.append("another web address is nested inside the URL")

    normalized = raw
    if scheme in WEB_SCHEMES and hostname:
        netloc = hostname
        if not _is_default_port(parts):
            netloc += f":{parts.get('port')}"
        norm_query = urlencode(
            sorted(parse_qsl(query, keep_blank_values=True)), doseq=True
        )
        normalized = (f"{scheme}://{netloc}{path}"
                      + (f"?{norm_query}" if norm_query else "")
                      + (f"#{fragment}" if fragment else ""))

    return {
        "raw": raw,
        "ok": bool(hostname or scheme or path),
        "scheme": scheme,
        "hostname": hostname,
        "root_domain": parts.get("root_domain") or "",
        "path": path,
        "query": query,
        "fragment": fragment,
        "normalized": normalized,
        "decoded_path": decoded_path,
        "decoded_query": decoded_query,
        "decoded_values": decoded_values,
        "hidden_components": hidden,
    }


# ---------------------------------------------------------------------------
# Purifier flag aggregation (reuses the URL-engine detectors)
# ---------------------------------------------------------------------------

def _purifier_flags(url_result: dict, norm: dict) -> dict:
    indicators = set(url_result.get("indicators") or [])
    raw = norm.get("raw") or ""
    decoded_raw = unquote(raw).lower()
    nested_visible = raw.count("://") > 1
    nested_hidden = decoded_raw.count("://") > raw.count("://")

    redirect_detected = bool(
        indicators & {"suspicious_redirect_parameter", "short_url_redirector"}
    ) or nested_visible
    nested_detected = bool(indicators & {"nested_url", "encoded_nested_url"}) or \
        nested_visible or nested_hidden
    encoded_destination = bool(
        indicators & {"encoded_nested_url", "nested_url"}
    ) or any("://" in (v.get("value") or "").lower()
             for v in norm.get("decoded_values") or [])
    obfuscation = bool(indicators & OBFUSCATION_INDICATORS) or \
        bool(norm.get("hidden_components"))

    return {
        "redirect_detected": redirect_detected,
        "nested_url_detected": nested_detected,
        "encoded_destination_detected": encoded_destination,
        "obfuscation_detected": obfuscation,
        "hidden_components": norm.get("hidden_components") or [],
        "purified_representation": {
            "raw": norm.get("raw") or "",
            "normalized": norm.get("normalized") or "",
            "decoded_path": norm.get("decoded_path") or "",
            "decoded_query": norm.get("decoded_query") or "",
            "decoded_values": norm.get("decoded_values") or [],
        },
    }


# ---------------------------------------------------------------------------
# Result assembly (shared schema + link_change feature fields)
# ---------------------------------------------------------------------------

def _risk_level(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _explain_entry(indicator, severity, reason, evidence="", score=0.0) -> dict:
    return {
        "indicator": indicator,
        "severity": severity,
        "score": score,
        "reason": reason,
        "evidence": evidence,
    }


def _build_result(*, mode: str, original: str, current: str,
                  normalized: dict, baseline_norm: dict | None,
                  url_result: dict, baseline_url_result: dict | None,
                  changes: list[dict], flags: dict, destination: dict) -> dict:
    """Assemble one link_change result with the existing unified schema."""
    score = int(max(0, min(100, url_result.get("risk_score", 0))))
    level = _risk_level(score)
    suspicious = bool(url_result.get("is_suspicious"))
    indicators = set(url_result.get("indicators") or [])

    compared = mode == "compare" and baseline_norm is not None

    risk_increasing = [
        c["category"] for c in changes if c["risk_impact"] == "risk_increasing"
    ]
    risk_increasing = _unique(risk_increasing)

    flag_indicators = {
        "redirect_parameter_present": flags["redirect_detected"],
        "nested_url_present": flags["nested_url_detected"],
        "encoded_destination_present": flags["encoded_destination_detected"],
        "obfuscation_present": flags["obfuscation_detected"],
    }
    for name, active in flag_indicators.items():
        if active:
            indicators.add(name)
    if compared and changes:
        indicators.add("link_changed_from_baseline")

    change_impact = _change_impact(changes, flags)
    risk_delta = 0
    risk_increased = False
    original_url_analysis = {
        "url": current,
        "risk_score": score,
        "risk_level": level,
        "is_suspicious": suspicious,
        "indicators": sorted(indicators),
    }
    if compared and baseline_url_result is not None:
        b_score = int(max(0, min(100, baseline_url_result.get("risk_score", 0))))
        risk_delta = score - b_score
        risk_increased = risk_delta > 0

    explanation = _explanation(mode, url_result, changes, change_impact,
                               risk_increased)
    recommendations = _recommendations(url_result, flags, mode, compared,
                                       risk_increased)
    summary = _summary(mode, normalized, url_result, changes, compared,
                       risk_increased, score)

    outcomes = {
        "success": True,
        "input_type": "link_change",
        "status": "ANALYSED",
        "mode": mode,
        "original_url": original,
        "current_url": current,
        "normalized_url": normalized.get("normalized") or current,
        "baseline_url": None,
        "baseline_normalized_url": None,
        "comparison": {
            "compared": False,
            "changes": [],
            "change_count": 0,
            "risk_increasing_changes": [],
        },
        "purifier": flags,
        "risk_score": score,
        "risk_level": level,
        "is_suspicious": suspicious,
        "scam_type": "phishing" if suspicious else "safe",
        "confidence": url_result.get("confidence", 0),
        "confidence_type": "heuristic",
        "confidence_note": CONFIDENCE_NOTE,
        "change_impact": change_impact,
        "risk_delta": risk_delta,
        "risk_increased": risk_increased,
        "original_url_analysis": original_url_analysis,
        "destination_analysis": destination.get("destination_analysis"),
        "safe_destination": destination.get("safe_destination"),
        "summary": summary,
        "indicators": sorted(indicators),
        "explanation": explanation,
        "recommendations": recommendations,
        "evidence": _evidence(mode, normalized, baseline_norm, url_result),
        "engine_results": {
            "link_change": _feature_view(mode, normalized, baseline_norm,
                                         changes, flags, destination),
            "url": url_result,
        },
        "warnings": _warnings(mode, normalized),
    }

    if compared:
        outcomes["baseline_url"] = (baseline_norm or {}).get("raw") or ""
        outcomes["baseline_normalized_url"] = (baseline_norm or {}).get("normalized") or ""
        outcomes["comparison"] = {
            "compared": True,
            "changes": changes,
            "change_count": len(changes),
            "risk_increasing_changes": risk_increasing,
        }
        if baseline_url_result is not None:
            outcomes["engine_results"]["baseline_url"] = baseline_url_result

    return outcomes


def _feature_view(mode, normalized, baseline_norm, changes, flags, destination) -> dict:
    return {
        "mode": mode,
        "normalized_url": normalized.get("normalized") or "",
        "baseline_normalized_url": (baseline_norm or {}).get("normalized") or "",
        "decoded_path": normalized.get("decoded_path") or "",
        "decoded_query": normalized.get("decoded_query") or "",
        "decoded_values": normalized.get("decoded_values") or [],
        "changes": changes,
        "purifier_flags": flags,
        "destination_analysis": destination.get("destination_analysis"),
        "safe_destination": destination.get("safe_destination"),
    }


def _change_impact(changes: list[dict], flags: dict) -> int:
    total = 0.0
    for c in changes:
        if c["risk_impact"] == "risk_increasing":
            total += float(CHANGE_IMPACT_POINTS.get(c["category"], 4.0))
    if flags.get("encoded_destination_detected"):
        total += 5.0
    if flags.get("obfuscation_detected"):
        total += 3.0
    total = min(float(CHANGE_IMPACT_CAP), total)
    return int(round(total))


def _explanation(mode, url_result, changes, change_impact, risk_increased):
    entries = []
    for c in changes:
        if c["risk_impact"] != "risk_increasing":
            continue
        sev = "high" if c["category"] in CHANGE_IMPACT_POINTS and \
            CHANGE_IMPACT_POINTS[c["category"]] >= 12 else "medium"
        entries.append(_explain_entry(
            "link_change_" + c["category"], sev, c["detail"], c.get("evidence", ""),
        ))
    if mode == "compare" and change_impact > 0:
        entries.append(_explain_entry(
            "link_change_impact", "medium",
            f"The structural comparison increased concern by a capped "
            f"heuristic impact of {change_impact}/70; the authoritative URL "
            "risk score is unchanged by this estimate.",
            score=0.0,
        ))
    if risk_increased:
        entries.append(_explain_entry(
            "link_risk_increased", "medium",
            "The current link scores higher than the baseline in the existing "
            "URL Intelligence engine.",
            score=0.0,
        ))
    entries += [
        _explain_entry(e.get("indicator", "pattern"), (e.get("severity") or "low"),
                       e.get("reason") or "A risk pattern was detected.",
                       e.get("evidence") or "", e.get("score") or 0.0)
        for e in (url_result.get("explanation") or [])
    ]
    return entries


def _recommendations(url_result, flags, mode, compared, risk_increased):
    recs = [str(r) for r in (url_result.get("recommendations") or [])]
    if flags.get("redirect_detected"):
        recs.append(
            "The link contains a redirect-type mechanism. Verify the final "
            "destination through the organisation's official website/app before "
            "clicking."
        )
    if flags.get("nested_url_detected") or flags.get("encoded_destination_detected"):
        recs.append(
            "A destination is hidden inside the link (nested or percent-encoded "
            "address). Do not open it; the visible host may not be where the link "
            "actually goes."
        )
    if compared and (risk_increased or flags.get("obfuscation_detected")):
        recs.append(
            "This link is structurally different from the previously observed "
            "one. Treat the change as suspicious until confirmed via an official "
            "channel."
        )
    recs = _unique(recs)
    if not recs:
        recs.append(
            "No clear risk indicators were found, but always verify the "
            "organisation through its official website before sharing sensitive "
            "information."
        )
    return recs


def _summary(mode, normalized, url_result, changes, compared, risk_increased,
             score) -> str:
    label = (normalized.get("root_domain") or normalized.get("hostname") or
             normalized.get("raw") or "the link")
    if compared:
        if not changes:
            return (f"The current link ({label}) shows no structural changes "
                    "compared with the baseline.")
        rising = sum(1 for c in changes if c["risk_impact"] == "risk_increasing")
        noun = "change" if len(changes) == 1 else "changes"
        return (f"The link changed from the baseline: {len(changes)} structural "
                f"{noun} detected, {rising} risk-increasing. Static URL analysis "
                f"rates the current link {_risk_level(score)}.")
    if url_result.get("is_suspicious"):
        indicators = sorted(set(url_result.get("indicators") or []))
        bits = ", ".join(indicators[:4]) or "structural risk indicators"
        return (f"Suspicious link ({label}) - static analysis found: {bits}. "
                "Do not open it. The normalized representation is shown for "
                "inspection only.")
    return (f"The link ({label}) was safely normalized and inspected. Static "
            "URL analysis found no significant risk indicators.")


def _evidence(mode, normalized, baseline_norm, url_result):
    ev = {
        "source": "link_change",
        "mode": mode,
        "original_url": normalized.get("raw") or "",
        "current_url": normalized.get("raw") or "",
        "normalized_url": normalized.get("normalized") or "",
        "domains": [],
    }
    if normalized.get("hostname"):
        ev["domains"].append(normalized["hostname"])
    if normalized.get("root_domain"):
        ev["domains"].append(normalized["root_domain"])
    if mode == "compare" and baseline_norm is not None:
        ev["baseline_url"] = baseline_norm.get("raw") or ""
        b_domains = []
        if baseline_norm.get("hostname"):
            b_domains.append(baseline_norm["hostname"])
        if baseline_norm.get("root_domain"):
            b_domains.append(baseline_norm["root_domain"])
        if b_domains:
            ev["baseline_domains"] = b_domains
    return ev


def _warnings(mode, normalized):
    warnings = [CONFIDENCE_NOTE]
    if not normalized.get("hostname") and normalized.get("raw"):
        warnings.append(
            "The input did not parse as a complete URL (no host detected); it "
            "was inspected as-is."
        )
    if mode == "compare":
        warnings.append("Static structural comparison only - changes are "
                        "reported, never resolved or followed.")
    return warnings


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def _error(message: str, error_type: str = "validation", destination: dict | None = None) -> dict:
    if not isinstance(destination, dict):
        destination = analyze_url_destination("")
    return {
        "success": False,
        "input_type": "link_change",
        "status": "ERROR",
        "mode": None,
        "error": message,
        "error_type": error_type,
        "original_url": None,
        "current_url": None,
        "normalized_url": None,
        "baseline_url": None,
        "comparison": {"compared": False, "changes": [], "change_count": 0,
                       "risk_increasing_changes": []},
        "purifier": None,
        "risk_score": 0,
        "risk_level": "LOW",
        "is_suspicious": False,
        "scam_type": None,
        "confidence": 0,
        "confidence_type": "heuristic",
        "confidence_note": CONFIDENCE_NOTE,
        "change_impact": 0,
        "risk_delta": 0,
        "risk_increased": False,
        "original_url_analysis": None,
        "destination_analysis": destination.get("destination_analysis"),
        "safe_destination": destination.get("safe_destination"),
        "summary": "The link could not be inspected.",
        "indicators": [],
        "explanation": [],
        "recommendations": ["Correct the input and try again."],
        "evidence": {"source": "link_change"},
        "engine_results": {},
        "warnings": [CONFIDENCE_NOTE],
    }


def purify_url(url) -> dict:
    """MODE 1: normalize + statically inspect a single URL. Deterministic."""
    if not isinstance(url, str) or not url.strip():
        return _error("The URL to inspect must be a non-empty string.")
    current = url.strip()
    normalized = normalize_url(current)
    url_result = _analyze_url(current)
    flags = _purifier_flags(url_result, normalized)
    destination = analyze_url_destination(current)
    return _build_result(
        mode="purify", original=current, current=current,
        normalized=normalized, baseline_norm=None, url_result=url_result,
        baseline_url_result=None, changes=[], flags=flags,
        destination=destination,
    )


def compare_urls(baseline, current) -> dict:
    """MODE 2: compare a baseline URL against the current URL. Deterministic."""
    if not isinstance(current, str) or not current.strip():
        return _error("The current URL must be a non-empty string.")
    if not isinstance(baseline, str) or not baseline.strip():
        return _error("The baseline URL must be a non-empty string.")
    baseline_raw = baseline.strip()
    current_raw = current.strip()
    b_norm = normalize_url(baseline_raw)
    c_norm = normalize_url(current_raw)
    b_url = _analyze_url(baseline_raw)
    c_url = _analyze_url(current_raw)
    changes = _changes_from(b_norm, c_norm)
    flags = _purifier_flags(c_url, c_norm)
    destination = analyze_url_destination(current_raw)
    return _build_result(
        mode="compare", original=baseline_raw, current=current_raw,
        normalized=c_norm, baseline_norm=b_norm, url_result=c_url,
        baseline_url_result=b_url, changes=changes, flags=flags,
        destination=destination,
    )


def _changes_from(baseline_norm: dict, current_norm: dict) -> list[dict]:
    from .changes import detect_changes
    b_parts = _parse.parse_url(baseline_norm.get("raw") or "")
    c_parts = _parse.parse_url(current_norm.get("raw") or "")
    return detect_changes(b_parts, c_parts)


def analyze_link_change(content) -> dict:
    """Framework-independent entry point.

    ``content`` may be a str (single-link purification) or a dict:
        {"url": "..."}                        -> PURIFY mode
        {"baseline_url": "...", "current_url": "..."}   -> COMPARE mode
        {"baseline": "...", "current": "..."}           -> COMPARE mode alias

    Returns a link_change result in the existing unified ScamShield schema
    with the additional ``comparison`` / ``purifier`` / ``normalized_url``
    fields. Fully offline.
    """
    if not isinstance(content, dict):
        return purify_url(content)
    if not content:
        return _error("Provide a 'url', or 'baseline_url' + 'current_url'.")
    if "url" in content:
        current = content.get("url")
        if "baseline_url" in content or "baseline" in content:
            baseline = content.get("baseline_url") or content.get("baseline")
            return compare_urls(baseline, current)
        return purify_url(current)
    baseline = content.get("baseline_url") or content.get("baseline")
    current = content.get("current_url") or content.get("current")
    if baseline is None or current is None:
        return _error("Provide 'baseline_url' and 'current_url' to compare, or "
                      "'url' to inspect a single link.")
    return compare_urls(baseline, current)


def _unique(values) -> list:
    seen = set()
    out = []
    for value in values:
        key = value.lower() if isinstance(value, str) else repr(value)
        if key and key not in seen:
            seen.add(key)
            out.append(value)
    return out


__all__ = ["purify_url", "compare_urls", "analyze_link_change",
           "normalize_url", "CONFIDENCE_NOTE"]