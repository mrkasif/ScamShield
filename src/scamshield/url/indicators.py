"""Structural + lexical URL risk indicators.

Every detector is a pure function that inspects the parsed URL (see parse.py)
and returns a list of contributions:

    {"indicator": str, "severity": str, "score": float,
     "reason": str, "summary": str}

- "indicator" is the stable machine-readable name.
- "severity" is low / medium / high (human orientation).
- "score" is the exact number of points added to the total (0-100).
- "reason" is a human-readable explanation.
- "summary" is a short phrase used by the CLI summary line.
- "evidence" (optional) names the concrete artefact that fired (root domain,
  matched label, parameter names, ...) so the result stays explainable.

The engine never contacts the URL, resolves it, or executes anything - this is
purely static analysis of the URL string and its parsed structure.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import parse_qsl, unquote

from . import domains
from . import patterns as _p

_ESC = re.escape


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _labels(hostname: str) -> list[str]:
    return [lab for lab in (hostname or "").split(".") if lab]


def _norm(word: str) -> str:
    """Normalise a word for homoglyph/leetspeak comparison."""
    w = (word or "").lower().replace("rn", "m")
    return "".join(_p.HOMOGLYPH_MAP.get(ch, ch) for ch in w)


def _lev(a: str, b: str) -> int:
    """Iterative Levenshtein distance (edit distance)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if not la:
        return lb
    if not lb:
        return la
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[lb]


def _security_keywords_in(parts: dict) -> set[str]:
    """Distinct suspicious keywords in host + decoded path/query."""
    host = (parts.get("hostname") or "").lower()
    decoded = unquote(parts.get("raw") or "").lower()
    idx = decoded.rfind("@")
    if idx != -1:
        decoded = decoded[idx + 1:]
    kws: set[str] = set()
    for w in _p.SUSPICIOUS_KEYWORDS:
        if re.search(r"(?<!\w)" + _ESC(w) + r"(?!\w)", host) or \
           re.search(r"(?<!\w)" + _ESC(w) + r"(?!\w)", decoded):
            kws.add(w)
    return kws


def _official_suffix(hostname: str, official: tuple[str, ...]) -> bool:
    host = hostname.lower()
    for dom in official:
        dom = dom.lower()
        if host == dom or host.endswith("." + dom):
            return True
    return False


# ---------------------------------------------------------------------------
# 1-2. Scheme
# ---------------------------------------------------------------------------

def detect_scheme(scheme: str) -> list[dict]:
    if not scheme:
        return []
    if scheme in _p.WEB_SCHEMES:
        out = []
        if scheme == "http":
            out.append({
                "indicator": "http_scheme",
                "severity": "low",
                "score": 6.0,
                "summary": "plain HTTP",
                "reason": ("The URL uses plain HTTP (no TLS). Traffic to and "
                           "from this address is not encrypted."),
            })
        return out

    # Any other scheme: javascript:, data:, file:, vbscript:, odd typos, etc.
    return [{
        "indicator": "unusual_scheme",
        "severity": "high",
        "score": 30.0,
        "summary": f"non-web scheme '{scheme}'",
        "reason": (f"The URL uses the uncommon scheme '{scheme}'. Non-http(s) "
                   "links in unsolicited messages can be used to trigger local "
                   "applications or encoded payloads."),
    }]


# ---------------------------------------------------------------------------
# 3. IP address host
# ---------------------------------------------------------------------------

def detect_ip_host(hostname: str) -> list[dict]:
    if not hostname:
        return []
    host = hostname.strip("[]")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return []
    return [{
        "indicator": "ip_address_host",
        "severity": "high",
        "score": 34.0,
        "summary": "raw IP address host",
        "reason": ("The URL uses a raw IP address instead of a registered "
                   "domain name. Legitimate organisations almost never send "
                   "links that point at bare IP addresses."),
    }]


# ---------------------------------------------------------------------------
# 4. Punycode / IDN / Unicode host
# ---------------------------------------------------------------------------

def detect_punycode(hostname: str) -> list[dict]:
    if not hostname:
        return []
    if "xn--" not in hostname.lower():
        return []
    return [{
        "indicator": "punycode_domain",
        "severity": "medium",
        "score": 12.0,
        "summary": "internationalized (xn--) domain",
        "reason": ("The domain contains an internationalized label (xn--). "
                   "Unicode domains are legitimate, but they can be used to "
                   "imitate trusted names with look-alike characters - treat "
                   "the destination with extra caution."),
    }]


def detect_internationalized_host(hostname: str) -> list[dict]:
    """Any non-ASCII character in the hostname (raw Unicode, not xn--)."""
    if not hostname:
        return []
    if not any(ord(c) > 127 for c in hostname):
        return []
    return [{
        "indicator": "internationalized_host",
        "severity": "medium",
        "score": 10.0,
        "summary": "non-ASCII characters in hostname",
        "reason": ("The hostname contains raw non-ASCII (Unicode) characters. "
                   "This is used by legitimate organisations, but also to "
                   "spell a trusted name using near-identical foreign "
                   "letters."),
    }]


def detect_mixed_script_host(hostname: str) -> list[dict]:
    """Two or more alphabets inside the registrable (SLD) label.

    We deliberately only scan the label that carries the brand AND the TLD is
    ignored: a Cyrillic word under ".com" is *not* mixed-script - but
    "pay" + Cyrillic "p" in a single label (payрal.com) is a homoglyph.
    """
    if not hostname:
        return []
    dp = domains.domain_parts(hostname)
    sld = dp["root_domain"].split(".", 1)[0] if dp["root_domain"] else hostname
    scripts: set[str] = set()
    for ch in sld:
        if unicodedata.category(ch)[0] != "L":
            continue  # letters only; digits/punct are neutral
        name = unicodedata.name(ch, "")
        if not name:
            continue
        scripts.add(name.split(" ", 1)[0])
    if len(scripts) < 2:
        return []
    return [{
        "indicator": "mixed_script_host",
        "severity": "medium",
        "score": 12.0,
        "summary": f"label mixes alphabets ({'/'.join(sorted(scripts))})",
        "reason": ("The registrable name mixes characters from different "
                   "alphabets "
                   f"({', '.join(sorted(scripts))}). This is a well-known way "
                   "to imitate a trusted Latin-script brand with "
                   "foreign-looking letters (homoglyph phishing)."),
        "evidence": sld,
    }]


# ---------------------------------------------------------------------------
# 5. Embedded credentials (userinfo)
# ---------------------------------------------------------------------------

def detect_embedded_credentials(parts: dict) -> list[dict]:
    has_user = bool(parts.get("username"))
    has_pass = bool(parts.get("password"))
    if not (has_user or has_pass):
        return []
    if has_user and not has_pass:
        reason = ("The URL embeds a username before the domain "
                  "(user@host). Legitimate links never need credentials in "
                  "the URL.")
    else:
        reason = ("The URL embeds credentials (user:password@). Legitimate "
                  "services never put passwords in URLs - this is a classic "
                  "phishing / accidental-leak pattern.")
    return [{
        "indicator": "embedded_credentials",
        "severity": "high",
        "score": 55.0,
        "summary": "credentials embedded in URL",
        "reason": reason,
    }]


# ---------------------------------------------------------------------------
# 6. URL length / complexity family
# ---------------------------------------------------------------------------

def detect_long_url(raw: str) -> list[dict]:
    n = len(raw or "")
    for length, severity, score in _p.LONG_URL_THRESHOLDS:
        if n > length:
            return [{
                "indicator": "long_url",
                "severity": severity,
                "score": score,
                "summary": f"unusually long URL ({n} chars)",
                "reason": (f"The URL is unusually long ({n} characters). "
                           "Long, parameter-stuffed links are often used to "
                           "hide the real destination."),
            }]
    return []


def detect_long_hostname(hostname: str) -> list[dict]:
    if len(hostname or "") > _p.LONG_HOSTNAME_THRESHOLD:
        return [{
            "indicator": "long_hostname",
            "severity": "low",
            "score": 4.0,
            "summary": f"long hostname ({len(hostname)} chars)",
            "reason": (f"The hostname is very long ({len(hostname)} "
                       "characters). Extremely long names are typical of "
                       "auto-generated scam domains."),
        }]
    return []


def detect_long_path(path: str) -> list[dict]:
    if len(path or "") > _p.LONG_PATH_THRESHOLD:
        return [{
            "indicator": "long_path",
            "severity": "low",
            "score": 4.0,
            "summary": f"long path ({len(path)} chars)",
            "reason": (f"The path is very long ({len(path)} characters). "
                       "Oversized paths are used to bury the real "
                       "destination or keyword denylists."),
        }]
    return []


def detect_many_query_parameters(query: str) -> list[dict]:
    if not query:
        return []
    try:
        count = len(parse_qsl(query, keep_blank_values=True))
    except Exception:
        return []
    if count >= _p.MANY_QUERY_PARAMS_MIN:
        return [{
            "indicator": "many_query_parameters",
            "severity": "low",
            "score": 4.0,
            "summary": f"{count} query parameters",
            "reason": (f"The URL carries {count} query parameters. "
                       "Parameter-stuffed links are a common way to obfuscate "
                       "the true purpose of the link."),
        }]
    return []


# ---------------------------------------------------------------------------
# 7. Subdomain depth
# ---------------------------------------------------------------------------

def detect_subdomain_depth(hostname: str) -> list[dict]:
    if not hostname:
        return []
    labels = _labels(hostname)
    if len(labels) < 3:
        return []
    # Depth = labels beyond the registrable domain + one suffix label.
    depth = len(labels) - 2
    for threshold, severity, score in _p.SUBDOMAIN_DEPTH_THRESHOLDS:
        if depth >= threshold:
            return [{
                "indicator": "excessive_subdomains",
                "severity": severity,
                "score": score,
                "summary": f"excessive subdomains ({depth} levels)",
                "reason": (f"The hostname has {depth} levels of sub-domain "
                           "prefixes. Legitimate sites sometimes use a couple "
                           "of sub-domains, but deep stacks such as "
                           "secure.login.verify.account.example.com are a "
                           "common phishing construction."),
            }]
    return []


# ---------------------------------------------------------------------------
# 8. Suspicious explicit port
# ---------------------------------------------------------------------------

def detect_unusual_port(parts: dict) -> list[dict]:
    port = parts.get("port")
    if port is None:
        return []
    scheme = parts.get("scheme") or ""
    if port in _p.DEFAULT_WEB_PORTS:
        return []
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return []
    return [{
        "indicator": "unusual_port",
        "severity": "medium",
        "score": 14.0,
        "summary": f"unusual port :{port}",
        "reason": (f"The URL uses the non-standard port {port}. Phishing and "
                   "malicious servers are commonly (though not always) hosted "
                   "on unusual ports."),
    }]


# ---------------------------------------------------------------------------
# 9. Percent-encoding / obfuscation
# ---------------------------------------------------------------------------

def detect_encoding(raw: str) -> list[dict]:
    count = (raw or "").count("%")
    for threshold, severity, score in _p.ENCODING_THRESHOLDS:
        if count >= threshold:
            return [{
                "indicator": "encoding_obfuscation",
                "severity": severity,
                "score": score,
                "summary": f"heavy percent-encoding ({count} encoded chars)",
                "reason": (f"The URL contains {count} percent-encoded "
                           "characters. Heavy encoding is often used to hide "
                           "keywords or the true destination from scanners "
                           "and readers."),
            }]
    return []


def detect_nested_url(raw: str) -> list[dict]:
    """More than one '://' means a second (nested) web address inside the URL."""
    if (raw or "").count("://") <= 1:
        return []
    return [{
        "indicator": "nested_url",
        "severity": "medium",
        "score": 10.0,
        "summary": "a second web address is nested inside the URL",
        "reason": ("The URL embeds another complete web address (:// appears "
                   "more than once). Nested links are used to funnel you "
                   "towards a destination hidden in the query string."),
    }]


def detect_encoded_nested_url(raw: str) -> list[dict]:
    """Percent-encoding hides a '://' that only appears after decoding."""
    r = raw or ""
    decoded = unquote(r)
    if decoded.count("://") <= r.count("://"):
        return []
    return [{
        "indicator": "encoded_nested_url",
        "severity": "medium",
        "score": 10.0,
        "summary": "encoded web address hidden in the URL",
        "reason": ("Once decoded, the URL reveals an extra complete web "
                   "address (://) that was hidden with percent-encoding. "
                   "Hiding a nested destination this way is a phishing "
                   "technique."),
        "evidence": ":// appears only after decoding",
    }]


def detect_hex_encoded_host(hostname: str) -> list[dict]:
    """An all-hex registrable label that decodes to a private/loopback address."""
    if not hostname:
        return []
    host = hostname.strip("[]")
    dp = domains.domain_parts(host)
    lab = dp["root_domain"].split(".", 1)[0] if dp["root_domain"] else host
    if len(lab) not in (8, 32):
        return []
    if not all(c in "0123456789abcdefABCDEF" for c in lab):
        return []
    try:
        if len(lab) == 8:
            ip = ipaddress.IPv4Address(
                bytes(int(lab[i:i + 2], 16) for i in range(0, 8, 2)))
        else:
            ip = ipaddress.IPv6Address(
                bytes(int(lab[i:i + 2], 16) for i in range(0, 32, 2)))
    except Exception:
        return []
    if not (ip.is_private or ip.is_loopback):
        return []
    return [{
        "indicator": "hex_encoded_host",
        "severity": "medium",
        "score": 10.0,
        "summary": f"hex-encoded host maps to {ip}",
        "reason": (f"The hostname '{lab}' is a hex-encoded network address "
                   f"that decodes to {ip}, a private/loopback range. Cloaking "
                   "an address this way hides where the link really goes."),
        "evidence": f"{lab} -> {ip}",
    }]


# ---------------------------------------------------------------------------
# 10. Special characters / confusing structure
# ---------------------------------------------------------------------------

def detect_multiple_at(raw: str, parts: dict) -> list[dict]:
    at_count = (raw or "").count("@")
    if at_count <= 1:
        # An '@' with a domain-like username (host@host) without a scheme
        # separator is itself a redirect trick.
        user = parts.get("username")
        if user and "." in user:
            return [{
                "indicator": "confusing_userinfo",
                "severity": "high",
                "score": 18.0,
                "summary": "host-shaped text before '@'",
                "reason": ("The part before the last '@' looks like a host "
                           "name. This pattern is used to display one domain "
                           "to the reader while actually navigating to a "
                           "different one."),
            }]
        return []
    return [{
        "indicator": "multiple_at",
        "severity": "high",
        "score": 18.0,
        "summary": f"{at_count} '@' symbols",
        "reason": (f"The URL contains {at_count} '@' symbols. Multiple '@' in "
                   "a URL is a classic trick to confuse the viewer about the "
                   "real destination."),
    }]


def detect_excessive_separators(path: str) -> list[dict]:
    if not path:
        return []
    slash_count = path.count("/")
    if "//" in path or slash_count >= 6:
        return [{
            "indicator": "excessive_separators",
            "severity": "low",
            "score": 5.0,
            "summary": "confusing path separators",
            "reason": ("The path uses extra separators (// or many levels). "
                       "This can be used to make a link look like it leads to "
                       "a trusted directory structure."),
        }]
    return []


def detect_excessive_hyphens(hostname: str) -> list[dict]:
    if not hostname:
        return []
    counts = [lab.count("-") for lab in _labels(hostname)]
    if not counts:
        return []
    if any(c >= _p.HYPHEN_LABEL_MAX for c in counts):
        fire = True
    elif sum(1 for c in counts if c > 0) >= _p.HYPHEN_LABELS_MIN:
        fire = True
    elif sum(counts) >= _p.HYPHEN_TOTAL_MIN:
        fire = True
    else:
        fire = False
    if not fire:
        return []
    return [{
        "indicator": "excessive_hyphens",
        "severity": "low",
        "score": 6.0,
        "summary": "hostname stuffed with hyphens",
        "reason": ("The hostname uses an excessive number of hyphens. "
                   "Hyphen-heavy names are typical of cheaply-generated or "
                   "phishing domains (e.g. secure-login-verify-sbi)."),
    }]


def detect_numeric_domain(hostname: str) -> list[dict]:
    if not hostname or domains.is_ip(hostname):
        return []
    root = domains.domain_parts(hostname)["root_domain"]
    root_label = root.split(".", 1)[0]
    if len(root_label) < 8:
        return []
    digits = sum(1 for c in root_label if c.isdigit())
    if digits * 2 < len(root_label):
        return []
    return [{
        "indicator": "numeric_domain",
        "severity": "low",
        "score": 6.0,
        "summary": "domain name is mostly digits",
        "reason": (f"The registrable domain '{root_label}' is almost entirely "
                   "digits. Heavily numeric domains are disproportionately "
                   "associated with scam operations (bot-registered names)."),
        "evidence": root,
    }]


# ---------------------------------------------------------------------------
# 11. URL shorteners
# ---------------------------------------------------------------------------

def detect_shortener(hostname: str) -> list[dict]:
    if not hostname:
        return []
    labels = _labels(hostname)
    for idx in range(max(0, len(labels) - 2), len(labels)):
        candidate = ".".join(labels[idx:])
        if candidate in _p.SHORTENERS:
            note = _p.SHORTENERS[candidate]
            return [{
                "indicator": "short_url_redirector",
                "severity": "medium",
                "score": 12.0,
                "summary": f"shortened link ({candidate})",
                "reason": (f"{note} A shortened URL hides the final "
                           "destination until it is opened."),
            }]
    return []


# ---------------------------------------------------------------------------
# 12. Suspicious keywords (hostname + decoded path/query)
# ---------------------------------------------------------------------------

def detect_suspicious_keywords(parts: dict) -> list[dict]:
    seen = _security_keywords_in(parts)
    if not seen:
        return []

    hits = len(seen)
    points = min(hits, _p.KEYWORD_HIT_CAP) * _p.KEYWORD_POINTS_PER_HIT
    strong = seen & _p.STRONG_KEYWORDS
    severity = "medium" if strong else "low"
    entries: list[dict] = []
    entries.append({
        "indicator": "suspicious_keyword",
        "severity": severity,
        "score": points,
        "summary": f"security keywords in link ({sorted(seen)})",
        "reason": ("The link contains security-relevant word(s): "
                   + ", ".join(sorted(seen))
                   + ". A keyword alone is not proof of fraud, but these words "
                   "are frequent in credential-harvesting and KYC/banking "
                   "phishing pages."),
    })
    if hits >= _p.KEYWORD_CLUSTER_MIN:
        entries.append({
            "indicator": "keyword_cluster",
            "severity": "medium",
            "score": 10.0,
            "summary": "link stuffed with security words",
            "reason": (f"The link contains {hits} distinct security-related "
                       "words. This density is far more typical of phishing "
                       "pages than of legitimate websites."),
        })
    return entries


# ---------------------------------------------------------------------------
# 13. Suspicious redirect parameters
# ---------------------------------------------------------------------------

def detect_redirect_parameter(parts: dict) -> list[dict]:
    query = (parts.get("query") or "")
    if not query:
        return []
    low = unquote(query).lower()
    try:
        params = {k.lower() for k, _v in parse_qsl(low, keep_blank_values=True)}
    except Exception:
        params = set()
    matched = [p for p in _p.SUSPICIOUS_REDIRECT_PARAMS if p in params]
    if not matched:
        return []
    return [{
        "indicator": "suspicious_redirect_parameter",
        "severity": "medium",
        "score": 12.0,
        "summary": f"redirect parameter present ({sorted(matched)})",
        "reason": ("The query string contains a redirect-type parameter "
                   "(" + ", ".join(sorted(matched)) +
                   "). Links that silently bounce you to another location are "
                   "a common phishing technique."),
        "evidence": ",".join(sorted(matched)),
    }]


# ---------------------------------------------------------------------------
# 13b. Suspicious query parameter *names* (password, otp, card, ...)
# ---------------------------------------------------------------------------

def detect_suspicious_query_param(parts: dict) -> list[dict]:
    query = (parts.get("query") or "")
    if not query:
        return []
    low = unquote(query).lower()
    try:
        names = {k.lower() for k, _v in parse_qsl(low, keep_blank_values=True)}
    except Exception:
        names = set()
    matched = [p for p in _p.SUSPICIOUS_QUERY_PARAMS if p in names]
    if not matched:
        return []
    take = matched[:_p.SUSPICIOUS_QUERY_PARAM_CAP]
    points = len(take) * _p.SUSPICIOUS_QUERY_PARAM_POINTS
    return [{
        "indicator": "suspicious_query_param",
        "severity": "low",
        "score": points,
        "summary": f"sensitive param name(s) in query ({sorted(matched)})",
        "reason": ("The query string uses parameter name(s) that ask for or "
                   "carry sensitive data: "
                   + ", ".join(sorted(matched))
                   + ". Links prompting for passwords, OTPs or card data are "
                   "a phishing pattern - never type credentials into a "
                   "parameter of a link."),
        "evidence": ",".join(sorted(matched)),
    }]


# ---------------------------------------------------------------------------
# 14. Brand impersonation (conservative, root/subdomain aware)
# ---------------------------------------------------------------------------

def _brand_label_index(hostname: str, token: str) -> int | None:
    """Index of the hostname label that mentions the brand (or None)."""
    labels = _labels(hostname.lower())
    candidates = [token]
    for alt in _p.COMPOUND_BRANDS.get(token, ()):
        if alt != token:
            candidates.append(alt.replace(" ", "-"))
    for i, lab in enumerate(labels):
        for cand in candidates:
            if re.search(r"(?<!\w)" + _ESC(cand) + r"(?!\w)", lab):
                return i
            t = lab.strip("-_")
            if t.startswith(cand) and t[len(cand):].isalpha():
                return i
    return None


def detect_brand_impersonation(parts: dict) -> list[dict]:
    hostname = (parts.get("hostname") or "").lower()
    if not hostname:
        return []

    keywords = _security_keywords_in(parts)
    dp = domains.domain_parts(hostname)
    root_labels = set(dp["root_domain"].split(".")) if dp["root_domain"] else set()

    seen_brand: str | None = None
    brand_label_idx: int | None = None

    for token, profile in _p.BRAND_PROFILES.items():
        if _official_suffix(hostname, tuple(profile["official"])):
            # Legit brand-owned domain; skip before checking tokens so
            # e.g. onlinesbi.com / amazonaws.com are never flagged.
            continue
        idx = _brand_label_index(hostname, token)
        if idx is None:
            continue
        if profile["need_keyword"] and not keywords:
            # Generic token (e.g. "upi" or "post"): require a security
            # keyword too so we do not flag ordinary uses of the word.
            continue
        seen_brand = token
        brand_label_idx = idx
        break

    if seen_brand is None:
        return []

    # Placement: did the brand appear in the registrable root or in a
    # sub-domain label? The *root* is what the owner actually registered;
    # a brand floating in a sub-domain above an unrelated root is a stronger
    # sign of deception (paypal.account-verify.com).
    labels = dp["labels"] or _labels(hostname)
    in_root = brand_label_idx is not None and labels[brand_label_idx] in root_labels

    if in_root:
        severity, score = ("high", 30.0) if keywords else ("medium", 16.0)
        subnote = ""
    else:
        severity, score = ("high", 24.0) if keywords else ("medium", 16.0)
        subnote = (" The brand word sits in a sub-domain of "
                   f"'{dp['root_domain']}' - a pattern scammers use to place "
                   "a trusted name in front of an unrelated site.")

    entries: list[dict] = [{
        "indicator": "brand_impersonation",
        "severity": severity,
        "score": score,
        "summary": f"possible '{seen_brand}' impersonation",
        "reason": (f"The domain '{hostname}' contains the brand term "
                   f"'{seen_brand}' but does not end with a domain that "
                   f"{seen_brand} officially owns. This is a preliminary "
                   "impersonation signal - always verify the organisation "
                   "through its official website or app before trusting the "
                   "link." + subnote),
        "evidence": dp["root_domain"] or hostname,
    }]

    if not in_root and dp["root_domain"]:
        entries.append({
            "indicator": "brand_in_subdomain",
            "severity": "medium",
            "score": 8.0,
            "summary": "brand name lives in a subdomain",
            "reason": (f"The brand word '{seen_brand}' appears only in a "
                       f"sub-domain of '{dp['root_domain']}', which is not a "
                       f"domain the brand owns. The real destination is "
                       f"'{dp['root_domain']}' - not the brand."),
            "evidence": dp["root_domain"],
        })
    return entries


# ---------------------------------------------------------------------------
# 14b. Brand tokens hiding in the path (requires a security keyword)
# ---------------------------------------------------------------------------

def detect_brand_in_path(parts: dict) -> list[dict]:
    if not _security_keywords_in(parts):
        return []
    hostname = (parts.get("hostname") or "").lower()
    path = (parts.get("path") or "").lower()
    if not path:
        return []
    for token, profile in _p.BRAND_PROFILES.items():
        if profile.get("need_keyword"):
            continue  # generic tokens (upi/post) excluded here as well
        if _official_suffix(hostname, tuple(profile["official"])):
            continue
        if re.search(r"(?<!\w)" + _ESC(token) + r"(?!\w)", hostname):
            continue  # brand already in host; impersonation handles it
        if re.search(r"(?<!\w)" + _ESC(token) + r"(?!\w)", path):
            return [{
                "indicator": "brand_in_path",
                "severity": "low",
                "score": 6.0,
                "summary": f"brand name '{token}' inside link path",
                "reason": (f"The path contains the brand word '{token}' but "
                           "the host is not a domain the brand owns. Combined "
                           "with security language elsewhere in the link, this "
                           "suggests the brand is being used to add "
                           "credibility to the URL."),
                "evidence": token,
            }]
    return []


# ---------------------------------------------------------------------------
# 14c. Possible brand typosquatting (homoglyph / look-alike / misspellings)
# ---------------------------------------------------------------------------

def detect_possible_brand_typosquatting(parts: dict) -> list[dict]:
    """Look-alike domain labels for known brands (paypaI, gooogle, amaz0n)."""
    hostname = (parts.get("hostname") or "").lower()
    if not hostname:
        return []

    for token, profile in _p.BRAND_PROFILES.items():
        if profile.get("need_keyword"):
            continue  # generic tokens (upi/post) are not typosquattable here
        if _official_suffix(hostname, tuple(profile["official"])):
            continue
        if _brand_label_index(hostname, token) is not None:
            continue  # exact brand word present -> impersonation, not squatt

        for lab in _labels(hostname):
            if lab == token:
                continue
            if _looks_like(lab, token):
                return [{
                    "indicator": "possible_brand_typosquatting",
                    "severity": "medium",
                    "score": 14.0,
                    "summary": f"domain label '{lab}' looks like '{token}'",
                    "reason": (f"The domain label '{lab}' is a near-miss or "
                               f"look-alike of the brand '{token}' "
                               "(homoglyph, leetspeak or a tiny spelling "
                               "difference). Look-alike domains are frequently "
                               "registered for brand-impersonation phishing."),
                    "evidence": f"'{lab}' -> '{token}'",
                }]
    return []


def _looks_like(label: str, token: str) -> bool:
    """True when label is a homoglyph/leetspeak or near miss of token."""
    if _norm(label) == _norm(token):
        return True
    if len(token) >= 5 and _lev(label, token) <= 1:
        return True
    # Transposition-only distance 2 (e.g. palpay -> paypal) when the label is
    # the same length and the brand is long enough to be unambiguous.
    if len(token) >= 6 and len(label) == len(token) and _lev(label, token) <= 2:
        return True
    return False


# ---------------------------------------------------------------------------
# 15. Unusual top-level domain
# ---------------------------------------------------------------------------

def detect_unusual_tld(hostname: str) -> list[dict]:
    if not hostname:
        return []
    tld = domains.domain_parts(hostname)["tld"]
    if tld not in _p.SUSPICIOUS_TLDS:
        return []
    return [{
        "indicator": "unusual_tld",
        "severity": "low",
        "score": 4.0,
        "summary": f"top-level domain '.{tld}'",
        "reason": (f"The top-level domain '.{tld}' is a TLD frequently used "
                   "for cheap, disposable or abusive registrations. It is "
                   "only a weak signal on its own, but adds to a suspicious "
                   "picture."),
        "evidence": f".{tld}",
    }]


# ---------------------------------------------------------------------------
# Entry point: run all detectors
# ---------------------------------------------------------------------------

def detect_all(parts: dict) -> list[dict]:
    """Run every indicator against a parse_url() result (never raises)."""
    findings: list[dict] = []
    if not parts:
        return findings

    raw = parts.get("raw") or ""
    scheme = parts.get("scheme") or ""
    hostname = parts.get("hostname") or ""
    path = parts.get("path") or ""
    query = parts.get("query") or ""

    findings += detect_scheme(scheme)
    findings += detect_ip_host(hostname)
    findings += detect_punycode(hostname)
    findings += detect_internationalized_host(hostname)
    findings += detect_mixed_script_host(hostname)
    findings += detect_embedded_credentials(parts)
    findings += detect_long_url(raw)
    findings += detect_long_hostname(hostname)
    findings += detect_long_path(path)
    findings += detect_many_query_parameters(query)
    findings += detect_subdomain_depth(hostname)
    findings += detect_unusual_port(parts)
    findings += detect_encoding(raw)
    findings += detect_nested_url(raw)
    findings += detect_encoded_nested_url(raw)
    findings += detect_hex_encoded_host(hostname)
    findings += detect_multiple_at(raw, parts)
    findings += detect_excessive_separators(path)
    findings += detect_excessive_hyphens(hostname)
    findings += detect_numeric_domain(hostname)
    findings += detect_shortener(hostname)
    findings += detect_suspicious_keywords(parts)
    findings += detect_redirect_parameter(parts)
    findings += detect_suspicious_query_param(parts)
    findings += detect_unusual_tld(hostname)
    findings += detect_brand_impersonation(parts)
    findings += detect_brand_in_path(parts)
    findings += detect_possible_brand_typosquatting(parts)

    return findings