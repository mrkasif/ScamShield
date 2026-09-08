"""Registrable-domain (root domain) extraction for the ScamShield URL engine.

We deliberately do NOT ship the full Public Suffix List - this is a small,
conservative, fully-local table of the suffixes most relevant to Indian and
common international addresses. Extraction is deterministic, offline and
designed to answer one question: *which label is the registrable domain name,
and which labels (if any) are sub-domains on top of it?*

Example:
    paypal.account-verify.com  -> root "account-verify.com", sub "paypal"
    www.sbi.co.in              -> root "sbi.co.in",        sub "www"
    www.google.com             -> root "google.com",       sub "www"
"""

from __future__ import annotations

import ipaddress

# Two-label public suffixes (e.g. "co.in"). When the final two labels equal
# one of these, the registrable domain extends one label further.
MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset({
    # India
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "res.in",
    "gen.in", "firm.in", "ind.in",
    # United Kingdom
    "co.uk", "org.uk", "gov.uk", "ac.uk", "nhs.uk",
    # Japan / Korea
    "co.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr",
    # Australia / NZ
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz",
    # Brazil / Mexico
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "org.mx",
    # South Africa / Singapore
    "co.za", "org.za", "gov.za",
    "com.sg", "org.sg", "gov.sg",
    # Hong Kong / China
    "com.hk", "org.hk",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    # Indonesia
    "co.id", "or.id",
})

# Single-label suffixes that are treated as the top level of the domain.
SINGLE_LABEL_SUFFIXES: frozenset[str] = frozenset({
    "com", "net", "org", "gov", "edu", "mil", "int", "in", "io", "co", "me",
    "dev", "app", "info", "biz", "tv", "cc", "ws", "news", "shop", "store",
    "tech", "online", "site", "club", "live", "cloud", "space", "email",
    "fun", "xyz",
})


def is_ip(hostname: str) -> bool:
    """True when the whole host is a bare IPv4/IPv6 address."""
    try:
        ipaddress.ip_address((hostname or "").strip("[]"))
        return True
    except ValueError:
        return False


def _labels(hostname: str) -> list[str]:
    return [lab for lab in (hostname or "").lower().split(".") if lab]


def domain_parts(hostname: str) -> dict:
    """Split a hostname into {root_domain, subdomains, tld, labels}.

    - labels:         every dot-separated label (lower-cased).
    - root_domain:    the registrable name (e.g. "sbi.co.in").
    - subdomains:     the labels *above* the root, dot-joined ("" when none).
    - tld:            the public suffix tail (e.g. "co.in", "com").

    IP addresses are returned as-is with no sub-domain decomposition.
    """

    host = (hostname or "").lower().strip("[]")
    if not host:
        return {"root_domain": "", "subdomains": "", "tld": "", "labels": []}
    if is_ip(host):
        return {"root_domain": host, "subdomains": "", "tld": "", "labels": [host]}

    labels = _labels(host)
    if len(labels) <= 1:
        # Single label (e.g. "localhost"): nothing to separate.
        return {"root_domain": host, "subdomains": "", "tld": "", "labels": labels}

    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        tld = ".".join(labels[-2:])
        root_idx = -3
    else:
        tld = labels[-1]
        root_idx = -2

    return {
        "root_domain": ".".join(labels[root_idx:]),
        "subdomains": ".".join(labels[:root_idx]),
        "tld": tld,
        "labels": labels,
    }


def registrable_domain(hostname: str) -> str:
    """Return the registrable (root) domain of a hostname, or '' if empty."""
    return domain_parts(hostname)["root_domain"]