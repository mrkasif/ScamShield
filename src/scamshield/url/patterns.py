"""Static reference tables for the ScamShield URL intelligence engine.

These are local constants only - the engine never queries external services.
The tables are deliberately conservative: a single keyword or brand token is
a *weak* signal that only gains weight when combined with other indicators.

All matching in `indicators.py` is case-insensitive (hostnames are lower-cased
before matching).
"""

from __future__ import annotations

# Schemes we treat as ordinary web traffic. Anything else (javascript:, data:,
# file:, mailto:, odd typos like httpx:) is flagged as an unusual scheme.
WEB_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# Ports that are normal for web traffic and never suspicious on their own.
DEFAULT_WEB_PORTS: frozenset[int] = frozenset({80, 443})

# Local dictionary of well-known URL shorteners. We never resolve them -
# the presence of a shortener is itself a (moderate) signal.
# key: canonical hostname (lower-case), value: short human note.
SHORTENERS: dict[str, str] = {
    "bit.ly": "bit.ly is a URL shortener.",
    "bitly.com": "bitly.com is a URL shortener.",
    "tinyurl.com": "TinyURL is a URL shortener.",
    "tiny.cc": "tiny.cc is a URL shortener.",
    "goo.gl": "goo.gl is a URL shortener.",
    "t.co": "t.co is a URL shortener (used by X/Twitter).",
    "rb.gy": "rb.gy is a URL shortener.",
    "cutt.ly": "cutt.ly is a URL shortener.",
    "is.gd": "is.gd is a URL shortener.",
    "ow.ly": "ow.ly is a URL shortener.",
    "lnkd.in": "lnkd.in is a URL shortener (LinkedIn).",
    "shorturl.at": "shorturl.at is a URL shortener.",
    "reurl.cc": "reurl.cc is a URL shortener.",
    "rebrand.ly": "rebrand.ly is a URL shortener.",
    "shorturl.co": "shorturl.co is a URL shortener.",
}

# Security-relevant terms that, when found in the hostname/path/query of an
# unsolicited link, hint at social engineering / credential harvesting.
# IMPORTANT: a single keyword raises the score only slightly (see scoring.py);
# these words alone never make a URL "suspicious".
SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    # credentials / identity
    "login", "signin", "sign-in", "sign_in", "password", "passwd", "pwd",
    "otp", "pin", "cvv", "card", "netbanking", "internetbanking",
    "mobilebanking", "verify", "verification", "verify-now", "authenticate",
    "auth", "authorize", "activation", "activate", "reactivate", "confirm",
    "secure", "security", "account", "accounts", "update", "updation",
    "suspended", "suspend", "restricted", "blocked", "unlock", "unblock",
    "dispute", "review", # frozen / restricted account vocabulary
    # financial / urgency
    "kyc", "bank", "banking", "payment", "pay", "refund", "reward",
    "cashback", "bonus", "prize", "lottery", "winner", "claim", "wallet",
    "deposit", "withdraw", "emi",
    # department/customer care
    "support", "helpdesk", "customer", "care", "complaint",
    # high-pressure offers
    "crypto", "bitcoin", "invest", "loan", "job", "free",
)

# Keywords that carry a stronger (but still capped) weight because they almost
# always appear inside credential-harvesting / KYC-type phishing pages.
STRONG_KEYWORDS: frozenset[str] = frozenset({
    "kyc", "otp", "password", "login", "verify", "verification",
    "wallet", "suspended", "unblock", "netbanking",
})

# Maximum number of keyword "hits" that can contribute points. Prevents a URL
# stuffed with security words from being treated as CRITICAL on keywords alone.
KEYWORD_HIT_CAP: int = 4
KEYWORD_POINTS_PER_HIT: float = 6.0

# When this many distinct keywords fire we add a "keyword_cluster" indicator
# (a moderate signal that the URL is stuffed with security jargon).
KEYWORD_CLUSTER_MIN: int = 3

# Query parameters that instruct a link to bounce the user somewhere else.
# e.g. ?redirect=..., ?url=..., ?next=... A redirect parameter in an
# unsolicited link is a phishing / open-redirect signal.
SUSPICIOUS_REDIRECT_PARAMS: tuple[str, ...] = (
    "redirect", "url", "next", "return", "callback", "goto", "target",
    "destination", "continue", "link", "rurl", "returnto",
)

# Query parameter *names* that ask for, or carry, security-sensitive values.
# Unlike redirect params these are a small (low) signal - many apps use
# "token" or "account" legitimately - but in an unsolicited link they are the
# classic credential-harvesting ask.
SUSPICIOUS_QUERY_PARAMS: tuple[str, ...] = (
    "password", "passwd", "pwd", "otp", "pin", "card", "cvv", "account",
    "verify", "token",
)
SUSPICIOUS_QUERY_PARAM_CAP: int = 2        # max params counted
SUSPICIOUS_QUERY_PARAM_POINTS: float = 5.0 # per matching param

# Top-level domains frequently used for cheap / disposable / abusive
# registrations. A TLD is never a verdict on its own - just a small nudge.
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq", "zip", "mov", "country",
})

# Homoglyph / leetspeak substitutions used to detect look-alike brand names.
# "g00gle" -> "google", "paypaI" -> "paypal", "amaz0n" -> "amazon", ...
HOMOGLYPH_MAP: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "|": "l", "!": "i", "@": "a", "$": "s",
}

# Complexity thresholds (each is a small low-level signal; the score_url cap
# keeps this whole family bounded at COMPLEXITY_CAP below).
LONG_HOSTNAME_THRESHOLD: int = 50
LONG_PATH_THRESHOLD: int = 150
MANY_QUERY_PARAMS_MIN: int = 6  # more than this many parameters
COMPLEXITY_CAP: float = 20.0    # cap for the long_url family combined

# Hyphen abuse thresholds for a hostname (typical of auto-generated scam
# domain names).
HYPHEN_LABEL_MAX: int = 3      # hyphens in a single label
HYPHEN_LABELS_MIN: int = 2     # separate labels containing a hyphen
HYPHEN_TOTAL_MIN: int = 4      # total hyphens across the hostname

# ---------------------------------------------------------------------------
# Brand impersonation profiles.
#
# token: the brand word we look for in hostname labels.
# official: secondary domains that are legitimately owned by the brand. If the
#           hostname ends with one of these, the brand is NOT at risk.
# need_keyword: if True, the brand term must co-occur with a suspicious
#           keyword before we fire (used for very generic tokens like "upi").
# ---------------------------------------------------------------------------
BRAND_PROFILES: dict[str, dict] = {
    "sbi": {
        "official": ("sbi.co.in", "onlinesbi.com", "sbicard.com"),
        "need_keyword": False,
    },
    "hdfc": {
        "official": ("hdfcbank.com", "hdfc.com", "hdfcbank.co.in"),
        "need_keyword": False,
    },
    "icici": {
        "official": ("icicibank.com", "icici.com", "icicibank.co.in"),
        "need_keyword": False,
    },
    "axis": {
        "official": ("axisbank.com", "axisbank.co.in"),
        "need_keyword": False,
    },
    "pnb": {
        "official": ("pnbindia.com", "pnbindia.in", "pnb.in"),
        "need_keyword": False,
    },
    "upi": {
        "official": ("npci.org.in", "upip.in"),
        "need_keyword": True,
    },
    "paytm": {
        "official": ("paytm.com", "paytm.in"),
        "need_keyword": False,
    },
    "phonepe": {
        "official": ("phonepe.com", "phonepe.in"),
        "need_keyword": False,
    },
    "amazon": {
        "official": ("amazon.in", "amazon.com", "amazonaws.com",
                     "amazonpay.in", "amazonpay.com", "amazon.in"),
        "need_keyword": False,
    },
    "flipkart": {
        "official": ("flipkart.com", "flipkart.in"),
        "need_keyword": False,
    },
    "indiapost": {
        "official": ("indiapost.gov.in"),
        "need_keyword": False,
    },
    "post": {
        "official": (),  # free-form matching below
        "need_keyword": True,
    },
    "uidai": {
        "official": ("uidai.gov.in", "resident.uidai.gov.in"),
        "need_keyword": False,
    },
    "aadhaar": {
        "official": ("uidai.gov.in"),
        "need_keyword": False,
    },
    "incometax": {
        "official": ("incometax.gov.in", "incometaxindia.gov.in"),
        "need_keyword": False,
    },
    "google": {
        "official": ("google.com", "google.co.in", "google.in", "google.co.uk",
                     "googleusercontent.com", "youtube.com"),
        "need_keyword": False,
    },
    "paypal": {
        "official": ("paypal.com", "paypal.me", "paypal.co.in", "paypal.in"),
        "need_keyword": False,
    },
}

# Brands matched with an explicit "income tax" / "post" compound pattern
# (handled separately because their brand word is a generic English word).
COMPOUND_BRANDS: dict[str, tuple[str, ...]] = {
    "indiapost": ("indiapost", "indianpost", "india-post", "india post"),
    "incometax": ("incometax", "income-tax", "income tax", "itdept", "itdepart"),
}

# Length thresholds for "unusually long URL" flagging.
LONG_URL_THRESHOLDS: tuple[tuple[int, str, float], ...] = (
    (2048, "high", 14.0),
    (500, "medium", 8.0),
    (200, "low", 4.0),
)

# Subdomain-depth thresholds (labels beyond the final two).
SUBDOMAIN_DEPTH_THRESHOLDS: tuple[tuple[int, str, float], ...] = (
    (5, "medium", 12.0),
    (3, "low", 6.0),
)

# Percent-encoding ("obfuscation") thresholds.
ENCODING_THRESHOLDS: tuple[tuple[int, str, float], ...] = (
    (10, "medium", 14.0),
    (4, "low", 8.0),
)