"""Individual indicator detectors for the ScamShield message engine.

Each detector is a pure function that inspects a normalized message (plus a list
of extracted URLs) and reports whether a particular risk indicator is present,
along with a severity (low / medium / high).

A detector firing is a *signal*, not a verdict on its own. The scoring module
combines all fired indicators with weighted scores to produce the final risk.
"""

from __future__ import annotations

import re
from typing import Callable

from . import patterns as _p


_URL_RE = re.compile(
    r"(?i)(?:https?://|www\.)[^\s<>()\[\]{}'\"]+" r"|(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?:/[^\s]*)?)",
)


URL_SCHEME_RE = re.compile(r"^(?:https?://|www\.)", re.I)
IP_HOST_RE = re.compile(r"^(?:[\d]{1,3}\.){3}[\d]{1,3}($|/)")
SHORTENER_RE = re.compile(r"(?i)(?:bit\.ly|tinyurl|goo\.gl|t\.co|rb\.gy|cutt\.ly|is\.gd|shorturl|ow\.ly|bit\.ly|tiny\.cc|lnkd\.in|rebrandly)")


def normalize(text: str) -> str:
    """Lowercase, collapse whitespace and strip for token/phrase matching."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text.strip().lower())


def extract_urls(text: str) -> list[str]:
    """Extract candidate URLs from a message (heuristic). Does NOT analyse them."""
    found: list[str] = []
    for m in _URL_RE.finditer(text or ""):
        url = m.group(0).rstrip(".,;:!?)]}>'\"").strip()
        # Try to recover a protocol-less domain preceded by whitespace.
        if url and url not in found:
            found.append(url)
    return found


def _count_hits(text: str, words: tuple[str, ...]) -> int:
    hits = 0
    for w in words:
        if re.search(r"[\u0900-\u097F]", w):
            # Devanagari: plain substring match (word boundaries are unreliable)
            if w in text:
                hits += 1
        else:
            # Latin-script: full word / phrase using two-sided word boundaries
            if re.search(r"(?<!\w)" + re.escape(w) + r"(?!\w)", text):
                hits += 1
    return hits


def _has_any(text: str, words: tuple[str, ...]) -> bool:
    return _count_hits(text, words) > 0


# ---------------------------------------------------------------------------
# Individual detectors. Each returns (present: bool, severity: str)
# ---------------------------------------------------------------------------

def detect_urgency(text: str) -> tuple[bool, str]:
    n = _count_hits(text, _p.URGENCY_WORDS)
    if n >= 3:
        return True, "high"
    if n >= 2:
        return True, "medium"
    if n == 1:
        return True, "low"
    return False, "low"


def detect_threat(text: str) -> tuple[bool, str]:
    n = _count_hits(text, _p.THREAT_WORDS)
    if n >= 2:
        return True, "high"
    if n == 1:
        return True, "medium"
    return False, "low"


def detect_kyc(text: str) -> tuple[bool, str]:
    return (bool(_has_any(text, _p.KYC_WORDS)), "high")


def detect_otp_request(text: str) -> tuple[bool, str]:
    """An OTP is only a *request* when the message asks the user to share, send,
    enter, or verify it. Merely mentioning OTP (e.g. a legit 'OTP for login is
    123456' or a warning 'do not share OTP') is not flagged."""
    # Protective phrases mean the message warns, not requests.
    if _has_any(text, _p.SAFE_MARKERS):
        return False, "low"
    # Request verbs that turn a mention of OTP into a request.
    request_verbs = (
        "share", "send", "enter", "tell", "provide", "give", "confirm",
        "verify", "submit", "batao", "do", "bhejo", "maango", "dene", "de",
        "साझा", "बताएं", "दें", "भेजें", "डालें", "बताओ", "भेजो", "दो",
        "शेयर", "द्या", "उघडा", "द्यायचा",
    )
    has_otp_word = _has_any(text, ("otp", "one time password", "one-time password",
                                   "ओटीपी", "वन टाइम पासवर्ड", "सुरक्षा कोड",
                                   "सत्यापन कोड", "सुरक्षा कोड", "otp"))
    if not has_otp_word:
        return False, "low"
    # Count request-verb co-occurrence
    hits = 0
    for v in request_verbs:
        if re.search(r"\b" + re.escape(v), text):
            hits += 1
    # A direct imperative like "share OTP" should count even if verb boundaries
    # are tricky; fall back to phrase detection.
    if _has_any(text, _p.OTP_WORDS):
        # confirm at least one explicit request phrase exists
        if any(req in text for req in ("share otp", "send otp", "enter otp",
                                       "tell otp", "otp batao", "otp do",
                                       "otp bhejo", "otp dene", "otp de",
                                       "otp share", "otp maango",
                                       "ओटीपी दें", "ओटीपी बताएं", "ओटीपी भेजें",
                                       "ओटीपी डालें", "ओटीपी शेयर")):
            hits += 2
    if hits >= 2:
        return True, "high"
    if hits == 1:
        return True, "medium"
    return False, "low"


def detect_credential_request(text: str) -> tuple[bool, str]:
    n = _count_hits(text, _p.CREDENTIAL_WORDS)
    if n >= 2:
        return True, "high"
    if n == 1:
        return True, "medium"
    return False, "low"


def detect_upi_payment(text: str) -> tuple[bool, str]:
    n = _count_hits(text, _p.UPI_PAYMENT_WORDS)
    if n >= 3:
        return True, "high"
    if n >= 2:
        return True, "medium"
    if n == 1:
        return True, "low"
    return False, "low"


def detect_prize_lottery(text: str) -> tuple[bool, str]:
    return (bool(_has_any(text, _p.PRIZE_WORDS)), "high")


def detect_job_offer(text: str) -> tuple[bool, str]:
    return (bool(_has_any(text, _p.JOB_WORDS)), "medium")


def detect_investment_offer(text: str) -> tuple[bool, str]:
    n = _count_hits(text, _p.INVESTMENT_WORDS)
    if n >= 2:
        return True, "high"
    if n == 1:
        return True, "medium"
    return False, "low"


def detect_loan_offer(text: str) -> tuple[bool, str]:
    n = _count_hits(text, _p.LOAN_WORDS)
    if n >= 2:
        return True, "high"
    if n == 1:
        return True, "medium"
    return False, "low"


def detect_customer_care(text: str) -> tuple[bool, str]:
    n = _count_hits(text, _p.CUSTOMER_CARE_WORDS)
    if n >= 2:
        return True, "high"
    if n == 1:
        return True, "medium"
    return False, "low"


def detect_delivery_package(text: str) -> tuple[bool, str]:
    n = _count_hits(text, _p.DELIVERY_WORDS)
    if n >= 2:
        return True, "high"
    if n == 1:
        return True, "medium"
    return False, "low"


def detect_bank_impersonation(text: str) -> tuple[bool, str]:
    n = _count_hits(text, _p.BANK_WORDS)
    if n >= 2:
        return True, "high"
    if n == 1:
        return True, "medium"
    return False, "low"


def detect_government_impersonation(text: str) -> tuple[bool, str]:
    n = _count_hits(text, _p.GOVERNMENT_WORDS)
    if n >= 2:
        return True, "high"
    if n == 1:
        return True, "medium"
    return False, "low"


def detect_social_impersonation(text: str) -> tuple[bool, str]:
    n = _count_hits(text, _p.SOCIAL_WORDS)
    if n >= 2:
        return True, "high"
    if n == 1:
        return True, "medium"
    return False, "low"


def detect_sensitive_info(text: str) -> tuple[bool, str]:
    return (bool(_has_any(text, _p.SENSITIVE_INFO_WORDS)), "medium")


def detect_suspicious_link(text: str, urls: list[str]) -> tuple[bool, str]:
    """A suspicious link is one that is present alongside other pressure cues,
    is a shortened URL, points to an IP literal, or is explicitly requested."""
    suspicious = False
    for u in urls:
        if SHORTENER_RE.search(u):
            suspicious = True
        elif IP_HOST_RE.search(u.split("://")[-1]):
            suspicious = True
    # Explicit instruction to click / open / verify a link
    if _has_any(text, _p.LINK_HINT_WORDS):
        suspicious = True
    severity = "high" if suspicious else "low"
    return suspicious, severity


def detect_reward_claim(text: str) -> tuple[bool, str]:
    return (bool(_has_any(text, _p.REWARD_CLAIM_WORDS)), "medium")


# ---------------------------------------------------------------------------
# Public registry: name -> detector callable (takes text and urls)
# ---------------------------------------------------------------------------

def _mk(det_fn: Callable[[str], tuple[bool, str]]) -> Callable[[str, list], tuple[bool, str]]:
    def _wrap(text: str, urls: list) -> tuple[bool, str]:
        return det_fn(text)
    return _wrap


DETECTORS: dict[str, Callable[[str, list], tuple[bool, str]]] = {
    "urgency": _mk(detect_urgency),
    "threat": _mk(detect_threat),
    "kyc_request": _mk(detect_kyc),
    "otp_request": _mk(detect_otp_request),
    "credential_request": _mk(detect_credential_request),
    "upi_payment_request": _mk(detect_upi_payment),
    "prize_lottery": _mk(detect_prize_lottery),
    "job_offer": _mk(detect_job_offer),
    "investment_offer": _mk(detect_investment_offer),
    "loan_offer": _mk(detect_loan_offer),
    "customer_care": _mk(detect_customer_care),
    "delivery_package": _mk(detect_delivery_package),
    "bank_impersonation": _mk(detect_bank_impersonation),
    "government_impersonation": _mk(detect_government_impersonation),
    "social_impersonation": _mk(detect_social_impersonation),
    "sensitive_info_request": _mk(detect_sensitive_info),
    "reward_claim": _mk(detect_reward_claim),
    "suspicious_link": detect_suspicious_link,
}


def detect_all(text: str) -> dict[str, dict]:
    """Run every detector over the message and return {indicator: {present, severity}}."""
    norm = normalize(text)
    urls = extract_urls(text)
    out: dict[str, dict] = {}
    for name, fn in DETECTORS.items():
        present, sev = fn(norm, urls)
        out[name] = {"present": present, "severity": sev}
    return out
