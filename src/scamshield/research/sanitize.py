"""Defensive text sanitisation for FP / FN example display.

Redacts phone numbers, OTPs, card numbers, bank accounts, UPI IDs, URLs,
emails and IP addresses before writing examples to disk. This is defence-in-
depth: the dataset already uses placeholders, but we never assume the dataset
is perfectly sanitised.

Sanitised values are replaced with bracketed labels (e.g. [PHONE], [URL]).
Output is truncated to a safe length. The original text is never persisted.
"""
from __future__ import annotations

import re

_MAX_LEN = 160

# OTP: keyword then digits (e.g. "OTP 123456", "pin: 4567", "otp is 123456")
_RE_OTP = re.compile(
    r"(?i)(?:\b(?:otp|one[\s-]?time[\s-]?password|pin)\b[^0-9]{0,20})(\d{4,8})\b",
)

# Card number: 4 groups of 4 digits (credit/debit card format)
_RE_CARD = re.compile(r"\b(\d{4}[ -]?){3}\d{4}\b")

# UPI payee address: identifier@handle (e.g. merchant@okaxis)
_RE_UPI_ID = re.compile(
    r"\b([a-z][a-z0-9._-]{2,30}@[a-z]{2,}(?:\.[a-z]{2,}){0,3})\b", re.IGNORECASE,
)

# Bank account / A/C: labelled or bare 9-18 digit run
_RE_ACCOUNT_LABELLED = re.compile(
    r"(?i)\b(a/c|acct|account|acc\.?)\s*[.:\-#/ ]*\s*(\d{4,})",
)
_RE_ACCOUNT_BARE = re.compile(r"(?<!\d)(\d{9,18})(?!\d)")

# URL (full URL span)
_RE_URL = re.compile(r"(?i)\bhttps?://\S+")

# Email address
_RE_EMAIL = re.compile(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")

# IPv4 address (not routable test-net but sanitise anyway)
_RE_IP = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

# 10-digit Indian phone number (starts 6-9)
_RE_PHONE = re.compile(r"(?<!\d)([6-9]\d{9})(?!\d)")

# Standalone 6-8 digit number after keywords like "reference" / "ref"
_RE_REF = re.compile(
    r"(?i)\b(ref(?:erence)?|ref[\s-]?no\.?)[^0-9]{0,12}(\d{4,10})\b",
)


def sanitize_text(text: str, *, max_len: int = _MAX_LEN) -> str:
    """Replace sensitive-looking tokens with bracketed labels, then truncate.

    The sanitisation is deliberately broad and lossy — the goal is to prevent
    accidental leakage, not to reconstruct the original text.
    """
    if not text:
        return ""
    s = text
    s = _RE_OTP.sub("[OTP]", s)
    s = _RE_CARD.sub("[CARD]", s)
    s = _RE_URL.sub("[URL]", s)
    s = _RE_EMAIL.sub("[EMAIL]", s)
    s = _RE_UPI_ID.sub("[UPI_ID]", s)
    s = _RE_ACCOUNT_LABELLED.sub(r"\1 [ACCOUNT]", s)
    s = _RE_PHONE.sub("[PHONE]", s)
    s = _RE_ACCOUNT_BARE.sub("[ACCOUNT]", s)
    s = _RE_IP.sub("[IP]", s)
    s = _RE_REF.sub(r"\1 [REF]", s)
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return s


def sanitize_example(record: dict, predicted: str, *, max_len: int = _MAX_LEN) -> dict:
    """Build a sanitised FP / FN example for reporting.

    Returns a dict with: label (true), predicted, excerpt (sanitised), truncated.
    The original text is never included.
    """
    text = record.get("text", "")
    excerpt = sanitize_text(text, max_len=max_len)
    truncated = len(text) > max_len
    return {
        "id": record.get("id"),
        "label": record.get("scam_or_safe", record.get("label", "")),
        "predicted": predicted,
        "language": record.get("language"),
        "scam_type": record.get("scam_type"),
        "excerpt": excerpt,
        "truncated": truncated,
    }
