"""Deterministic text preprocessing for the ScamShield ML layer.

Covers English, Hindi, Marathi and Hinglish text with lightweight, stateless
transformations only:

  * Unicode normalization (NFC)
  * whitespace normalization
  * ASCII folding of Latin-script characters (keeps Devanagari intact)
  * safe lowercasing of the (already folded) Latin portion
  * preserving useful scam-related tokens: URL http(s)://... is left in place
    but anonymized to a uniform "<URL>" marker to avoid leaking a specific
    host and to help generalize; numbers are NOT stripped because amounts and
    thresholds (e.g. "50000", "Rs.250") are strong scam signals.

This is deliberately lightweight and does NOT claim full multilingual NLP
understanding (no stemming, no lemmatization, no POS, no language model). The
goal is a deterministic, testable tokenization that keeps scam patterns
visible while removing only raw formatting noise.

It never touches network, files or model artifacts.
"""

from __future__ import annotations

import re
import unicodedata

# A URL-like token: scheme + optional authority. We capture the whole run so we
# can replace it with a single uniform marker instead of leaking the host.
_URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)

_WHITESPACE_RE = re.compile(r"\s+")

# Devanagari block + common Indic combining ranges we must NOT fold or strip.
_DEVANAGARI_RE = re.compile(r"[\u0900-\u097F\uA8E0-\uA8FF]")


def normalize_unicode(text: str) -> str:
    """Normalize to NFC (canonical decomposition then recomposition)."""
    return unicodedata.normalize("NFC", text)


def fold_latin(text: str) -> str:
    """Lowercase Latin letters without touching Devanagari.

    Applies case folding only to non-Devanagari characters and maps accented
    Latin letters to ASCII (e.g. "₹" is already a symbol, "é" -> "e"). This
    keeps Devanagari words intact while making the Latin portion
    case-insensitive.
    """
    out = []
    for ch in text:
        if _DEVANAGARI_RE.match(ch):
            out.append(ch)
            continue
        low = ch.lower()
        folded = unicodedata.normalize(
            "NFKD", low
        ).encode("ascii", "ignore").decode("ascii")
        out.append(folded if folded else ch)
    return "".join(out)


def anonymize_urls(text: str) -> str:
    """Replace every URL token with a uniform "<URL>" marker.

    This preserves the crucial "this message contains a link" signal while
    avoiding over-fitting to a specific host and never persisting raw URLs in
    the vectorized features.
    """
    return _URL_RE.sub("<URL>", text)


def normalize_whitespace(text: str) -> str:
    """Collapse runs of whitespace to a single space and strip ends."""
    return _WHITESPACE_RE.sub(" ", text).strip()


def preprocess(text: str) -> str:
    """Full deterministic preprocessing pipeline.

    Order matters and is fixed so identical input always yields identical
    output:

        normalize_unicode -> fold_latin -> anonymize_urls -> whitespace

    `text` may be None (treated as ""). Non-string input that cannot be
    coerced to str raises a ValueError so callers never silently analyse
    unexpected types.
    """
    if text is None:
        text = ""
    if not isinstance(text, str):
        raise ValueError(
            f"preprocess() expects str, got {type(text).__name__}"
        )
    return normalize_whitespace(anonymize_urls(fold_latin(normalize_unicode(text))))


def tokenize_words(text: str) -> list[str]:
    """Split a preprocessed string into word tokens (approx.).

    Keeps alphanumeric runs and the common rupee/symbol forms together. This is
    a light helper for tests/feature inspection; the real feature extraction
    uses scikit-learn's TfidfVectorizer with its own token_pattern.
    """
    return re.findall(r"\w+", text)
