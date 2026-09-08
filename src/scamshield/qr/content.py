"""Classify a decoded QR payload into a content type.

Routing:
    "url"     - payload starts with http:// or https://   -> URL Intelligence Engine
    "upi"     - UPI payment URI (upi://pay?... or upi:pay?...)
              -> UPI parser + indicator scoring
    "text"    - plain message text / multi-line payload   -> message engine
    "unknown" - any other scheme (mailto:, geo:, bitcoin:...) or empty payload.
              A payload classified "unknown" is NEVER auto-marked malicious.

Classification only inspects the leading characters of the string. It never
fetches, executes or opens anything.
"""

from __future__ import annotations

import re

__all__ = ["classify_content"]

_HTTP_RE = re.compile(r"^https?://", re.IGNORECASE)
_UPI_RE = re.compile(r"^upi:(//)?", re.IGNORECASE)
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")


def classify_content(text: str) -> str:
    """Return one of: "url", "upi", "text", "unknown"."""
    payload = (text or "").strip()
    if not payload:
        return "unknown"
    if _HTTP_RE.match(payload):
        return "url"
    if _UPI_RE.match(payload):
        return "upi"
    # Multi-line payloads (vCards, contact data...) are free text.
    if "\n" in payload or "\r" in payload:
        return "text"
    # A single-line string starting with an unknown scheme is unverified.
    if _SCHEME_RE.match(payload):
        return "unknown"
    return "text"