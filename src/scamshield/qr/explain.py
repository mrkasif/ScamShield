"""Recommendation builder for QR analysis results.

Combines QR-level advice with the underlying engine's recommendations
(URL engine / message engine / UPI scorer) without duplicating entries.
"""

from __future__ import annotations

__all__ = ["build_recommendations"]

_PAYMENT_WARNING = (
    "ScamShield only analyses the decoded QR payload locally. It never opens "
    "the decoded URL and never executes or approves a decoded payment."
)
_SAFE_NOTE = (
    "No strong risk indicators were detected, but always verify QR codes that "
    "come from unsolicited or unknown sources."
)


def _unique(seq: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in seq:
        key = item.strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(item.strip())
    return out


def build_recommendations(
    content_type: str,
    is_suspicious: bool,
    url_analysis: dict | None = None,
    message_analysis: dict | None = None,
    upi_analysis: dict | None = None,
) -> list[str]:
    """Return a de-duplicated recommendation list for a QR content result."""
    recs: list[str] = []

    if content_type == "url":
        recs.append(
            "This QR code decodes to a link. Do not paste it into a payment "
            "page and do not enter credentials on the linked page."
        )
        if is_suspicious:
            recs.extend([
                "Do not enter OTP, PIN or card details on the linked page.",
                "Do not make any payment through this link.",
                "Report the QR code (and the message containing it) to the "
                "platform or bank.",
            ])
        if url_analysis:
            recs.extend(url_analysis.get("recommendations", []))
        recs.append(
            "ScamShield analysed the decoded URL statically and never opened it."
        )
    elif content_type == "upi":
        recs.append(_PAYMENT_WARNING)
        if upi_analysis:
            recs.extend(upi_analysis.get("recommendations", []))
        elif is_suspicious:
            recs.append(
                "Do not approve any unexpected collect or payment request "
                "from this QR code."
            )
    elif content_type == "text":
        recs.append(
            "The QR code contains text that was analysed like a message. "
            "Follow the message analyzer's recommendations below."
        )
        if message_analysis:
            recs.extend(message_analysis.get("recommendations", []))
    elif content_type == "unknown":
        recs.append(
            "This QR code's content type is not recognized. Treat the payload "
            "as unverified and do not act on it."
        )
        recs.append(
            "If the QR code came with an unexpected email or message, do not "
            "scan or act on it."
        )
        recs.append(_PAYMENT_WARNING)
    else:
        recs.append("No usable content was found in the QR code.")

    if content_type in ("url", "upi", "text") and not is_suspicious:
        recs.append(_SAFE_NOTE)
    return _unique(recs)