"""ScamShield URL Intelligence Engine.

Static, local and deterministic risk assessment for a URL string. See
`src/scamshield/url/README.md` for full documentation.

Public API:
    analyze_url(url) -> dict
    combine_message_and_urls(message_score, url_scores) -> dict
    analyze_attachment_filename(filename) -> dict
    assess_sender(display_name, sender_email, sender_domain) -> dict
"""

from .engine import (
    analyze_url,
    analyze_attachment_filename,
    assess_sender,
    combine_message_and_urls,
)

__all__ = [
    "analyze_url",
    "analyze_attachment_filename",
    "assess_sender",
    "combine_message_and_urls",
]