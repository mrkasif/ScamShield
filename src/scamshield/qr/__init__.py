"""ScamShield QR Security Analyzer.

Decodes QR code images locally (OpenCV ``QRCodeDetector``, no network), routes
each decoded payload to its analyser and returns a transparent 0-100 risk
assessment:

    * ``analyze_qr(image_path)`` - decode an image file and analyse every QR
      code in it;
    * ``analyze_qr_content(text)`` - analyse an already decoded payload string
      (no image required).

Content routing:
    url     -> static URL Intelligence Engine (scamshield.url)
    upi     -> static UPI payment-URI parser + scorer (scamshield.qr.upi)
    text    -> static message engine (scamshield.nlp)
    unknown -> neutral result, never auto-malicious

Principles (see `src/scamshield/qr/README.md` for full documentation):
    * fully local and offline - no QR API, no cloud lookup, no keys;
    * never opens decoded URLs and never executes decoded payments;
    * deterministic - same input always yields the same result;
    * decoding a QR code never proves its destination is trustworthy.
"""

from .engine import (
    analyze_qr,
    analyze_qr_content,
    classify_content,
    combine_risk_scores,
    decode_qr_codes as decode_qr_image,
)
from .upi import analyze_upi, parse_upi_uri

__version__ = "1.0.0"

__all__ = [
    "analyze_qr",
    "analyze_qr_content",
    "analyze_upi",
    "classify_content",
    "combine_risk_scores",
    "decode_qr_image",
    "parse_upi_uri",
    "__version__",
]