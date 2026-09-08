"""Generate safe, synthetic QR fixture images for tests and demos.

All payloads below are fictitious (example.com, @upi test IDs, harmless text).
Nothing here contacts the network or a real payment service.

Usage:
    python scripts/generate_qr_fixtures.py               # -> tests/fixtures/qr/*.png
    python scripts/generate_qr_fixtures.py --out tmp     # -> tmp/*.png
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import cv2
    import numpy as np
    import qrcode
except Exception as exc:  # pragma: no cover
    print(f"Missing dependency: {exc}")
    print("Install with: python -m pip install opencv-python-headless qrcode")
    raise SystemExit(1)

FIXTURES = {
    "url_benign.png": "https://example.com/offer",
    "url_suspicious.png": "https://secure-sbi-verify.example.com/login",
    "upi_normal.png": "upi://pay?pa=merchant@upi&pn=Tea Store&am=60.00&cu=INR&tn=Order",
    "upi_refund_scan.png": ("upi://pay?pa=prize.claim@upi&am=50000&cu=INR&"
                            "tn=Congratulations! Claim your reward refund now"),
    "text_scam.png": "Your KYC is blocked. Verify immediately and enter the OTP sent to your phone.",
    "text_plain.png": "Meet me at 5pm at the cafe.",
    "unknown_scheme.png": "mailto:user@example.com",
    "multi_two_codes.png": None,  # built specially below
    "no_qr_blank.png": None,      # built specially below
}


def _render(payload: str, size: int = 512) -> np.ndarray:
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    return np.array(qr.make_image().convert("RGB"))


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(Path("tests", "fixtures", "qr")))
    args = parser.parse_args(argv)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    for name, payload in FIXTURES.items():
        img = _render(payload) if payload is not None else None

        if name == "multi_two_codes.png":
            img = _render("https://example.com/")
            second = _render("upi://pay?pa=a@upi&am=50")
            pad = 40
            h = max(img.shape[0], second.shape[0])
            canvas = np.full(
                (h + 2 * pad, img.shape[1] + second.shape[1] + 3 * pad, 3),
                255,
                np.uint8,
            )
            oy = (canvas.shape[0] - img.shape[0]) // 2
            canvas[oy:oy + img.shape[0], pad:pad + img.shape[1]] = img
            oy = (canvas.shape[0] - second.shape[0]) // 2
            x0 = pad + img.shape[1] + pad
            canvas[oy:oy + second.shape[0], x0:x0 + second.shape[1]] = second
            img = canvas
        if name == "no_qr_blank.png":
            img = np.full((512, 512, 3), 245, np.uint8)

        cv2.imwrite(str(out_dir / name), img)
        print(f"wrote {out_dir / name}")

    print("Generated synthetic QR fixtures (100% local, safe payloads).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())