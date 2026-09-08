"""Local QR code image decoding.

Uses the ``QRCodeDetector`` shipped with ``opencv-python-headless`` so no
separate ZBar/DLL dependency is required. The image is read once and decoded
in memory; nothing is ever uploaded or sent to a network service.

Public function:
    decode_qr_codes(image_path) -> dict
"""

from __future__ import annotations

from pathlib import Path

try:
    import cv2  # noqa: PLC0415
    QR_DECODER_AVAILABLE = True
except Exception:  # pragma: no cover - depends on the installed environment
    cv2 = None
    QR_DECODER_AVAILABLE = False

__all__ = ["QR_DECODER_AVAILABLE", "decode_qr_codes"]


def _read_all(image) -> list[str]:
    """Return every non-empty payload decoded from ``image``.

    Multi QR decoding is preferred; the single-code decoder is only a
    fallback for images the multi decoder rejects. Both call sites are
    guarded so a decoding failure can never propagate as an exception.
    """
    decoder = cv2.QRCodeDetector()
    try:
        retval, decoded_info, _points, _straight = decoder.detectAndDecodeMulti(image)
        if retval:
            codes = [str(t) for t in decoded_info if t]
            if codes:
                return codes
    except Exception:
        pass
    try:
        data, _points, _straight = decoder.detectAndDecode(image)
        if data:
            return [str(data)]
    except Exception:
        pass
    return []


def decode_qr_codes(image_path) -> dict:
    """Decode every QR code found in an image file.

    Returns a dict and never raises an exception:

        ok      - True when the pipeline ran (False on a missing file or an
                  unreadable image - the reason is under "error").
        decoded - True when at least one QR code payload was extracted.
        codes   - list[str] of decoded payloads (empty strings dropped).
        count   - number of decoded codes.
        error   - None or a human-readable reason.

    Security guards: the function only reads and decodes the image. It does
    not open URLs, execute payloads or contact any service.
    """
    path = Path(image_path)
    if not QR_DECODER_AVAILABLE:
        return {
            "ok": True,
            "decoded": False,
            "codes": [],
            "count": 0,
            "error": "QR decoder backend (opencv-python-headless) is not installed.",
        }
    if not path.is_file():
        return {
            "ok": False,
            "decoded": False,
            "codes": [],
            "count": 0,
            "error": f"Image file not found: {path}",
        }
    try:
        image = cv2.imread(str(path), cv2.IMREAD_COLOR)
    except Exception:
        image = None
    if image is None:
        return {
            "ok": False,
            "decoded": False,
            "codes": [],
            "count": 0,
            "error": "Unreadable image (unsupported format or corrupt file).",
        }
    try:
        codes = _read_all(image)
    except Exception:
        codes = []
    return {
        "ok": True,
        "decoded": bool(codes),
        "codes": codes,
        "count": len(codes),
        "error": None,
    }