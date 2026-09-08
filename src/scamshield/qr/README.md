# `qr/` - QR Security Analyzer

**Offline, local, deterministic QR analysis.** Decodes QR code images on the
machine (OpenCV `QRCodeDetector`, no network, no QR API, no keys), classifies
the decoded payload and routes it to the matching analysis engine.

## Public API

```python
from scamshield.qr import analyze_qr, analyze_qr_content

result = analyze_qr("path/to/qr.png")        # decode image -> analyse
result = analyze_qr_content("upi://pay?...")  # analyse an already-decoded payload
```

## Content routing

| Payload                                   | Content type | Analysed by                     |
| ----------------------------------------- | ------------ | ------------------------------- |
| `https://...` / `http://...`              | `url`        | `scamshield.url` (static)       |
| `upi://pay?...` (or `upi:pay?...`)        | `upi`        | `scamshield.qr.upi` (static)    |
| Plain text / multi-line payload           | `text`       | `scamshield.nlp` (static)       |
| Anything else (`mailto:`, `geo:`, ...)    | `unknown`    | neutral result, never malicious |

A `url` QR result embeds the full URL assessment under `url_analysis`; a
`text` QR result embeds the message assessment under `message_analysis`; a
`upi` QR result embeds the UPI assessment under `upi_analysis`. QR-level risk,
level and confidence are inherited from the routed engine, and the explanation
always states that ("URL risk was inherited from the URL Intelligence Engine").

## Result schema

`analyze_qr_content` / `analyze_qr` return:

- `success` (bool), `status` (`DECODED` / `NOT DECODED` / `ERROR`)
- `content_type` (`url` | `upi` | `text` | `unknown`)
- `decoded_content`, `risk_score` (0-100), `risk_level`
  (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`), `is_suspicious`, `confidence`
- `indicators` (list of fired signal names)
- `explanation` — list of `{indicator, severity, score, reason, evidence}`,
  every point of the final score is listed
- `recommendations` (list), `warning`
- `url_analysis` / `message_analysis` / `upi_analysis` (routed engine results)
- `analyze_qr` adds: `file`, `decoded`, `decoded_count`, `codes` (all decoded
  payloads), `multiple_codes`, `code_analyses`, `error`, `note`

Hard errors (missing file, unreadable image, missing backend) never raise:
they return `success=False`, `status="ERROR"` and a safe message.

## UPI analysis (static, transparent)

Parses `pa`, `pn`, `am`, `cu`, `tn`, `mc`, `tr`/`tid` from the URI with the
standard library only. Indicators:

| Indicator                                   | Severity | Points  |
| ------------------------------------------- | -------- | ------- |
| `payment_destination_detected`              | low      | 8       |
| `embedded_payment_amount`                   | low      | 10      |
| `recipient_not_named`                       | low      | 6       |
| `payment_amount_threshold_1` (≥ 10,000)     | low      | 8       |
| `payment_amount_threshold_2` (≥ 50,000)     | medium   | 14      |
| `payment_amount_threshold_3` (≥ 100,000)    | high     | 22      |
| `malformed_upi_uri`                         | low      | 8       |
| `non_pay_action`                            | low      | 4       |
| `urgent_payment_request`                    | medium   | 16      |
| `refund_reward_prize_language`              | medium   | 18      |
| `kyc_unblock_account_language`              | medium   | 18      |
| `otp_credential_request`                    | high     | 30      |
| `social_engineering_cluster` (3+ families)  | medium   | 10      |

Combination bonuses (each applied once, +4 to +6) reward pairs that are much
stronger together than apart - e.g. *destination + amount*, *amount + urgency*,
*refund + urgency*, *OTP + destination*. Caps: all note-language family
indicators together are capped at 45 points (scaled proportionally so the
explanation always sums to the score). The score is clamped to 0-100.

**Calibration:** a normal "pay this merchant" QR (destination + name + small
amount) stays LOW. A refund/prize/urgent note with a high amount reaches
HIGH/CRITICAL. The analyzer never claims a specific UPI ID is fraudulent -
it always says *verify the recipient*.

## Multiple QR codes in one image

`decode_qr_codes` uses `detectAndDecodeMulti` (with a single-code fallback).
Every decoded payload is analysed independently and the final risk is combined
with the documented **70% headroom rule** (the same rule shape used for
message+URL combination):

    combined = strongest
    for each further score s (descending):
        combined = combined + (100 - combined) * (s / 100) * 0.7

The result is always ≥ the strongest component (never a diluted average),
order-independent, and capped at 100. `combine_risk_scores(scores)` is exposed
publicly. Note in the result: *"an image with several QR codes can hide a
harmful second code."*

## Security guarantees

- **No network.** The image is read and decoded in memory; nothing is sent
  anywhere.
- **No execution / no payment.** The decoded URL is never opened and the UPI
  payload is never executed or approved. The module imports no payment SDK.
- **No verdicts on trust.** Decoding a QR code never proves its destination or
  recipient is trustworthy.
- **Deterministic.** Identical input always yields identical output.
- **Never raises on bad input.** Missing files, corrupt images, malformed UPI
  URIs and arbitrary strings all return safe structured results.

The `tests/test_qr_engine.py` suite (56 tests) monkeypatches the network,
subprocess and payment-import surfaces to prove the analyzer cannot reach out.

## CLI

```bash
python -m app.qr_scan "path/to/qr.png"     # single image
python -m app.qr_scan a.png b.jpg c.webp   # several images
```

## Generating demo fixtures

```bash
python scripts/generate_qr_fixtures.py      # writes tests/fixtures/qr/*.png
```

All fixtures are synthetic and safe (`.example.com` hosts, `@upi` test IDs).
Runtime analysis needs only `opencv-python-headless`; `qrcode` exists solely
for generating these images in tests and demos.