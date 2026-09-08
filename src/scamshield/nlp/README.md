# `nlp/` - Message and Text Processing

Responsible for: **Message/text processing and scam classification.**

This module is the first working ScamShield detection layer: an **explainable,
deterministic, rule-based message intelligence engine** that needs no internet,
no GPU and no paid APIs at prediction time.

## Quick start

```bash
# From the repo root.
python -m pytest tests/test_scamshield.py -q     # run the test suite
python -m app.scan "Your KYC has expired. Verify immediately at this link."
```

## Public API

```python
from scamshield.nlp import analyze_message

result = analyze_message("Your bank account is blocked. Share your OTP to unblock it.")

# result keys
# is_scam             bool
# risk_score          int 0-100
# risk_level          "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"
# scam_type           one of the supported categories (or "safe")
# confidence          float 0-1
# detected_indicators list[str]
# detected_urls       list[str]
# explanations        list[str]   human-readable reasons
# recommendations     list[str]   actionable safety advice
```

## How it works

1. `patterns.py` - multilingual indicator dictionaries (English, Hindi,
   Marathi and romanised Hinglish): banks, UPI/payment verbs, OTP requests,
   link hints, threats/urgency, job/investment/loan/delivery/lottery terms,
   government/utility terms, credentials, safe cues (e.g. "official app").
2. `detectors.py` - individual binary detectors per indicator, plus
   `extract_urls()` (IPv4, bare domains and full URLs). Latin words are
   matched with Unicode word boundaries; Devanagari uses substring matching
   because Devanagari scripts do not use word breaks.
3. `scoring.py` - weighted scoring: each detector has a weight multiplied by a
   severity multiplier (low 1.0 / medium 1.6 / high 2.2), plus bonuses for
   indicator *combinations* (e.g. bank impersonation + threat = +10) and a
   systematic bonus when a scam *family* coincides with a money/credential
   request (pushing single-family fee-scams like jobs and loans past the
   threshold). Legitimate transactional confirmations and safe cues are
   penalised/neutralised so realistic bank/app/Train messages stay safe.
4. `category.py` - maps fired indicators to a scam type using a priority
   order (specific families such as `fake_kyc`, `lottery_prize` or
   `delivery_scam` win over the generic `upi_payment`).
5. `explain.py` - converts every fired indicator into a human-readable
   explanation and maps the category to actionable recommendations.
6. `engine.py` - `analyze_message()` orchestrates the pipeline and returns a
   fully reproducible dict.

## Risk levels

| Score   | Level    |
|---------|----------|
| 0-24    | LOW      |
| 25-49   | MEDIUM   |
| 50-74   | HIGH     |
| 75-100  | CRITICAL |

Messages with `risk_score >= 50` are flagged as scams (`is_scam = True`).

## Supported scam types

`fake_kyc` · `bank_impersonation` · `credential_theft` · `government_impersonation` ·
`lottery_prize` · `job_scam` · `investment_scam` · `loan_scam` · `delivery_scam` ·
`fake_customer_care` · `social_media_impersonation` · `upi_payment` · `phishing` · `other`

## Languages

- English (`en`)
- Hindi (`hi`)
- Marathi (`mr`)
- Hinglish (code-mixed English-Hindi / English-Marathi)

## Limitations

- Rule-based and heuristic: coverage depends on the curated dictionaries;
  wording outside them may be missed. There is **no ML model yet**.
- Not a guaranteed detector - scoring is a calibrated heuristic, not a
  probability. Always treat a HIGH/CRITICAL result as "verify before acting".
- URL extraction extracts the URL string but does **not** assess the
  destination (pure heuristic `url/` analysis is a later task).
- Detecting contextual meaning (sarcasm, family-group humour, follow-up
  chains) is out of scope for this layer.

Output feeds into the Risk Engine (`risk/`) and Explainability layer
(`explain/`) in later steps; today this module provides both scoring and
explainability directly so the prototype is usable end-to-end.