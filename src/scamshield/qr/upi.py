"""UPI payment URI parsing and static risk assessment.

URIs look like::

    upi://pay?pa=merchant@upi&pn=Name&am=100.00&cu=INR&tn=note&mc=0000&tr=txn1

Parsing is done with the stdlib URL parser only. The scanner NEVER:

    * talks to a payment gateway, NPCI or any network service;
    * generates, executes or approves a payment;
    * claims that a specific UPI ID is fraudulent.

The score is a transparent 0-100 heuristic: every point is listed under
"explanation" with its indicator, severity, exact contribution and evidence.
A plain "pay this merchant" QR stays LOW. Higher scores come only from
combinations of embedded payment details, unusual amounts and
social-engineering language in the transaction note.

Public functions:
    parse_upi_uri(uri) -> dict
    analyze_upi(uri) -> dict
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urlsplit

__all__ = ["analyze_upi", "parse_upi_uri"]

# ---------------------------------------------------------------------------
# Indicator table: (contribution, severity)
# ---------------------------------------------------------------------------

INDICATORS = {
    "payment_destination_detected": (8.0, "low"),
    "embedded_payment_amount": (10.0, "low"),
    "recipient_not_named": (6.0, "low"),
    "payment_amount_threshold_1": (8.0, "low"),      # >= 10,000
    "payment_amount_threshold_2": (14.0, "medium"),  # >= 50,000
    "payment_amount_threshold_3": (22.0, "high"),    # >= 100,000
    "malformed_upi_uri": (8.0, "low"),
    "non_pay_action": (4.0, "low"),
    "urgent_payment_request": (16.0, "medium"),
    "refund_reward_prize_language": (18.0, "medium"),
    "kyc_unblock_account_language": (18.0, "medium"),
    "otp_credential_request": (30.0, "high"),
}

# Amount thresholds are checked from most to least specific.
AMOUNT_THRESHOLDS = (
    (100000.0, "payment_amount_threshold_3"),
    (50000.0, "payment_amount_threshold_2"),
    (10000.0, "payment_amount_threshold_1"),
)

# Note-language families. Each family is matched independently on the
# lower-cased transaction note with word boundaries, so a normal note such as
# "Order #1234 Refund" is only ever a weak signal on its own.
_URGENT_WORDS = (
    "urgent", "immediately", "asap", "act now", "hurry", "now only",
    "today only", "limited time", "fast",
)
_REFUND_WORDS = (
    "refund", "prize", "reward", "cashback", "cash back", "gift", "won",
    "winner", "lottery", "free money", "claim",
)
_KYC_WORDS = (
    "kyc", "update kyc", "aadhaar link", "aadhaar update", "unblock",
    "reactivate", "account blocked", "account block", "verify account",
    "account verification", "know your customer",
)
_CRED_WORDS = (
    "otp", "pin", "password", "credential", "net banking", "card number",
    "cvv", "login",
)

NOTE_FAMILIES = {
    "urgent_payment_request": _URGENT_WORDS,
    "refund_reward_prize_language": _REFUND_WORDS,
    "kyc_unblock_account_language": _KYC_WORDS,
    "otp_credential_request": _CRED_WORDS,
}

# Cap for all note-language family indicators combined (avoids stacking many
# words in one note to an absurd score).
UPI_MAX_NOTE_SCORE = 45.0

# Combination bonuses: (indicator_a, indicator_b, points, reason)
UPI_COMBINATIONS = (
    (
        "payment_destination_detected",
        "embedded_payment_amount",
        4.0,
        "A payment destination and amount are embedded in this QR code. "
        "Verify the recipient and amount before approving the transaction.",
    ),
    (
        "embedded_payment_amount",
        "payment_amount_threshold_1",
        6.0,
        "The embedded amount is unusually large for a personal transfer.",
    ),
    (
        "embedded_payment_amount",
        "urgent_payment_request",
        6.0,
        "An amount combined with urgent wording is a common collect-request "
        "or refund-fraud pattern.",
    ),
    (
        "refund_reward_prize_language",
        "urgent_payment_request",
        6.0,
        "Refund/prize wording combined with urgency is a classic "
        "advance-fraud pattern.",
    ),
    (
        "kyc_unblock_account_language",
        "urgent_payment_request",
        6.0,
        "KYC/account business combined with urgency pressures the victim.",
    ),
    (
        "otp_credential_request",
        "payment_destination_detected",
        6.0,
        "Requesting credentials together with a payment destination is not "
        "how legitimate merchants collect payments.",
    ),
)

CLUSTER_NEEDED = 3  # note-language families that must fire for the cluster bonus


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _clean_query(value: str | None) -> str | None:
    if value is None:
        return None
    value = unquote(value).strip()
    return value or None


def _parse_amount(value: str | None):
    """Parse a currency amount to an int/float or None. Never raises."""
    if value is None:
        return None
    clean = str(value).strip().replace(",", "")
    if clean in {"", ".", "-", "+"}:
        return None
    try:
        number = float(clean)
    except ValueError:
        return None
    if number < 0 or number != number or number in (float("inf"), float("-inf")):
        return None
    return int(number) if number.is_integer() else round(number, 2)


def parse_upi_uri(uri: str) -> dict:
    """Parse a UPI URI into its fields.

    Returns a dict (never raises) with at least:
        raw, scheme, action, is_pay, payee_address, payee_name, amount,
        currency, transaction_note, merchant_code, transaction_ref,
        valid_upi, malformed
    """
    raw = (uri or "").strip()
    out = {
        "raw": raw,
        "scheme": "",
        "action": "",
        "is_pay": False,
        "payee_address": None,
        "payee_name": None,
        "amount": None,
        "currency": None,
        "transaction_note": None,
        "merchant_code": None,
        "transaction_ref": None,
        "valid_upi": False,
        "malformed": False,
    }
    if not raw:
        out["malformed"] = True
        return out
    try:
        split = urlsplit(raw)
    except ValueError:
        out["malformed"] = True
        return out
    if (split.scheme or "").lower() != "upi":
        out["malformed"] = True
        return out
    out["scheme"] = "upi"
    action = (split.netloc or split.path or "").lstrip("/").lower()
    action = action.split("?")[0]
    out["action"] = action
    out["is_pay"] = action == "pay"

    params: dict[str, str] = {}
    try:
        for key, value in parse_qsl(split.query, keep_blank_values=True):
            low_key = key.lower()
            if low_key not in params:
                params[low_key] = value
    except Exception:
        params = {}

    out["payee_address"] = _clean_query(params.get("pa"))
    out["payee_name"] = _clean_query(params.get("pn"))
    out["amount"] = _parse_amount(params.get("am"))
    out["currency"] = _clean_query(params.get("cu"))
    out["transaction_note"] = _clean_query(params.get("tn"))
    out["merchant_code"] = _clean_query(params.get("mc"))
    out["transaction_ref"] = _clean_query(
        params.get("tr") or params.get("tid")
    )
    out["valid_upi"] = out["is_pay"] and bool(
        out["payee_address"] or out["payee_name"]
    )
    if out["is_pay"] and not (out["payee_address"] or out["payee_name"]):
        out["malformed"] = True
    return out


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _note_matches(note: str) -> dict[str, list[str]]:
    """Map fired family name -> matched words (word boundaries)."""
    low = f" {note.lower()} "
    fired: dict[str, list[str]] = {}
    for family, words in NOTE_FAMILIES.items():
        hits = [w for w in words if re.search(rf"(?<![A-Za-z]){re.escape(w)}(?![A-Za-z])", low)]
        if hits:
            fired[family] = hits
    return fired


def _detect(findings: list[dict], fields: dict, note_families: dict) -> None:
    """Append indicator dicts (in a stable order) to ``findings``."""

    def add(indicator: str, evidence: str) -> None:
        score, severity = INDICATORS[indicator]
        findings.append({
            "indicator": indicator,
            "severity": severity,
            "score": score,
            "evidence": evidence,
        })

    if fields["malformed"]:
        add("malformed_upi_uri", fields["raw"])
    if fields["action"] and fields["action"] != "pay":
        add("non_pay_action", fields["action"])
    if fields["payee_address"]:
        add("payment_destination_detected", fields["payee_address"])
        if not fields["payee_name"]:
            add("recipient_not_named", fields["payee_address"])
    if fields["amount"] is not None:
        add("embedded_payment_amount", str(fields["amount"]))
        for threshold, indicator in AMOUNT_THRESHOLDS:
            if fields["amount"] >= threshold:
                add(indicator, str(fields["amount"]))
                break
    for family in (
        "urgent_payment_request",
        "refund_reward_prize_language",
        "kyc_unblock_account_language",
        "otp_credential_request",
    ):
        if note_families.get(family):
            add(family, ", ".join(note_families[family]))


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _risk_level(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _score(contributions: list[dict]) -> dict:
    """Sum indicator points, apply combination bonuses, cap the note-language
    family and clamp to 0-100.

    Both the risk score and the per-entry explanation respect the note cap:
    when several note-language families fire in one note, every family entry
    in the explanation is scaled down proportionally so the shown points
    always add up to the contribution actually applied.
    """
    common_indicators = {
        "malformed_upi_uri": "The UPI URI in this QR code is malformed or missing a payee.",
        "non_pay_action": "The UPI URI is not a standard pay request.",
        "recipient_not_named": "A payment destination is embedded but no recipient name is shown - the payer cannot verify who receives the money.",
    }
    reasons = {
        "payment_destination_detected": "The QR code embeds a UPI payment destination. Verify the recipient before authorizing.",
        "embedded_payment_amount": "The QR code embeds a pre-filled payment amount. Verify the amount and recipient before approving.",
        "payment_amount_threshold_1": "The embedded amount equals or exceeds the 10,000 threshold.",
        "payment_amount_threshold_2": "The embedded amount equals or exceeds the 50,000 threshold.",
        "payment_amount_threshold_3": "The embedded amount equals or exceeds the 100,000 threshold.",
        "urgent_payment_request": "The transaction note contains urgent/limited-time wording that pressures the user to act quickly.",
        "refund_reward_prize_language": "The transaction note mentions refunds, prizes or reward language often used in advance-fraud schemes.",
        "kyc_unblock_account_language": "The transaction note mentions KYC/account actions that legitimate merchants never request via a payment QR.",
        "otp_credential_request": "The transaction note asks for OTP/PIN/password - credentials a legitimate merchant never collects through a payment QR.",
    }
    reasons.update(common_indicators)

    names = {c["indicator"] for c in contributions}
    bonuses: list[dict] = []
    for a, b, points, reason in UPI_COMBINATIONS:
        if a in names and b in names:
            bonuses.append({
                "indicator": f"combo_{a}_plus_{b}",
                "severity": "low",
                "score": points,
                "reason": reason,
            })

    family_fired = sum(1 for c in contributions if c["indicator"] in NOTE_FAMILIES)
    if family_fired >= CLUSTER_NEEDED:
        bonuses.append({
            "indicator": "social_engineering_cluster",
            "severity": "medium",
            "score": 10.0,
            "reason": "Multiple social-engineering language families appear together in one transaction note.",
        })

    # Cap the note-language family: scale every family entry proportionally.
    notes = [c for c in contributions if c["indicator"] in NOTE_FAMILIES]
    note_raw = sum(c["score"] for c in notes)
    note_scale = 1.0
    if note_raw > UPI_MAX_NOTE_SCORE:
        note_scale = UPI_MAX_NOTE_SCORE / note_raw
    scaled_note = {
        c["indicator"]: round(c["score"] * note_scale, 2) for c in notes
    }

    raw_total = sum(c["score"] for c in contributions) + sum(
        b["score"] for b in bonuses
    )
    if note_scale < 1.0:
        raw_total -= (note_raw - UPI_MAX_NOTE_SCORE)
    score = max(0.0, min(100.0, raw_total))

    contributions_shown = []
    for c in contributions:
        shown = dict(c)
        if c["indicator"] in scaled_note:
            shown["score"] = scaled_note[c["indicator"]]
        contributions_shown.append(shown)

    return {
        "risk_score": int(round(score)),
        "risk_level": _risk_level(score),
        "is_suspicious": score >= 50.0,
        "confidence": min(92, 45 + int(score * 0.45)),
        "explanation": [
            {
                "indicator": c["indicator"],
                "severity": c["severity"],
                "score": c["score"],
                "reason": reasons.get(
                    c["indicator"], "A UPI risk pattern was detected."
                ),
                "evidence": c["evidence"],
            }
            for c in contributions_shown
        ]
        + list(bonuses),
        "indicators": [c["indicator"] for c in contributions]
        + [b["indicator"] for b in bonuses],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_upi(uri: str) -> dict:
    """Analyze a UPI payment URI and return a transparent risk assessment.

    Returned keys: raw, parse, risk_score, risk_level, is_suspicious,
    confidence, indicators, explanation, recommendations, warning.
    Deterministic: same input -> same output.
    """
    fields = parse_upi_uri(uri)
    note_families = _note_matches(fields["transaction_note"] or "")
    contributions: list[dict] = []
    _detect(contributions, fields, note_families)
    scored = _score(contributions)

    parse_view = {k: fields[k] for k in (
        "raw", "scheme", "action", "is_pay", "payee_address", "payee_name",
        "amount", "currency", "transaction_note", "merchant_code",
        "transaction_ref", "valid_upi", "malformed",
    )}

    recommendations = [
        "ScamShield does not execute payments. Verify the recipient and amount "
        "inside your own payment app before approving anything.",
    ]
    if fields["payee_name"]:
        recommendations.append(
            f"Confirm the recipient name shown in your payment app "
            f"({fields['payee_name']})."
        )
    if fields["amount"] is not None:
        recommendations.append(
            f"Confirm the exact amount of {fields['amount']} in your payment "
            f"app before authorizing."
        )
    if scored["is_suspicious"]:
        recommendations.extend([
            "Do not approve any unexpected collect or payment request.",
            "Never share your UPI PIN, OTP or bank password, even if the QR "
            "note sounds urgent.",
            "Ignore refund/prize/KYC demands that arrive via QR codes and "
            "report them to your bank.",
        ])

    return {
        "raw": uri or "",
        "parse": parse_view,
        "risk_score": scored["risk_score"],
        "risk_level": scored["risk_level"],
        "is_suspicious": scored["is_suspicious"],
        "confidence": scored["confidence"],
        "indicators": scored["indicators"],
        "explanation": scored["explanation"],
        "recommendations": recommendations,
        "warning": "Decoding UPI details never executes a payment.",
    }