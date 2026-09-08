"""Explainability for scam-chain analysis.

This module turns the normalized stages, validated relationships, and score
breakdown into human-readable explanations:

1. What each stage represents
2. Why stages are connected (relationship evidence)
3. Which pattern was recognized (if any)
4. Why the final score was assigned (breakdown)
5. Recommendations for the user

The prose is deterministic and always grounded in the actual stage/relationship
data — the module never invents evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from .models import Stage
from .correlate import ChainRelationship

# ---- recognized chain patterns ----------------------------------------------
# Each pattern is a *decision function* over normalized stages. A pattern is
# recognized only when the evidence points to it; the same input maps to at most
# ONE primary pattern (priority order below). Patterns are NOT hardcoded claims
# that every matching sequence is malicious.
#
# The detectors are concrete heuristics (source language family + destination
# type), which keeps detection explainable and deterministic. They are defined
# first so the (_PATTERNS) registry below can reference them.


def _kyc_phishing(stages: Sequence[Stage]) -> Tuple[bool, Optional[str]]:
    if len(stages) < 2:
        return False, None
    first = stages[0]
    rest = stages[1:]
    if first.type not in ("message", "qr"):
        return False, None
    if first.type == "message" and not first.has_credential_signal:
        return False, None
    if first.type == "qr" and (first.content_type != "url" and not first.has_credential_signal):
        return False, None
    # The destination must actually carry a credential/verification signal (a
    # verify/login/kyc URL, or a stage requesting sensitive data). Merely being a
    # URL/UPI is NOT enough - otherwise payment chains would be mislabeled KYC.
    cred_dest = any(s.has_credential_signal for s in rest)
    if not cred_dest:
        return False, None
    return True, "KYC/account warning leads into a suspicious verification URL / credential request"


def _payment_scam(stages: Sequence[Stage]) -> Tuple[bool, Optional[str]]:
    if len(stages) < 2:
        return False, None
    first = stages[0]
    rest = stages[1:]
    if first.type not in ("message", "qr"):
        return False, None
    if first.type == "message":
        if not (first.has_payment_signal or first.has_language_signal):
            return False, None
        # A generic payment/urgency message is payment_scam only when it does NOT
        # strongly match a more specific opportunity pattern (prize/refund, job,
        # investment, loan, customer-care) - those each have their own pattern and
        # would otherwise be mislabeled as a generic payment scam.
        if first.prize_refund_signal() or first.job_signal() or first.investment_signal() or first.loan_signal() or first.support_signal():
            return False, None
    pay_dest = any(s.is_payment_stage or s.has_payment_signal for s in rest)
    if not pay_dest:
        return False, None
    return True, "urgent/payment message leads into a UPI/payment destination"


def _prize_refund(stages: Sequence[Stage]) -> Tuple[bool, Optional[str]]:
    if len(stages) < 2:
        return False, None
    first = stages[0]
    rest = stages[1:]
    if first.type not in ("message", "qr"):
        return False, None
    if not first.prize_refund_signal():
        return False, None
    pay_dest = any(s.is_payment_stage or s.has_payment_signal for s in rest)
    if not pay_dest:
        return False, None
    return True, "prize/refund message leads into a payment destination"


def _fake_customer_care(stages: Sequence[Stage]) -> Tuple[bool, Optional[str]]:
    if len(stages) < 2:
        return False, None
    first = stages[0]
    rest = stages[1:]
    if not first.support_signal():
        return False, None
    dest = any(s.is_payment_stage or s.has_payment_signal or s.type in ("url", "qr") for s in rest)
    if not dest:
        return False, None
    return True, "bank/customer-care impersonation leads into a URL or payment request"


def _job_scam(stages: Sequence[Stage]) -> Tuple[bool, Optional[str]]:
    if len(stages) < 2:
        return False, None
    first = stages[0]
    rest = stages[1:]
    if not first.job_signal():
        return False, None
    dest = any(s.is_payment_stage or s.has_payment_signal or s.type in ("url", "qr") for s in rest)
    if not dest:
        return False, None
    return True, "job opportunity message leads into a URL or payment request"


def _investment_scam(stages: Sequence[Stage]) -> Tuple[bool, Optional[str]]:
    if len(stages) < 2:
        return False, None
    first = stages[0]
    rest = stages[1:]
    if not first.investment_signal():
        return False, None
    dest = any(s.is_payment_stage or s.has_payment_signal or s.type in ("url", "qr") for s in rest)
    if not dest:
        return False, None
    return True, "investment opportunity message leads into a URL or payment request"


def _loan_scam(stages: Sequence[Stage]) -> Tuple[bool, Optional[str]]:
    if len(stages) < 2:
        return False, None
    first = stages[0]
    rest = stages[1:]
    if not first.loan_signal():
        return False, None
    dest = any(s.is_payment_stage or s.has_payment_signal or s.type in ("url", "qr") for s in rest)
    if not dest:
        return False, None
    return True, "loan offer message leads into a URL or payment request"


_PATTERNS = (
    ("kyc_phishing", _kyc_phishing),
    ("payment_scam", _payment_scam),
    ("prize_refund", _prize_refund),
    ("fake_customer_care", _fake_customer_care),
    ("job_scam", _job_scam),
    ("investment_scam", _investment_scam),
    ("loan_scam", _loan_scam),
)

_PATTERN_LABELS = {
    "kyc_phishing": "KYC phishing",
    "payment_scam": "Payment scam",
    "prize_refund": "Prize/refund scam",
    "fake_customer_care": "Fake customer care",
    "job_scam": "Job scam",
    "investment_scam": "Investment scam",
    "loan_scam": "Loan scam",
}


def detect_pattern(stages: Sequence[Stage]) -> Optional[str]:
    """Highest-priority recognized chain pattern, or None.

    Pattern detection is optimistic but evidence-grounded: a pattern is only
    returned when the source language and destination type line up. Priority
    order means one input maps to at most one primary pattern.
    """
    if len(stages) < 2:
        return None
    for name, detector in _PATTERNS:
        hit, _reason = detector(stages)
        if hit:
            return name
    return None


def pattern_reason(pattern: Optional[str], stages: Sequence[Stage]) -> Optional[str]:
    """Return the human-readable reason string for a detected pattern."""
    if not pattern:
        return None
    for name, detector in _PATTERNS:
        if name == pattern:
            _hit, reason = detector(stages)
            return reason
    return None


# ---- explanation building ----------------------------------------------------
def build_stage_explanations(stages: Sequence[Stage]) -> List[Dict[str, Any]]:
    """Explain what each stage represents, with its normalized signals."""
    out: List[Dict[str, Any]] = []
    for s in stages:
        reasons: List[str] = []
        if s.is_suspicious:
            reasons.append(f"flagged suspicious ({s.risk_level}, risk {s.risk_score}/100)")
            if s.scam_type:
                reasons.append(f"scam category: {s.scam_type}")
        else:
            reasons.append(f"not flagged suspicious (risk {s.risk_score}/100)")
        if s.type == "message":
            if s.has_credential_signal:
                reasons.append("contains KYC/credential/verification language")
            if s.has_payment_signal:
                reasons.append("contains payment/refund/prize language")
            if s.has_language_signal:
                reasons.append("contains urgency/account-warning language")
        elif s.type == "url":
            reasons.append("is a URL artifact")
            if s.urls:
                reasons.append(f"references {', '.join(s.urls[:2])}")
        elif s.type == "qr":
            reasons.append(f"is a QR artifact (decoded: {s.content_type or 'unknown'})")
            if s.urls:
                reasons.append(f"references {', '.join(s.urls[:2])}")
        elif s.type == "upi":
            reasons.append("is a UPI payment destination")
            if s.payee_address:
                reasons.append(f"payee: {s.payee_address}")
            if s.amount is not None:
                reasons.append(f"amount: {s.amount} {s.currency or 'INR'}")
        out.append({
            "id": s.idx + 1,
            "type": s.type,
            "label": s.label,
            "is_suspicious": s.is_suspicious,
            "risk_score": s.risk_score,
            "risk_level": s.risk_level,
            "explanation": "; ".join(reasons) or "No notable signals.",
        })
    return out


def build_relationship_explanations(rels: Sequence[ChainRelationship]) -> List[Dict[str, Any]]:
    """Explain each validated relationship with its concrete evidence."""
    out: List[Dict[str, Any]] = []
    for r in rels:
        out.append({
            "from_stage": r.from_stage,
            "to_stage": r.to_stage,
            "relation": r.relation,
            "explanation": r.label,
            "match_type": r.match_type,
            "evidence": list(r.evidence),
        })
    return out


def build_score_explanation(breakdown: Dict[str, float]) -> List[str]:
    """Explain, in plain language, why the final chain score was assigned."""
    lines: List[str] = []
    total = breakdown.get("total", 0)
    floor = breakdown.get("floor", 0)
    lines.append(
        f"Chain score {int(round(total))}/100 starts from the strongest individual stage "
        f"({int(round(floor))}/100) and is never lower than it."
    )
    if breakdown.get("stage_bonus", 0) > 0:
        n_susp = int(round(breakdown["stage_bonus"] / 7.0))
        lines.append(
            f"Multi-stage progression: +{breakdown['stage_bonus']:.1f} for ~{max(n_susp, 1)} "
            "combined suspicious stages."
        )
    if breakdown.get("rel_bonus", 0) > 0:
        lines.append(
            f"Validated relationships: +{breakdown['rel_bonus']:.1f} from correlated links "
            "(capped at the documented relationship cap)."
        )
    if breakdown.get("category", 0) > 0:
        lines.append(
            f"Consistent scam categories across stages: +{breakdown['category']:.1f}."
        )
    if breakdown.get("progress", 0) > 0:
        lines.append("Sensitive-information/payment progression detected: +{:.1f}.".format(breakdown["progress"]))
    if breakdown.get("pattern", 0) > 0:
        lines.append("Recognized chain pattern: +{:.1f}.".format(breakdown["pattern"]))
    if not lines:
        lines.append("No suspicious stages or validated relationships; the chain baseline is 0.")
    return lines


def build_recommendations(stages: Sequence[Stage], classification: str,
                          pattern: Optional[str], is_suspicious: bool) -> List[str]:
    """Deterministic, actionable recommendations based on the chain state."""
    recs: List[str] = []
    if not is_suspicious:
        recs.append("No suspicious multi-stage chain detected. The supplied artifacts do not "
                    "form a correlated scam sequence.")
        return recs
    recs.append("Do NOT open any supplied links, scan unknown QR codes, or share OTP/password/KYC "
                "details with the sender.")
    if any(s.is_payment_stage or s.has_payment_signal for s in stages):
        recs.append("Do not pay, send money, or transfer funds to the UPI/merchant address in the "
                    "analysis, regardless of any promised refund or prize.")
    if any(s.has_credential_signal for s in stages):
        recs.append("Do not enter Aadhaar/PAN/bank credentials or OTPs on any link or QR in the "
                    "analysis. Banks never ask for OTPs via links.")
    if pattern:
        recs.append(f"This matches the known scam pattern '{pattern}'. Verify independently with "
                    "the official app/website before acting.")
    recs.append("If you already shared sensitive data or made a payment, contact your bank / "
                "report to the cyber-cell promptly.")
    return recs


def build_summary(classification: str, pattern: Optional[str], score: int,
                  risk_level: str, n_stages: int, is_suspicious: bool) -> str:
    """Deterministic human-readable summary line."""
    if not is_suspicious:
        return (
            f"Analyzed {n_stages} artifact(s): no correlated scam chain detected "
            f"(score {score}/100, {risk_level})."
        )
    pat = f" matching the {pattern} pattern" if pattern else ""
    return (
        f"Analyzed {n_stages} artifact(s): correlated into a possible multi-stage scam chain "
        f"(score {score}/100, {risk_level}){pat}."
    )