"""Transparent, deterministic chain scoring for scam-chain analysis.

The chain score is NOT a simple average of the stage risk scores. It combines:

1. **Strongest-stage floor** — the final chain score is never lower than the
   most suspicious individual stage, so a chain can never "dilute" a critical
   artifact by mixing it with safe ones.

2. **Multi-stage progression bonus** — each additional *suspicious* stage adds a
   diminishing marginal bonus (2nd stage +N, 3rd +N/2, 4th +N/4 ...), capping the
   contribution of many repeat stages so one repeated indicator type can't inflate
   the chain score.

3. **Relationship bonus (capped)** — the total contribution of all validated
   relationships is capped (``RELATION_BONUS_CAP``), and each relationship only
   contributes proportional to its local strength, so a single repeated link
   cannot push the score past the cap.

4. **Category-consistency bonus (capped)** — when multiple flagged stages belong
   to the same scam family, a small consistency bonus applies (also capped).

5. **Sensitive-information / payment progression** — when the chain exhibits a
   progression from informational language to request-for-sensitive-data or a
   payment destination, a bounded bonus applies.

6. **Pattern recognition** — when a recognized chain pattern (KYC/payment/
   prize-refund/customer-care/job/investment/loan) is detected, a bounded bonus
   applies.

The final formula:

    floor      = max(stage.risk_score)
    stage_bonus = sum over suspicious stages i>=1 of STAGE_INCREMENT / (2 ** (i-1))
    rel_bonus   = min(RELATION_BONUS_CAP, sum(rel.strength ** 2 * RELATION_WEIGHT for rel in rels))
    category    = min(CATEGORY_BONUS_CAP, len(consistent_families) * CATEGORY_BONUS)   if >=2 flagged stages
    progress    = PROGRESS_BONUS if sensitive/payment progression else 0
    pattern     = PATTERN_BONUS if recognized pattern else 0
    raw         = floor + stage_bonus + rel_bonus + category + progress + pattern
    chain_score = min(100, raw)

All bonuses are CAPPED and deliberately conservative so the score is dominated by
genuinely strong artifacts and validated links rather than by stacking weak,
repeated indicators.

The score is heuristic (``confidence_type: heuristic``) — it is NOT a calibrated
statistical probability of scam.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from .models import Stage
from .correlate import ChainRelationship, categories_consistent, category_family

# ---- tuning constants (documented in README, all intentionally small/capped) ----
STAGE_INCREMENT = 7          # marginal score bonus per suspicious stage
RELATION_WEIGHT = 26.0       # weight on validated relationship strength
RELATION_BONUS_CAP = 40.0    # hard cap on total relationship bonus
CATEGORY_BONUS = 4.0         # bonus per consistent category family
CATEGORY_BONUS_CAP = 8.0     # hard cap on category-consistency bonus
PROGRESS_BONUS = 8.0         # bonus when sensitive-info/payment progression detected
PATTERN_BONUS = 6.0          # bonus when a recognized chain pattern is detected

_MAX_SCORE = 100


def score_chain(stages: Sequence[Stage], rels: Sequence[ChainRelationship],
                matched_pattern: Optional[str] = None) -> Tuple[int, Dict[str, float]]:
    """Compute the deterministic chain score.

    Returns a tuple ``(score, breakdown)`` where ``breakdown`` is a dict of the
    numeric components (for explanation and testing).
    """
    if not stages:
        return 0, {
            "floor": 0, "stage_bonus": 0.0, "rel_bonus": 0.0,
            "category": 0.0, "progress": 0.0, "pattern": 0.0, "total": 0.0,
        }

    floor = max((s.risk_score for s in stages), default=0)

    # 2. Multi-stage progression bonus (diminishing, capped).
    suspicious = [s for s in stages if s.is_suspicious]
    stage_bonus = sum(STAGE_INCREMENT / (2 ** (i - 1)) for i in range(1, len(suspicious)))

    # 3. Relationship bonus (squared strength -> valid strong links count most,
    #    capped hard).
    rel_bonus = min(
        RELATION_BONUS_CAP,
        sum(min(r.strength, 1.0) ** 2 * RELATION_WEIGHT for r in rels),
    )

    # 4. Category-consistency bonus (only when flagged, capped). The bonus counts
    #    flagged stages that share the SAME scam family (e.g. several "credential"
    #    stages) - not the number of distinct families. Two consistent families both
    #    contribute, but the total is capped.
    family_counts: Dict[str, int] = {}
    for s in stages:
        fam = category_family(s.scam_type) if s.is_suspicious else None
        if fam:
            family_counts[fam] = family_counts.get(fam, 0) + 1
    category = 0.0
    if family_counts:
        n_consistent = max(family_counts.values())
        if n_consistent >= 2:
            category = min(CATEGORY_BONUS_CAP, n_consistent * CATEGORY_BONUS)

    # 5. Sensitive-information / payment progression.
    #
    # The chain progression is considered present when an earlier informational
    # stage leads into a payment destination OR a later stage requests sensitive
    # data. Both are computed from normalized stage signals only.
    progress = 0.0
    if _has_progression(stages):
        progress = PROGRESS_BONUS

    # 6. Pattern recognition bonus.
    pattern = PATTERN_BONUS if matched_pattern else 0.0

    total = min(
        _MAX_SCORE,
        floor + stage_bonus + rel_bonus + category + progress + pattern,
    )

    breakdown = {
        "floor": float(floor),
        "stage_bonus": round(stage_bonus, 3),
        "rel_bonus": round(rel_bonus, 3),
        "category": round(category, 3),
        "progress": round(progress, 3),
        "pattern": round(pattern, 3),
        "total": round(total, 3),
    }
    return int(round(total)), breakdown


def _has_progression(stages: Sequence[Stage]) -> bool:
    """Detect a sensitive-info/payment progression across ordered stages.

    Returns True when there is at least one *informational* source (message) that
    leads into a later stage that either carries a payment destination
    (``upi`` type / payment signal) or a credential-sensitive signal.
    """
    if len(stages) < 2:
        return False
    for i, src in enumerate(stages[:-1]):
        if src.type not in ("message", "qr"):
            continue
        # Informational source: a message that is not itself the destination.
        for dst in stages[i + 1:]:
            if dst.is_payment_stage or dst.has_payment_signal or dst.has_credential_signal:
                return True
    return False


def risk_level(score: int) -> str:
    """Map a chain score to the EXISTING normalized risk levels (no new scale)."""
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"