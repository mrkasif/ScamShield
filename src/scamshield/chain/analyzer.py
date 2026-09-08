"""Orchestration entrypoint for scam-chain analysis.

``analyze_chain`` is the single public entrypoint. It:

1. normalizes each supplied artifact into a :class:`Stage` (deterministic,
   never re-runs message/URL/QR/UPI detection);
2. correlates the stages into explained relationships;
3. recognizes a chain pattern (if the evidence supports one);
4. scores the chain 0..100 with the transparent formula;
5. classifies the chain (none / potential_chain / multi_stage_scam);
6. builds the explanation, recommendations, and the JSON output dict.

The function is fully offline and never resolves/opens/executes anything.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from .models import Stage, StageBuildError, normalize_stage, SUPPORTED_TYPES
from .correlate import build_relationships, ChainRelationship
from .scoring import score_chain, risk_level
from .explain import (
    build_stage_explanations,
    build_relationship_explanations,
    build_score_explanation,
    build_recommendations,
    build_summary,
    detect_pattern,
    pattern_reason,
)

_MULTI_STAGE_MIN = 2      # a chain needs at least 2 stages to be "multi-stage"
_PATTERN_SCORE_FLOOR = 50  # below this the "pattern" signal is not enough to call CRITICAL


def analyze_chain(
    stages_material: Sequence[Any],
    *,
    warnings: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Analyze an ordered collection of already-analyzed artifacts as a possible
    multi-stage scam chain.

    ``stages_material`` accepts a list where each element is:

    * a raw engine result dict (message/url/qr/upi),
    * a unified analyzer result (with ``engine_results``),
    * a structured stage dict (``{"type": ..., "risk_score": ...}``),
    * a :class:`Stage` instance.

    The function always returns a JSON-serializable dict (never raises for
    malformed input — malformed items are reported as warnings).
    """
    out_warnings: List[str] = list(warnings or [])

    raw_items: List[Any] = list(stages_material)
    if not raw_items:
        return _empty_result(out_warnings)

    stages: List[Stage] = []
    for idx, material in enumerate(raw_items):
        try:
            stages.append(normalize_stage(material, idx=idx))
        except StageBuildError as exc:
            out_warnings.append(str(exc))
        except Exception as exc:  # defensive: never crash on a bad stage
            out_warnings.append(f"stage {idx}: could not normalize ({exc})")

    return _build_chain_result(stages, out_warnings)


def _empty_result(warnings: List[str]) -> Dict[str, Any]:
    """Structured result for an empty chain."""
    return {
        "success": True,
        "classification": "none",
        "chain_pattern": None,
        "risk_score": 0,
        "risk_level": "LOW",
        "is_suspicious": False,
        "confidence": 0,
        "confidence_type": "heuristic",
        "summary": "Empty chain: no artifacts supplied for analysis.",
        "stages": [],
        "relationships": [],
        "indicators": [],
        "explanation": ["No artifacts were supplied, so there is nothing to correlate."],
        "recommendations": ["Supply at least one analyzed artifact to run chain analysis."],
        "evidence": {"stage_count": 0, "flagged_stage_count": 0, "score_breakdown": {}},
        "warnings": list(warnings),
    }


def _build_chain_result(stages: List[Stage], warnings: List[str]) -> Dict[str, Any]:
    """Build the full normalized result dict for a non-empty chain."""
    if not stages:
        return _empty_result(warnings)

    rels: List[ChainRelationship] = build_relationships(stages)
    pattern = detect_pattern(stages)
    score, breakdown = score_chain(stages, rels, matched_pattern=pattern)
    level = risk_level(score)

    # Classification (normalized): none | potential_chain | multi_stage_scam
    classification = _classify(stages, rels, score, pattern)

    flagged = [s for s in stages if s.is_suspicious]
    is_suspicious = classification != "none"

    # Aggregate indicators (dedup, order-preserving) for the result.
    indicators: List[str] = []
    seen = set()
    for s in stages:
        for ind in s.indicators:
            k = ind.lower()
            if k not in seen:
                seen.add(k)
                indicators.append(ind)

    # Stage + relationship + score explanations.
    stage_expl = build_stage_explanations(stages)
    rel_expl = build_relationship_explanations(rels)
    score_expl = build_score_explanation(breakdown)

    explanation: List[str] = []
    for se in stage_expl:
        explanation.append(f"Stage {se['id']} ({se['label']}): {se['explanation']}")
    for re_ in rel_expl:
        explanation.append(
            f"Relationship stage {re_['from_stage']} -> stage {re_['to_stage']}: "
            f"{re_['explanation']}"
        )
        for ev in re_.get("evidence", []):
            explanation.append(f"  evidence: {ev}")
    reason = pattern_reason(pattern, stages)
    if pattern:
        explanation.append(f"Chain pattern detected: {pattern}.")
        if reason:
            explanation.append(f"  {reason}")
    explanation.extend(score_expl)

    recommendations = build_recommendations(stages, classification, pattern, is_suspicious)

    summary = build_summary(classification, pattern, score, level, len(stages), is_suspicious)

    # Evidence object (never includes raw credentials/OTPs/passwords).
    evidence = {
        "stage_count": len(stages),
        "flagged_stage_count": len(flagged),
        "score_breakdown": {k: round(float(v), 3) for k, v in breakdown.items()},
    }

    return {
        "success": True,
        "classification": classification,
        "chain_pattern": pattern,
        "risk_score": score,
        "risk_level": level,
        "is_suspicious": is_suspicious,
        "confidence": score,  # heuristic confidence; NOT a statistical probability
        "confidence_type": "heuristic",
        "summary": summary,
        "stages": [s.to_dict() for s in stages],
        "relationships": [r.to_dict() for r in rels],
        "indicators": indicators,
        "explanation": explanation,
        "recommendations": recommendations,
        "evidence": evidence,
        "warnings": list(warnings),
    }


def _classify(stages: List[Stage], rels: List[ChainRelationship], score: int,
              pattern: Optional[str]) -> str:
    """Normalize the classification: none | potential_chain | multi_stage_scam."""
    if not stages:
        return "none"
    if len(stages) < _MULTI_STAGE_MIN:
        # Single stage carrying suspicious signals is NOT a multi-stage chain.
        return "none"
    flagged = [s for s in stages if s.is_suspicious]
    if not flagged:
        return "none"
    # Strong enough evidence (score + validated relationships + recognized pattern)
    # to call it a multi-stage scam. Otherwise a potential chain.
    strong = (
        score >= 65
        and len(rels) >= 1
        and (len(flagged) >= 2)
    )
    if strong or (pattern and score >= _PATTERN_SCORE_FLOOR):
        return "multi_stage_scam"
    if rels:
        return "potential_chain"
    return "none"


# Convenience alias kept for readability at call sites.
def analyze_chain_result(*args, **kwargs) -> Dict[str, Any]:
    return analyze_chain(*args, **kwargs)