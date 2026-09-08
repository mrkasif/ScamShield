"""Multi-Stage Scam / Attack Chain analysis for ScamShield.

This is a research/prototype correlation layer. It does NOT run any independent
message/URL/QR/UPI detection — it analyzes artifacts that have already been
produced by the individual engines (or the unified analyzer) and correlates them
into a possible multi-stage scam chain.
"""

from .models import Stage, StageBuildError, normalize_stage, SUPPORTED_TYPES
from .correlate import correlate_chain, build_relationships, ChainRelationship
from .scoring import score_chain
from .explain import build_stage_explanations, build_recommendations, build_summary
from .analyzer import analyze_chain

__all__ = [
    "Stage",
    "StageBuildError",
    "normalize_stage",
    "SUPPORTED_TYPES",
    "correlate_chain",
    "build_relationships",
    "ChainRelationship",
    "score_chain",
    "build_stage_explanations",
    "build_recommendations",
    "build_summary",
    "analyze_chain",
]
