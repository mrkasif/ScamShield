"""ScamShield Research & Evaluation Lab.

A reproducible, completely local evaluation framework that measures how well
the existing ScamShield system performs against the labelled dataset. No network,
no external APIs, no model changes — evaluation only.

Run:   python -m app.research_eval [--json] [--output-dir models/research]
"""
from __future__ import annotations

from .runner import run_full_evaluation, write_artifacts

__all__ = ["run_full_evaluation", "write_artifacts"]
