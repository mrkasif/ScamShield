"""ScamShield message intelligence engine (explainable rule-based layer).

This is the initial, locally-working detection layer. It uses deterministic
security/NLP heuristics (keyword + phrase + link extraction) across English,
Hindi, Marathi and Hinglish. It does NOT require internet, an ML model, or any
paid service.

This stage is described as an "Explainable rule-based message intelligence
engine". A trained ML model can be integrated later and compared against this
baseline for the research component.

Primary entry point:
    from scamshield.nlp import analyze_message
    result = analyze_message("Your KYC has expired. Verify immediately at this link.")
"""

from .engine import analyze_message
from . import detectors
from . import scoring
from . import category
from . import explain
from . import patterns

__all__ = [
    "analyze_message",
    "detectors",
    "scoring",
    "category",
    "explain",
    "patterns",
]
