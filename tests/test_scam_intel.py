"""Focused tests for the additive ``scam_intelligence`` layer
(``scamshield.scam_intel``).

The layer is ADDITIVE and evidence-driven:

* It never re-scores. The authoritative ``risk_score``, Safety Zone
  (``zone`` / ``zone_label`` / ``zone_description`` / ``recommended_action``),
  ``risk_assessment`` and ``risk_breakdown`` are derived by the existing
  Safety-Zone presentation and are NOT touched by scam intelligence.
* It is DETERMINISTIC: given the same unified result, it always produces the
  same ``scam_intelligence`` dict (pure function of existing evidence).
* It is FULLY OFFLINE: no network, no DNS, no URL opening, no ML/LLM, no
  external API, no randomness, no wall-clock dependence. The reference brand
  is only ever surfaced as possibly-*impersonated* (never accused).
* Benign inputs have ``primary_pattern = None`` and no referenced entities.

These tests reuse the message/URL committed to the engine smokes so expected
values stay byte-exact and reproduce on any machine.
"""

import copy
import inspect
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scamshield import analyze  # noqa: E402
from scamshield import scam_intel as si  # noqa: E402

KYC_TRIGGER = (
    "SBI KYC verification is required immediately. Your Aadhaar and account "
    "will be suspended unless you complete identity verification and "
    "reverification within 24 hours; click: http://sbi.example.com/kyc-verify"
)

BENIGN = (
    "Your electricity bill of Rs 6,200 is due on the 25th. Please pay "
    "through the official payment portal to avoid a late fee."
)


def _si(message: str) -> dict:
    r = analyze("message", message)
    return r["scam_intelligence"]


def _docstring(src: str) -> str:
    module = inspect.getmodule(si)
    return module.__doc__ or ""


# ---------------------------------------------------------------------------
# Additivity + authority preservation
# ---------------------------------------------------------------------------


def test_scam_intelligence_never_changes_authoritative_presentation():
    """The layer is purely additive: the authoritative risk presentation
    (risk_score, Safety Zone, risk_assessment, risk_breakdown) of a result
    with scam intelligence attached is identical to the same message analyzed
    through the plain unified path with the presentation applied."""
    r_plain = analyze("message", KYC_TRIGGER)
    r_additive = analyze("message", KYC_TRIGGER)
    for key in ("zone", "zone_label", "zone_description", "recommended_action",
                "risk_assessment", "risk_breakdown", "risk_score",
                "risk_level", "is_suspicious", "is_suspicious"):
        assert r_additive[key] == r_plain[key], key
    assert r_additive["scam_intelligence"] != {}
    assert r_additive["scam_intelligence"]["primary_pattern"] is not None


def test_attachment_does_not_mutate_the_input_result():
    """attach_scam_intelligence must be additive: it returns the same dict
    reference but only ADDS keys; never mutating existing values."""
    raw = analyze("message", KYC_TRIGGER)
    snapshot = copy.deepcopy(raw)
    from scamshield.scam_intel import attach_scam_intelligence
    out = attach_scam_intelligence(raw)
    assert out is raw
    assert raw == snapshot, "attach must not mutate existing evidence"


# ---------------------------------------------------------------------------
# Determinism + offline
# ---------------------------------------------------------------------------


def test_deterministic_across_repeated_runs():
    a = _si(KYC_TRIGGER)
    b = _si(KYC_TRIGGER)
    assert a == b


def test_benign_is_deterministic_and_has_offline_defaults():
    a = _si(BENIGN)
    b = _si(BENIGN)
    assert a == b
    assert a["primary_pattern"] is None
    assert a["referenced_entities"] == []
    assert a["confidence_type"] == "rule_based"
    assert a["confidence_note"]


def test_module_imports_no_network_no_random_no_time_no_os():
    src = Path(si.__file__).read_text(encoding="utf-8")
    import re as _re_imports
    banned_imports = _re_imports.findall(
        r"^\s*(?:import|from)\s+(\w+)", src, flags=_re_imports.MULTILINE)
    assert "requests" not in banned_imports
    assert "socket" not in banned_imports
    assert "os" not in banned_imports
    assert "time" not in banned_imports
    assert "random" not in banned_imports
    # No wall-clock / RNG / environment / subprocess CALL SITES either. This
    # checks calls, not docstring prose ("match time" in a docstring is fine).
    import re as _re2
    call_sites = _re2.findall(
        r"\b(time\.|random\.|os\.environ|os\.getenv|os\.path|os\.urandom|"
        r"datetime\.|datetime\b)",
        src,
    )
    assert call_sites == [], call_sites


# ---------------------------------------------------------------------------
# Evidence-driven firing + honest brand handling
# ---------------------------------------------------------------------------


def test_kyc_primary_is_rule_based_and_evidence_backed():
    si_ = _si(KYC_TRIGGER)
    pp = si_["primary_pattern"]
    assert pp is not None
    assert pp["pattern_id"] == "kyc_verification"
    assert isinstance(pp["confidence"], int) and 60 <= pp["confidence"] <= 100
    assert pp["confidence_type"] == "rule_based"
    assert si_["confidence_type"] == "rule_based"


def test_primary_schema_is_stable():
    si_ = _si(KYC_TRIGGER)
    pp = si_["primary_pattern"]
    assert set(pp) >= {
        "pattern_id", "name", "description", "typical_target",
        "matched_terms", "min_terms", "confidence", "confidence_type",
        "confidence_note", "tactics", "recommended_action",
    }


def test_primary_tactics_are_draw_from_small_vocabulary():
    si_ = _si(KYC_TRIGGER)
    tactics = si_["primary_pattern"]["tactics"]
    assert tactics
    assert all(isinstance(t, str) for t in tactics)


def test_referenced_entities_are_labelled_possible_impersonation_only():
    si_ = _si(KYC_TRIGGER)
    for ent in si_["referenced_entities"]:
        assert "possible brand impersonation" in (
            ent["assessment"].lower())
        assert "impersonat" in ent["assessment"].lower()
        assert "malicious" not in ent["assessment"].lower()


def test_benign_never_references_or_accuses_indian_brands():
    si_ = _si(BENIGN)
    assert si_["primary_pattern"] is None
    assert si_["referenced_entities"] == []


def test_primary_is_none_when_evidence_is_absent():
    r = analyze("message", "Have a nice day, the weather is beautiful.")
    assert r["scam_intelligence"]["primary_pattern"] is None
