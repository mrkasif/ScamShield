"""Deterministic correlation between chain stages.

The chain analyzer correlates ALREADY-ANALYZED artifacts. Each :class:`Stage`
carries a normalized projection of an engine result (risk, indicators, urls,
domains, upi metadata). This module computes *why* two stages are connected:

* both point at the same destination (matched URL string / registrable domain,
  matched UPI payee address);
* the source stage's language/indicators lead naturally into the destination
  stage's purpose (message -> url, message -> upi, url -> upi, qr -> url,
  qr -> upi);
* their risk categories are consistent (both flagged as the same kind of scam).

The module is deliberately NOT a detection engine: it never opens URLs, resolves
DNS, follows redirects, or re-runs message/URL/QR/UPI analysis. All matching is
deterministic and local - it is evidence *correlation*, not proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import Stage, parse_url_safely

# ---- category compatibility -------------------------------------------------
# Scam types, grouped into broad families for "is consistent" checks. The chain
# uses these to decide whether two flagged stages are the same *kind* of scam
# (which strengthens a connection) or unrelated (which weakens it). This is a
# coarse mapping; the exact original scam_type string is preserved as evidence.
_CATEGORY_MAP = {
    "fake_kyc": "credential",
    "kyc": "credential",
    "credential_phishing": "credential",
    "phishing": "credential",
    "account_security": "credential",
    "account_freeze": "credential",
    "otp": "credential",
    "payment_fraud": "payment",
    "prize": "payment",
    "prize_scam": "payment",
    "refund": "payment",
    "refund_scam": "payment",
    "reward": "payment",
    "loan": "payment",
    "loan_scam": "payment",
    "investment": "payment",
    "investment_scam": "payment",
    "job": "payment",
    "job_scam": "payment",
    "fake_fee": "payment",
    "fee": "payment",
    "cashback": "payment",
    "fake_customer_care": "support",
    "customer_care": "support",
    "tech_support": "support",
    "fake_customer_support": "support",
    "upi_fraud": "payment",
    "upi_payment": "payment",
    "upi": "payment",
    "recharge": "payment",
    "lottery": "payment",
    "gift": "payment",
    "shopping": "payment",
    "product": "payment",
    "none": None,
}


def category_family(scam_type: Optional[str]) -> Optional[str]:
    if not scam_type:
        return None
    key = scam_type.strip().lower()
    return _CATEGORY_MAP.get(key, None)


def categories_consistent(a: Optional[str], b: Optional[str]) -> bool:
    """True if both stage scam types belong to the same broad family.

    Unknown/None families never count as "consistent" (absence of a category is
    not evidence of a relationship).
    """
    fa, fb = category_family(a), category_family(b)
    if not fa or not fb:
        return False
    return fa == fb


# ---- artifact matching ------------------------------------------------------
def normalize_url_for_match(url: str) -> Optional[Dict[str, Any]]:
    """Deterministic URL normalization for *matching*.

    Any string that does not carry an explicit scheme/netloc is dropped so that
    loose text like ``example.com`` is not treated as a real URL (mirroring the
    URL engine's conservative stance). The registrable root is auto-derived.
    """
    return parse_url_safely(url)


def urls_identical(a: str, b: str) -> bool:
    """Exact (case-insensitive) URL match after scheme+host normalization.

    Scheme and host are always lowercased; the path is also compared
    case-insensitively so that ``/Login`` and ``/login`` match (defensive
    normalization — the intent of the destination is what matters for
    correlation, not its case).
    """
    pa, pb = normalize_url_for_match(a), normalize_url_for_match(b)
    if not pa or not pb:
        return False
    return (pa["hostname"] == pb["hostname"]
            and pa["path"].lower() == pb["path"].lower())


def domains_match(a: str, b: str) -> bool:
    """Registrable-root / hostname match after normalization."""
    return _norm_dom(a) == _norm_dom(b)


def _norm_dom(d: str) -> str:
    if not d:
        return ""
    s = d.strip().lower()
    if s.startswith(("http://", "https://", "upi://")):
        p = normalize_url_for_match(s)
        if p:
            return p["hostname"]
    # Bare hostnames are reduced to their registrable root so
    # "login.example.com" matches "verify.example.com" the same way the
    # engine's root-domain logic treats them.
    labels = s.strip(".").split(".")
    if len(labels) >= 3:
        return ".".join(labels[-2:])
    return s.strip(".")


def _extract_all_domains(stage: Stage) -> List[str]:
    """All normalized hostnames the stage references (urls + explicit domains)."""
    out = set()
    for d in stage.domains:
        out.add(_norm_dom(d))
    for u in stage.urls:
        p = normalize_url_for_match(u)
        if p:
            out.add(p["hostname"])
            out.add(p["root_domain"])
    return sorted(out)


def out_domains(stage: Stage) -> List[str]:
    """Public helper: deduplicated hostnames referenced by the stage."""
    return _extract_all_domains(stage)


# ---- relationship description -----------------------------------------------
@dataclass
class ChainRelationship:
    """A single explained connection between two stages.

    * ``from_stage`` / ``to_stage`` - 1-based stage ids.
    * ``relation`` - machine-readable relation name (e.g. ``message_contains_url``).
    * ``label`` - human readable phrase.
    * ``strength`` - 0.0..1.0 contribution weight (used by the scorer).
    * ``match_type`` - ``exact`` | ``domain`` | ``upi`` | ``none``.
    * ``evidence`` - list of concrete indicator strings.
    * ``details`` - extra structured context (urls/payee/categories shared).
    """

    from_stage: int
    to_stage: int
    relation: str
    label: str
    strength: float = 0.0
    match_type: str = "none"
    evidence: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_stage": self.from_stage,
            "to_stage": self.to_stage,
            "relation": self.relation,
            "label": self.label,
            "strength": round(self.strength, 3),
            "match_type": self.match_type,
            "evidence": list(self.evidence),
            "details": self.details,
        }


# ---- artifact matching helpers used by correlate_chain ----------------------
def _find_domain_match(stage_a: Stage, stage_b: Stage) -> Optional[str]:
    """Best-match normalized domain shared by two stages, or None."""
    da = _extract_all_domains(stage_a)
    db = _extract_all_domains(stage_b)
    for x in sorted(da):
        if x in db:
            return x
    # Root-domain overlap: stages that reference different hostnames under the
    # same registrable root (e.g. login.example.com vs verify.example.com) still
    # share a root - a weaker but real signal.
    root_a = set()
    for u in stage_a.urls:
        p = normalize_url_for_match(u)
        if p:
            root_a.add(p["root_domain"])
    root_b = set()
    for u in stage_b.urls:
        p = normalize_url_for_match(u)
        if p:
            root_b.add(p["root_domain"])
    shared = (root_a & root_b) - set(da)
    if shared:
        return next(iter(shared))
    return None


def _upi_payee_match(stage_a: Stage, stage_b: Stage) -> Optional[str]:
    """Shared normalized UPI payee address, or None."""
    pa = stage_a.payee_address or ""
    pb = stage_b.payee_address or ""
    if not pa or not pb:
        return None
    if pa.strip().lower() == pb.strip().lower():
        return pa
    return None


# ---- the correlation entrypoint ---------------------------------------------
def build_relationships(stages: List[Stage]) -> List[ChainRelationship]:
    """Produce an ordered list of explained relationships across all stages.

    Correlations are computed between every ordered pair (i, j) with i < j so the
    full chain topology is available, but the strongest edges (consecutive + exact
    artifact matches) always appear first in the returned list.
    """
    rels: List[ChainRelationship] = []
    n = len(stages)
    for i in range(n):
        for j in range(i + 1, n):
            a, b = stages[i], stages[j]
            edge = _correlate_pair(a, b)
            if edge:
                rels.append(edge)

    # Stable ordering: consecutive edges first (by index), then by strength desc.
    def _sort_key(r: ChainRelationship):
        consecutive = 0 if r.to_stage == r.from_stage + 1 else 1
        return (consecutive, -r.strength, r.from_stage, r.to_stage)

    rels.sort(key=_sort_key)
    return rels


def _correlate_pair(a: Stage, b: Stage) -> Optional[ChainRelationship]:
    """Correlate source stage ``a`` with destination stage ``b`` (a precedes b).

    Returns one relationship (the strongest applicable) or None. The logic is a
    deterministic amalgam of the documented patterns:

    message -> url / message -> (qr with url)
    message -> upi / message -> (qr with upi)
    url  -> upi  / url  -> (qr with upi)   [payment/credential continuation]
    qr   -> url  / qr   -> upi             [qr decoded content continuation]
    plus generic strong-signal connection when both stages are highly suspicious
    and categorically consistent (but never treated as a verified link).
    """
    # --- artifact exact matching ---------------------------------------------
    shared_domain = _find_domain_match(a, b)
    payee = _upi_payee_match(a, b)

    # 1. Message -> URL --------------------------------------------------------
    if a.type == "message" and b.type in ("url", "qr"):
        # Only correlate when there is real evidence: the message actually
        # references a URL (matching or not), OR it is suspicious with compatible
        # signals. A plain safe message with no link must NOT be linked to an
        # unrelated URL.
        msg_urls = _urls_from_message(a)
        target_urls = _urls_from(b)
        if not msg_urls and not (a.is_suspicious or a.has_credential_signal or a.has_payment_signal or a.has_language_signal):
            return None
        return _build(
            a, b,
            relation="message_leads_to_url",
            label="Message leads to a suspicious URL",
            base_strength=0.45,
            shared_domain=shared_domain,
            payee=payee,
            url_from_source=msg_urls,
            url_from_target=target_urls,
        )

    # 2. Message -> UPI --------------------------------------------------------
    if a.type == "message" and b.type in ("upi", "qr"):
        # Gate: only a message that actually asks for money / payment qualifies.
        if not a.has_payment_signal and not a.has_language_signal:
            return None
        relation = "message_leads_to_payment"
        label = "Message asks for money via a UPI destination"
        return _build(
            a, b,
            relation=relation,
            label=label,
            base_strength=0.5,
            shared_domain=shared_domain,
            payee=payee,
            url_from_source=_urls_from_message(a),
            url_from_target=_urls_from(b),
        )

    # 3. URL -> UPI ------------------------------------------------------------
    if a.type == "url" and b.type == "upi":
        return _build(
            a, b,
            relation="url_to_payment_continuation",
            label="Suspicious URL leads into a payment destination",
            base_strength=0.5,
            shared_domain=shared_domain,
            payee=payee,
            url_from_source=_urls_from(a),
            url_from_target=[],
        )

    # 4. QR -> URL / UPI -------------------------------------------------------
    if a.type == "qr" and b.type == "url":
        return _build(
            a, b,
            relation="qr_to_url_continuation",
            label="QR code decodes to the analyzed URL",
            base_strength=0.5,
            shared_domain=shared_domain,
            payee=payee,
            url_from_source=_urls_from(a),
            url_from_target=_urls_from(b),
        )
    if a.type == "qr" and b.type == "upi":
        return _build(
            a, b,
            relation="qr_to_upi_continuation",
            label="QR code decodes to the analyzed UPI destination",
            base_strength=0.5,
            shared_domain=shared_domain,
            payee=payee,
            url_from_source=_urls_from(a),
            url_from_target=[],
        )

    # 5. Generic strong-signal continuation ----------------------------------
    if a.is_suspicious and b.is_suspicious and categories_consistent(a.scam_type, b.scam_type):
        return _build(
            a, b,
            relation="consistent_flagged_sequence",
            label="Both stages are flagged with a consistent scam category",
            base_strength=0.3,
            shared_domain=shared_domain,
            payee=payee,
            url_from_source=_urls_from(a),
            url_from_target=_urls_from(b),
        )

    return None


def _build(a: Stage, b: Stage, *, relation: str, label: str, base_strength: float,
           shared_domain: Optional[str], payee: Optional[str],
           url_from_source: List[str], url_from_target: List[str]) -> ChainRelationship:
    """Assemble a ChainRelationship with evidence + a local strength estimate.

    The strength is computed deterministically from the *local* features:

    * base for the relationship type,
    * exact URL/domain match,
    * shared UPI payee,
    * source language urgency/credential/payment signal,
    * shared scam category (consistency),
    * both stages being suspicious.

    It is capped at 1.0 and high-stakes signals saturate quickly so a single
    repeated indicator does not inflate the whole chain score.
    """
    strength = base_strength
    evidence: List[str] = []
    details: Dict[str, Any] = {
        "source": f"stage {a.idx + 1}",
        "dest": f"stage {b.idx + 1}",
    }
    match_type = "none"

    if shared_domain:
        strength += 0.35
        match_type = "domain"
        evidence.append(f"both reference the same domain/URL: {shared_domain}")
        details["shared_domain"] = shared_domain

    if payee:
        strength += 0.35
        if match_type == "none":
            match_type = "upi"
        evidence.append(f"same UPI payee address referenced: {payee}")
        details["shared_payee"] = payee

    for u in url_from_source:
        if u and u in url_from_target:
            match_type = "exact"
            strength += 0.4
            evidence.append(f"the exact URL appears in both stages: {u}")
            details["exact_url"] = u
            break

    if a.has_credential_signal or a.has_language_signal:
        strength += 0.15
        evidence.append("source stage carries urgency/credential/KYC signal")

    if b.has_payment_signal and relation in ("message_leads_to_payment", "url_to_payment_continuation", "qr_to_upi_continuation"):
        strength += 0.12
        evidence.append("destination stage carries a payment request/destination signal")

    if categories_consistent(a.scam_type, b.scam_type):
        strength += 0.1
        evidence.append(f"both carry the same scam category family ({a.scam_type or b.scam_type})")
        details["consistent_category"] = a.scam_type or b.scam_type

    if a.is_suspicious and b.is_suspicious:
        strength += 0.1

    strength = min(strength, 1.0)
    return ChainRelationship(
        from_stage=a.idx + 1,
        to_stage=b.idx + 1,
        relation=relation,
        label=label,
        strength=round(strength, 3),
        match_type=match_type,
        evidence=evidence,
        details=details,
    )


def _urls_from_message(stage: Stage) -> List[str]:
    """URLs embedded in a message stage (detected_urls / nested url_analysis)."""
    return list(stage.urls)


def _urls_from(stage: Stage) -> List[str]:
    return list(stage.urls)


# Public facade ----------------------------------------------------------------
def correlate_chain(stages: List[Stage]) -> Dict[str, Any]:
    """Compute all relationships for a chain of normalized stages.

    Returns a dict compatible with the chain result schema's ``relationships``
    field: a list of relationship dicts plus the count.
    """
    rels = build_relationships(stages)
    return {
        "relationships": [r.to_dict() for r in rels],
        "count": len(rels),
    }