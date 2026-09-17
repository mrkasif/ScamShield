"""Indian Scam Intelligence - Threat Pattern Library.

An ADDITIVE, deterministic, fully-offline interpretation layer that sits ABOVE
the existing scam detectors and *interprets their evidence*. It never:

* replaces, weakens or re-scores the existing detectors;
* changes the authoritative 0-100 risk score or the Safety Zone;
* opens URLs, resolves domains, decodes anything, or touches the network;
* calls an LLM or any external API;
* invents evidence or claims a pattern/entity that no detected indicator
  supports;
* labels a legitimate Indian brand/organisation as malicious. If an existing
  impersonation indicator (e.g. ``bank_impersonation``) already names a known
  entity, that entity is surfaced as POSSIBLY IMPERSONATED - the real
  organisation is never accused.

How it works (deterministic rules, no statistics):

1. Evidence is gathered ONLY from the unified result the existing engines
   already produced: the top-level ``indicators`` plus each ``explanation``
   entry's ``indicator``, ``reason`` and ``summary`` text. Nothing is computed
   from the raw input directly.
2. Each threat pattern declares a small set of evidence terms (indicator ids
   and explainable text substrings). A pattern "matches" (``matched_terms``,
   ``matched_evidence``) only for terms that appear in the real evidence.
3. A pattern is REPORTED when the overall result is already
   ``is_suspicious`` and at least ``min_terms`` distinct terms matched.
4. Confidence is a deterministic, internally-consistent *rule strength* value
   (0-100) derived from how many distinct evidence terms matched, whether the
   Safety Zone is RED and whether high-severity / credential-related evidence
   is present. It is explicitly documented as rule strength, NOT a calibrated
   statistical probability.
5. The strongest matched pattern becomes ``primary_pattern``; the others are
   listed as ``related_patterns`` (deterministic order: more evidence first,
   then alphabetically by id).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Indian entity table (used ONLY to annotate existing impersonation evidence)
# ---------------------------------------------------------------------------
# These are the real, legitimate Indian services/organisations that phishers
# routinely impersonate. Listing them here is NOT an accusation: a name is only
# surfaced under ``referenced_entities`` when an existing detector already
# emitted an impersonation indicator whose evidence text mentions it.

INDIAN_ENTITIES = {
    "sbi": {"brand": "SBI", "category": "banking"},
    "sbi_yono": {"brand": "SBI YONO", "category": "banking"},
    "hdfc": {"brand": "HDFC Bank", "category": "banking"},
    "icici": {"brand": "ICICI Bank", "category": "banking"},
    "axis": {"brand": "Axis Bank", "category": "banking"},
    "kotak": {"brand": "Kotak Mahindra Bank", "category": "banking"},
    "canara": {"brand": "Canara Bank", "category": "banking"},
    "pnb": {"brand": "Punjab National Bank", "category": "banking"},
    "bank_of_baroda": {"brand": "Bank of Baroda", "category": "banking"},
    "union_bank": {"brand": "Union Bank of India", "category": "banking"},
    "upi": {"brand": "UPI", "category": "payments"},
    "phonepe": {"brand": "PhonePe", "category": "payments"},
    "paytm": {"brand": "Paytm", "category": "payments"},
    "google_pay": {"brand": "Google Pay", "category": "payments"},
    "gpay": {"brand": "Google Pay", "category": "payments"},
    "irctc": {"brand": "IRCTC", "category": "travel"},
    "uidai": {"brand": "UIDAI / Aadhaar", "category": "government"},
    "aadhaar": {"brand": "UIDAI / Aadhaar", "category": "government"},
    "income_tax": {"brand": "Income Tax Department",
                   "category": "government"},
    "india_post": {"brand": "India Post", "category": "government_post"},
    "jio": {"brand": "Jio", "category": "telecom"},
    "airtel": {"brand": "Airtel", "category": "telecom"},
    "vi": {"brand": "Vodafone Idea", "category": "telecom"},
}

# Alphabetical key list whose values are subsequence-matched only
_ENTITY_BOUNDARY_NEEDED = {"upi", "vi", "sbi", "axis", "jio", "gpay"}


def _matches_entity(text_lower: str, key: str) -> bool:
    if key in _ENTITY_BOUNDARY_NEEDED:
        return bool(re.search(rf"(?<![a-z0-9]){re.escape(key)}(?![a-z0-9])",
                              text_lower))
    return key in text_lower


# ---------------------------------------------------------------------------
# Evidence collection - ONLY from what the engines already reported
# ---------------------------------------------------------------------------

_INDICATOR_WHERE = re.compile(r"[^a-z0-9_]")


def _indicator_tokens(indicators) -> list[str]:
    if not indicators:
        return []
    out = []
    for indicator in indicators:
        text = _INDICATOR_WHERE.sub(" ", str(indicator or "")).lower().strip()
        out.extend(t for t in text.split() if t)
    return out


def _normalize_evidence_text(piece) -> str:
    return re.sub(r"\s+", " ", str(piece or "")).lower()


def _collect_evidence(result: dict) -> tuple[list[str], list[str]]:
    """Return (indicator_tokens, evidence_texts).

    ``evidence_texts`` is the low-entropy text the engines actually wrote in
    ``explanation`` (indicator id + reason + summary) and in ``summary``. All
    entries that exist in the unified result are included verbatim - nothing is
    invented.
    """
    tokens: list[str] = []
    texts: list[str] = []

    for indicator in result.get("indicators") or []:
        tokens.extend(_indicator_tokens([indicator]))

    explanation = result.get("explanation") or []
    if isinstance(explanation, list):
        entries = explanation
    elif isinstance(explanation, dict):
        entries = (explanation.get("entries")
                   or explanation.get("items") or [])
    else:
        entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        indicator = entry.get("indicator")
        if indicator:
            tokens.extend(_indicator_tokens([indicator]))
        for key in ("reason", "summary", "indicator"):
            value = entry.get(key)
            if value:
                texts.append(_normalize_evidence_text(value))

    summary = result.get("summary")
    if summary:
        texts.append(_normalize_evidence_text(summary))

    # Deduplicate while preserving first-seen order.
    seen = set()
    unique_tokens: list[str] = []
    for token in tokens:
        if token not in seen:
            seen.add(token)
            unique_tokens.append(token)
    return unique_tokens, list(dict.fromkeys(texts))


def _text_union(tokens: list[str], texts: list[str]) -> str:
    return " " + " ".join(tokens + texts) + " "


def _term_score(term: str, tokens: list[str], haystack: str) -> int:
    """0=no evidence, 1=evidence-text match, 2=indicator/token match."""
    if any(token == term for token in tokens):
        return 2
    if term in tokens:  # substring match against an indicator token
        return 1
    if len(term) >= 4 and term in haystack:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Threat pattern library (compact structured rules - no huge data files)
# ---------------------------------------------------------------------------
# Each pattern: id, name, description, typical_target, evidence_terms,
# min_terms (distinct terms required before reporting), tactics (deterministic
# tactic ids, filtered at match time to those with evidence support),
# recommended_action.

SCAM_PATTERNS = [
    {
        "id": "kyc_verification",
        "name": "KYC / Account Verification Scam",
        "description": "Claims the victim's KYC/account verification is due or "
                       "expired and presses them to act immediately to avoid "
                       "suspension or account blockage.",
        "typical_target": "Banking customers",
        "evidence_terms": [
            "kyc_request", "kyc", "bank_impersonation", "urgency",
            "urgent", "account_", "suspension", "suspend", "verify",
            "reverification", "identity_verification",
        ],
        "min_terms": 3,
        "tactics": [
            "urgency", "account_suspension", "fake_verification",
            "brand_impersonation",
        ],
        "recommended_action": "Verify through the official banking application "
                              "or website.",
    },
    {
        "id": "banking_phishing",
        "name": "Banking Phishing",
        "description": "A link or message masquerades as a real bank or its "
                       "login/payment flow to steal banking credentials or "
                       "drive the victim to a fake page.",
        "typical_target": "Banking customers",
        "evidence_terms": [
            "bank_impersonation", "brand_impersonation",
            "brand_in_subdomain", "brand_in_path", "credential_request",
            "login", "signin", "password", "credential", "phishing",
            "verify_account", "update_account", "otp_request", "otp",
        ],
        "min_terms": 4,
        "tactics": [
            "brand_impersonation", "credential_harvesting",
            "account_suspension", "urgency",
        ],
        "recommended_action": "Open the bank's official app or website "
                              "directly instead of clicking the link.",
    },
    {
        "id": "upi_payment",
        "name": "UPI / Payment Scam",
        "description": "Pressures the victim to send money via UPI (or a "
                       "pre-filled UPI payment request) and sometimes a "
                       "refund/reward story.",
        "typical_target": "UPI app users",
        "evidence_terms": [
            "upi_payment_request", "upi", "payment_request",
            "request_money", "amount", "payee", "refund", "reward_claim",
            "transaction", "payment",
        ],
        "min_terms": 4,
        "tactics": ["payment_request", "urgency", "reward_bait"],
        "recommended_action": "Never approve an unexpected UPI payment "
                              "request; verify the payee before paying.",
    },
    {
        "id": "otp_harvesting",
        "name": "OTP / Verification Scam",
        "description": "Asks the victim to share an OTP / one-time password "
                       "on the pretext of KYC, refund, offer or verification.",
        "typical_target": "Anyone with a bank/UPI account",
        "evidence_terms": [
            "otp_request", "otp", "share_otp", "one_time_password",
            "credential_request", "otp", "verification", "confirm", "verify",
        ],
        "min_terms": 3,
        "tactics": ["otp_collection", "fake_verification", "urgency"],
        "recommended_action": "Never share an OTP with anyone, including "
                              "callers claiming to be from the bank.",
    },
    {
        "id": "fake_customer_care",
        "name": "Fake Customer Care Scam",
        "description": "Impersonates a company's customer-care / helpline "
                       "(or the company itself) to extract money or "
                       "credentials via a fake support process.",
        "typical_target": "Customers of telecoms, banks and tech companies",
        "evidence_terms": [
            "customer_care", "customer_support", "support", "helpline",
            "otp_request", "credential_request", "social_impersonation",
            "technology_impersonation",
        ],
        "min_terms": 3,
        "tactics": ["fake_verification", "credential_harvesting", "urgency"],
        "recommended_action": "Contact the company only through the official "
                              "number/app/website, never the number in the "
                              "message.",
    },
    {
        "id": "job_recruitment",
        "name": "Job / Recruitment Scam",
        "description": "Offers a job / work-from-home role and asks for a "
                       "'registration / processing / joining' fee or "
                       "sensitive personal data.",
        "typical_target": "Job seekers, students, gig workers",
        "evidence_terms": [
            "job_offer", "job", "recruitment", "registration_fee", "salary",
            "work_from_home", "interview", "payment_request", "upskilling",
        ],
        "min_terms": 3,
        "tactics": ["employment_bait", "payment_request"],
        "recommended_action": "Never pay to 'register' for a job; verify the "
                              "employer independently first.",
    },
    {
        "id": "loan_scam",
        "name": "Loan Scam",
        "description": "Offers an instant / easy loan and demands an advance / "
                       "processing fee or credential/OTP before disbursing.",
        "typical_target": "People seeking fast personal loans",
        "evidence_terms": [
            "loan_offer", "loan", "advance_fee", "processing_fee", "instant",
            "pre_approved", "credit", "payment_request",
        ],
        "min_terms": 3,
        "tactics": ["payment_request", "reward_bait"],
        "recommended_action": "Only deal with RBI-registered lenders; "
                              "legitimate lenders never charge an upfront fee.",
    },
    {
        "id": "investment_scam",
        "name": "Investment / Trading Scam",
        "description": "Promises guaranteed / very high returns on investment "
                       "or trading, often pushing an urgent deposit or "
                       "prize-like reward.",
        "typical_target": "People seeking high-return investments",
        "evidence_terms": [
            "investment_fraud", "investment", "guaranteed_return",
            "high_return", "trading", "double_your", "reward_claim",
            "quick_profit", "get_rich",
        ],
        "min_terms": 3,
        "tactics": ["investment_promise", "reward_bait", "urgency"],
        "recommended_action": "Verify the platform independently and avoid any "
                              "guaranteed-return claim.",
    },
    {
        "id": "electricity_utility",
        "name": "Electricity / Utility Disconnection Scam",
        "description": "Threatens disconnection of an electricity/utility "
                       "connection and pushes urgent payment through a "
                       "link/UPI to avoid it.",
        "typical_target": "Electricity / utility bill payers",
        "evidence_terms": [
            "electricity", "utility", "disconnect", "disconnection",
            "overdue", "bill", "death_threat", "payment_request", "urgency",
        ],
        "min_terms": 3,
        "tactics": ["urgency", "payment_request", "threat_fear"],
        "recommended_action": "Verify through the official utility app/website "
                              "and pay only on the official platform.",
    },
    {
        "id": "parcel_courier",
        "name": "Parcel / Courier Scam",
        "description": "Claims a parcel/courier is stuck at customs or needs "
                       "a delivery/customs fee, directing payment to a fake "
                       "account.",
        "typical_target": "Online shoppers, courier customers",
        "evidence_terms": [
            "parcel", "courier", "customs", "delivery", "shipping_fee",
            "tracking", "india_post", "payment_request",
        ],
        "min_terms": 3,
        "tactics": ["payment_request", "urgency"],
        "recommended_action": "Verify the shipment independently on the "
                              "official carrier site before paying anything.",
    },
    {
        "id": "government_impersonation",
        "name": "Government Impersonation Scam",
        "description": "Impersonates a government body / department or agency "
                       "(income tax, UIDAI/Aadhaar, police, court, India "
                       "Post) to frighten the victim into paying or sharing "
                       "data.",
        "typical_target": "Taxpayers, Aadhaar holders, the general public",
        "evidence_terms": [
            "government_impersonation", "authority", "income_tax",
            "uidai", "aadhaar", "police", "court", "legal", "india_post",
            "govt", "notification", "case_filed", "arrest",
        ],
        "min_terms": 3,
        "tactics": ["threat_fear", "account_suspension",
                    "credential_harvesting"],
        "recommended_action": "Do not pay or share data under threat. Verify "
                              "with the official government portal/helpdesk.",
    },
    {
        "id": "lottery_reward",
        "name": "Lottery / Prize / Reward Scam",
        "description": "Announces the victim won a lottery/prize/reward and "
                       "asks for a processing/claim fee or OTP to release "
                       "the winnings.",
        "typical_target": "Everyone (broad outreach via SMS/QR/UPI)",
        "evidence_terms": [
            "prize_lottery", "lottery", "reward_claim", "reward",
            "winner", "claim", "payout", "prize", "you_have_won",
        ],
        "min_terms": 3,
        "tactics": ["reward_bait", "payment_request", "otp_collection"],
        "recommended_action": "Do not pay a 'fee' to claim a prize you never "
                              "entered. Report and delete.",
    },
    {
        "id": "refund_scam",
        "name": "Refund Scam",
        "description": "Claims you are owed a refund and asks you to confirm "
                       "bank details / share an OTP or pay a 'refund "
                       "processing' amount.",
        "typical_target": "Recent online shoppers / service users",
        "evidence_terms": [
            "refund_request", "refund", "refund_amount",
            "upi_payment_request", "otp_request", "bank_details",
            "reversal", "back_payment", "account_credit",
        ],
        "min_terms": 3,
        "tactics": ["refund_bait", "otp_collection", "payment_request"],
        "recommended_action": "Refunds are processed through the original "
                              "payment method only - never share OTPs or "
                              "transfer money to 'receive' one.",
    },
    {
        "id": "social_media_impersonation",
        "name": "Social Media Account Impersonation / Support Scam",
        "description": "Impersonates a social platform, its support or an "
                       "acquaintance to harvest login credentials, run fake "
                       "giveaways or push payment.",
        "typical_target": "Social media users",
        "evidence_terms": [
            "social_impersonation", "social_media", "account_recovery",
            "instagram", "whatsapp", "facebook", "telegram", "credential",
            "login", "giveaway",
        ],
        "min_terms": 3,
        "tactics": ["brand_impersonation", "credential_harvesting",
                    "reward_bait"],
        "recommended_action": "Do not enter credentials on unofficial pages. "
                              "Contact support through the platform's real "
                              "official channels only.",
    },
    {
        "id": "credential_harvesting",
        "name": "Credential Harvesting / Login Phishing",
        "description": "A page or message asks the victim to log in, 'verify "
                       "account', update credentials or scan a login QR so "
                       "their username/password/OTP is captured.",
        "typical_target": "Email, banking, social & work account holders",
        "evidence_terms": [
            "credential_request", "password", "login", "signin",
            "verify_account", "update_account", "credential_harvesting",
            "suspicious_redirect_parameter", "brand_in_subdomain",
            "qr_", "otp", "phishing",
        ],
        "min_terms": 4,
        "tactics": ["credential_harvesting", "brand_impersonation"],
        "recommended_action": "Do not enter credentials. Open the official "
                              "service directly instead.",
    },
]

_PATTERNS_BY_ID = {p["id"]: p for p in SCAM_PATTERNS}

# ---------------------------------------------------------------------------
# Tactic classifiers (deterministic). Each tactic is reported only when at
# least two of its evidence terms appear in the actual evidence.
# ---------------------------------------------------------------------------

_TACTIC_RULES = {
    "urgency": ["urgency", "urgent", "immediately", "act_now", "asap",
                "limited_time", "deadline", "now"],
    "threat_fear": ["suspension", "suspend", "blocked", "disconnect",
                    "arrest", "legal", "case", "penalty", "fine", "warn"],
    "account_suspension": ["suspension", "suspend", "blocked", "deactivated",
                           "terminated", "locked"],
    "brand_impersonation": ["impersonation", "brand", "imitation",
                            "impersonated"],
    "credential_harvesting": ["credential", "password", "login", "signin",
                              "otp", "otp_request", "verify_account"],
    "payment_request": ["payment_request", "upi", "payee", "amount",
                        "transfer", "send", "fee", "payment"],
    "otp_collection": ["otp", "otp_request", "share_otp", "one_time_code"],
    "fake_verification": ["verify", "verification", "kyc", "confirm",
                          "reverification"],
    "reward_bait": ["prize", "reward", "lottery", "won", "winner", "claim"],
    "investment_promise": ["investment", "return", "profit", "guaranteed",
                           "trading", "get_rich"],
    "employment_bait": ["job", "recruitment", "salary", "work_from_home",
                        "interview"],
    "refund_bait": ["refund", "reversal", "back_payment", "account_credit"],
}

_CONFIDENCE_NOTE = (
    "Rule-based confidence - a deterministic strength measure derived from how "
    "many distinct detected evidence terms matched the pattern. It is an "
    "internal, explainable heuristic score, NOT a calibrated statistical "
    "probability."
)

_IMPERSONATION_INDICATORS = frozenset({
    "bank_impersonation", "brand_impersonation",
    "government_impersonation", "social_impersonation",
    "technology_impersonation", "brand_in_subdomain", "brand_in_path",
    "possible_brand_typosquatting",
})


# ---------------------------------------------------------------------------
# Deterministic matching
# ---------------------------------------------------------------------------

def _matched_tactics(terms: list[str], tokens: list[str], haystack: str,
                     tactics_from_pattern: list[str]) -> list[str]:
    """Return the pattern's tactics that are supported by actual evidence."""
    supported = []
    for tactic in tactics_from_pattern:
        rules = _TACTIC_RULES.get(tactic, [])
        hits = 0
        for term in rules:
            if _term_score(term, tokens, haystack):
                hits += 1
        if hits >= 2:
            supported.append(tactic)
    return supported


def _referenced_entities(tokens: list[str], texts: list[str],
                         is_suspicious: bool,
                         matched_terms: list[str]) -> list[dict]:
    """Entities named as POSSIBLY IMPERSONATED - only when an existing
    impersonation indicator is present in the evidence AND the entity name
    actually appears in the evidence text."""
    if not is_suspicious:
        return []
    text_lower = " ".join(tokens + texts + matched_terms).lower()
    impersonation_present = any(
        name in text_lower for name in _IMPERSONATION_INDICATORS
    )
    if not impersonation_present:
        return []
    entities = []
    for key, meta in INDIAN_ENTITIES.items():
        if not _matches_entity(text_lower, key):
            continue
        entities.append({
            "entity": key,
            "brand": meta["brand"],
            "category": meta["category"],
            "assessment": (
                "Possible brand impersonation - the REAL "
                f"{meta['brand']} is NOT reported as malicious; it is only "
                "being impersonated by the suspicious content."
            ),
            "evidence_term": key,
        })
    entities.sort(key=lambda e: e["entity"])
    return entities


def build_scam_intelligence(result: dict) -> dict:
    """Build the additive ``scam_intelligence`` section for a unified result.

    Deterministic and rule-based. It reads ONLY the already-produced evidence
    (indicators / explanation / summary). A pattern is only reported when the
    authoritative result is already ``is_suspicious`` and enough distinct
    evidence terms match - so a pattern can never be claimed without real,
    detectable evidence. The authoritative ``risk_score`` and Safety Zone are
    never modified here.
    """
    tokens, texts = _collect_evidence(result)
    haystack = _text_union(tokens, texts)
    indicator_set = set(tokens)

    is_suspicious = bool(result.get("is_suspicious")) or (
        result.get("is_suspicious") is None
        and (result.get("risk_score") or 0) >= 25
    )
    red = (result.get("risk_score") or 0) >= 60

    matches: list[dict] = []
    for pattern in SCAM_PATTERNS:
        matched_terms = []
        for term in pattern["evidence_terms"]:
            if _term_score(term, tokens, haystack) > 0:
                matched_terms.append(term)
        matched_terms = list(dict.fromkeys(matched_terms))
        if not is_suspicious:
            continue
        if len(matched_terms) < pattern["min_terms"]:
            continue

        # Rule-strength confidence (0-100), deterministic, evidence-only.
        strength = 45 + 8 * (len(matched_terms) - pattern["min_terms"])
        if red:
            strength += 18
        strong_evidence = any(
            term in indicator_set or term in {"otp", "password", "credential"}
            for term in matched_terms
        )
        if strong_evidence:
            strength += 12
        confidence = max(0, min(100, int(strength)))

        matches.append({
            "pattern_id": pattern["id"],
            "name": pattern["name"],
            "description": pattern["description"],
            "typical_target": pattern["typical_target"],
            "matched_terms": matched_terms,
            "min_terms": pattern["min_terms"],
            "confidence": confidence,
            "confidence_type": "rule_based",
            "confidence_note": _CONFIDENCE_NOTE,
            "tactics": _matched_tactics(matched_terms, tokens, haystack,
                                        pattern["tactics"]),
            "recommended_action": pattern["recommended_action"],
        })

    matches.sort(key=lambda m: (-len(m["matched_terms"]),
                                (-m["min_terms"], m["pattern_id"])))
    primary = matches[0] if matches else None

    referenced = []
    if primary:
        referenced = _referenced_entities(
            tokens, texts, is_suspicious, primary["matched_terms"]
        )

    return {
        "primary_pattern": primary,
        "related_patterns": matches[1:],
        "referenced_entities": referenced,
        "confidence_type": "rule_based",
        "confidence_note": _CONFIDENCE_NOTE,
        "note": (
            "Deterministic, offline, evidence-driven interpretation of the "
            "existing detectors. The authoritative 0-100 risk score and "
            "Safety Zone are never changed by this layer. No machine learning, "
            "no LLM, no network, no external API. Referenced Indian "
            "entities are legitimate organisations only being IMPERSONATED; "
            "they are never labelled malicious."
        ),
    }


def attach_scam_intelligence(result: dict) -> dict:
    """Attach the additive ``scam_intelligence`` section to a unified result.

    Additive only: this adds the new ``scam_intelligence`` key and never
    modifies any existing key/value, never changes the risk score or the
    Safety Zone. Returns the same dict (mutated in place and returned).
    """
    result["scam_intelligence"] = build_scam_intelligence(result)
    return result


__all__ = [
    "SCAM_PATTERNS",
    "INDIAN_ENTITIES",
    "build_scam_intelligence",
    "attach_scam_intelligence",
]
