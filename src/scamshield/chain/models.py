"""Structured, normalized representations of analyzed artifacts (stages) for chain analysis.

The chain analyzer NEVER re-runs message/URL/QR/UPI detection. It accepts artifacts
that have ALREADY been analyzed by the individual engines (or the unified analyzer)
and normalizes the relevant fields into a lightweight :class:`Stage`.

Three kinds of input are accepted and normalized the same way:

* a raw engine result (e.g. ``analyze_message(...)``, ``analyze_url(...)``,
  ``analyze_qr(...)`` output), auto-detected by its keys;
* a unified analyzer result (``analyze("message", ...)`` etc. which carries an
  ``engine_results`` dict);
* an explicitly structured dictionary with the documented fields (see
  :meth:`Stage.from_dict`).

The normalized stage carries only the fields needed for correlation/scoring so the
rest of the chain package stays engine-agnostic and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Supported artifact types (chain stages)
SUPPORTED_TYPES = ("message", "url", "qr", "upi")

_ENGINE_KEYS_TO_TYPES = {
    "url": "url",  # matches URL engine / QR url_analysis sub-dict
    "message": "message",  # matches message engine / QR message_analysis sub-dict
    "upi": "upi",  # matches QR upi_analysis sub-dict
}

# A message engine result has these top-levels; a URL result has 'url' + 'parse'.
_MESSAGE_ENGINE_MARKERS = ("detected_indicators", "is_scam", "url_analysis", "explanations")
_URL_ENGINE_MARKERS = ("parse", "url")
_UPI_ENGINE_MARKERS = ("payee_address",)

_URL_SENSITIVE_SUBSTRINGS = ("login", "verify", "kyc", "update", "pan", "aadhaar", "otp", "secure", "confirm", "rebate", "refund", "prize", "claim", "loan", "offer")
_UPI_SENSITIVE_LANGUAGE = (
    "refund", "prize", "claim", "reward", "loan", "investment", "salary", "bonus",
    "cashback", "rebate", "kyc", "verify", "urgent", "fee", "payment", "money", "amount",
)


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def parse_url_safely(url: str) -> Optional[Dict[str, Any]]:
    """Deterministic, offline URL normalization for *matching* purposes.

    This is used for chain correlation ONLY (extract root domain / hostname / path
    so the chain can test whether two artifacts reference the same destination). It
    does NOT visit the URL, resolve DNS, or follow redirects, and it does NOT
    replicate the URL engine's risk scoring.

    Returns a dict with ``scheme``, ``hostname``, ``root_domain``, ``path``,
    ``query``, ``fragment``, ``with_scheme`` — or ``None`` if the string is not a
    plausible scheme:// URL (i.e. ``upi://`` and http(s) scheme present).
    """
    if not isinstance(url, str):
        return None
    s = url.strip()
    if not s:
        return None
    low = s.lower()
    if not (low.startswith(("http://", "https://", "upi://"))):
        return None
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(s)
    except Exception:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    hostname = (parts.hostname or "").lower().strip(".")
    if not hostname:
        return None
    path = parts.path or ""
    return {
        "scheme": parts.scheme.lower(),
        "hostname": hostname,
        "root_domain": _root_domain(hostname),
        "path": path,
        "query": parts.query or "",
        "fragment": parts.fragment or "",
        "with_scheme": f"{parts.scheme.lower()}://{hostname}{path}" + (f"?{parts.query}" if parts.query else ""),
    }


def _root_domain(hostname: str) -> str:
    """Best-effort registrable-domain extraction from a hostname.

    Uses the public-suffix heuristic of the URL engine (last 2 labels when the TLD
    is not strongly multi-part) so matching stays deterministic and offline. Exact
    hostnames are preserved separately by :func:`model aliases`.
    """
    labels = hostname.strip(".").split(".")
    if len(labels) <= 2:
        return hostname
    # Multi-label TLDs are rare in the synthetic dataset and the public suffix
    # list is intentionally avoided (offline, no external dependency). Keep the
    # last two labels as the registrable root for matching purposes.
    return ".".join(labels[-2:])


def _extract_urls_and_domains(analysis: Dict[str, Any]) -> tuple:
    """Best-effort extraction of ``url`` / ``domain`` strings from an analysis dict.

    Handles the shapes produced by the individual engines:

    * a direct ``url`` key (URL engine, QR ``url_analysis`` sub-dict);
    * a ``detected_urls`` list (message engine);
    * a nested ``url_analysis`` dict OR list-of-dicts (message engine);
    * nested ``upi_analysis`` / ``message_analysis`` sub-dicts with a ``url`` key.

    Returns a deduplicated, order-preserving list of urls and domains.
    """
    urls: List[str] = []
    domains: List[str] = []

    def add_url(u: Any) -> None:
        u = _safe_str(u).strip()
        if u and u.lower() not in [x.lower() for x in urls]:
            urls.append(u)
        if u:
            p = parse_url_safely(u)
            if p:
                root = (p.get("root_domain") or "").strip()
                if root and root.lower() not in [x.lower() for x in domains]:
                    domains.append(root)

    # Direct 'url' key
    if "url" in analysis:
        add_url(analysis["url"])
    # Message detected_urls list
    for u in _as_list(analysis.get("detected_urls")):
        add_url(u)
    # Nested sub-analysis: url_analysis may be a dict or a list of dicts
    for sub_key in ("url_analysis", "upi_analysis", "message_analysis"):
        sub = analysis.get(sub_key)
        subs = sub if isinstance(sub, list) else [sub]
        for s in subs:
            if isinstance(s, dict):
                if s.get("url"):
                    add_url(s["url"])
    # URL parse root_domain (standalone URL engine result)
    parse = analysis.get("parse") if isinstance(analysis.get("parse"), dict) else {}
    root = parse.get("root_domain")
    if root:
        root = _safe_str(root).strip()
        if root and root.lower() not in [x.lower() for x in domains]:
            domains.append(root)

    return urls, domains


def _detect_type(analysis: Dict[str, Any]) -> Optional[str]:
    """Detect the stage type from an engine/unified result dict without re-running detection."""
    if not isinstance(analysis, dict):
        return None

    # Explicitly-typed structured dict wins.
    t = analysis.get("type") or analysis.get("input_type")
    if isinstance(t, str) and t in SUPPORTED_TYPES:
        return t

    # Unified analyzer result with an engine_results wrapper: detect from the
    # inner engine result's own structure (which the detectors already produced).
    if isinstance(analysis.get("engine_results"), dict):
        er = analysis["engine_results"]
        for key in ("message", "url", "qr", "upi"):
            if key in er and isinstance(er[key], dict):
                t = _detect_type(er[key])
                if t:
                    return t
        return None

    # Sub-analysis markers from QR (url_analysis / upi_analysis / message_analysis)
    # are detected by their own keys; this handles standalone dicts with those shapes.
    if "payee_address" in analysis or (
        "parse" in analysis and isinstance(analysis.get("parse"), dict)
        and analysis.get("parse", {}).get("scheme") == "upi"
    ):
        return "upi"
    # A result carrying a dedicated upi_analysis sub-dict (QR envelope wrapping a UPI
    # decode or the unified UPI engine) is a UPI stage.
    if isinstance(analysis.get("upi_analysis"), dict):
        return "upi"
    if "url" in analysis and "parse" in analysis and _is_url_like(analysis.get("url")):
        return "url"
    if any(m in analysis for m in _MESSAGE_ENGINE_MARKERS) and "detected_urls" in analysis:
        return "message"
    if analysis.get("content_type") in ("url", "upi", "text") or "decoded" in analysis:
        return "qr"
    return None


def _is_url_like(value: Any) -> bool:
    v = _safe_str(value)
    return v.lower().startswith(("http://", "https://", "upi://", "upi:"))


class StageBuildError(ValueError):
    """Raised when a stage cannot be normalized from the supplied artifact."""


@dataclass
class Stage:
    """A normalized stage of a chain.

    Fields:

    * ``idx`` — 0-based index in the supplied input order (preserved).
    * ``type`` — ``message`` | ``url`` | ``qr`` | ``upi``.
    * ``label`` — human readable label for this stage.
    * ``risk_score`` — 0..100 (from the original analysis; not recomputed).
    * ``risk_level`` — ``LOW`` | ``MEDIUM`` | ``HIGH`` | ``CRITICAL``.
    * ``is_suspicious`` — whether the original analysis flagged it.
    * ``scam_type`` — original scam category string (may be None/mixed).
    * ``indicators`` — list of indicator names from the original analysis.
    * ``urls`` — extracted URL strings.
    * ``domains`` — extracted registrable-root domains.
    * ``payee_address``, ``amount``, ``currency``, ``transaction_ref`` — UPI metadata when present.
    * ``content_type`` — for ``qr`` stages: ``url`` | ``upi`` | ``text``.
    * ``decoded_text`` — for ``qr`` text stage.
    * ``raw`` — the original analysis dict (kept for evidence + round-tripping).
    * ``provenance`` — whether normalized from engine/unified/structured input.
    * ``warnings`` — non-fatal normalization notes.
    """

    idx: int
    type: str
    label: str
    risk_score: int
    risk_level: str
    is_suspicious: bool
    indicators: List[str] = field(default_factory=list)
    scam_type: Optional[str] = None
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    payee_address: Optional[str] = None
    amount: Optional[float] = None
    currency: Optional[str] = None
    transaction_ref: Optional[str] = None
    content_type: Optional[str] = None
    decoded_text: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    provenance: str = "structured"
    warnings: List[str] = field(default_factory=list)

    # -- convenience ---------------------------------------------------------
    @property
    def suspicious(self) -> bool:
        return self.is_suspicious

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serializable projection of the stage (excludes bulky raw by default)."""
        return {
            "id": self.idx + 1,
            "type": self.type,
            "label": self.label,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "is_suspicious": self.is_suspicious,
            "indicators": list(self.indicators),
            "scam_type": self.scam_type,
            "urls": list(self.urls),
            "domains": list(self.domains),
            "payee_address": self.payee_address,
            "amount": self.amount,
            "currency": self.currency,
            "content_type": self.content_type,
            "decoded_text": self.decoded_text[:300] if self.decoded_text else None,
        }

    # -- normalization helpers ----------------------------------------------
    def _normalize_risk(self, analysis: Dict[str, Any]) -> None:
        try:
            rs = analysis.get("risk_score")
            if rs is None:
                # Combined risk may be the authoritative message score.
                rs = analysis.get("combined_risk")
            self.risk_score = int(round(float(rs))) if rs is not None else 0
        except (TypeError, ValueError):
            self.risk_score = 0
            self.warnings.append("non-numeric risk_score coerced to 0")

        self.risk_level = _safe_str(analysis.get("risk_level") or "").upper() or _level_for_score(self.risk_score)
        self.is_suspicious = bool(analysis.get("is_suspicious") or analysis.get("is_scam") or analysis.get("suspicious"))

    def _normalize_indicators(self, analysis: Dict[str, Any]) -> None:
        self.indicators = [i for i in (analysis.get("detected_indicators", analysis.get("indicators", [])) or [])]
        if not isinstance(self.indicators, list):
            self.indicators = [str(self.indicators)]
        self.indicators = [str(i) for i in self.indicators]

    @classmethod
    def from_engine(cls, analysis: Dict[str, Any], idx: int, forced_type: Optional[str] = None) -> "Stage":
        """Normalize an already-analyzed artifact (raw engine / unified) into a Stage."""
        if not isinstance(analysis, dict):
            raise StageBuildError(f"stage {idx}: expected a mapping of analyzed fields, got {type(analysis).__name__}")

        # Unify: pull the primary engine result out of a unified wrapper if present.
        inner = analysis
        unified_engine = analysis.get("engine_results")
        if isinstance(unified_engine, dict):
            # Find the single message/url/qr/upi result inside engine_results.
            for key in ("message", "url", "qr", "upi"):
                if key in unified_engine and isinstance(unified_engine[key], dict):
                    inner = unified_engine[key]
                    if forced_type is None:
                        forced_type = key
                    break

        stype = forced_type or _detect_type(inner) or _detect_type(analysis)

        # QR is special: the *envelope* is the qr stage, but we preserve the
        # relevant nested analysis (url/upi/text) as metadata.
        qr_content_type = None
        decoded_text = None
        urls: List[str] = []
        domains: List[str] = []
        payee = None
        amount = None
        currency = None
        txn_ref = None
        indicators: List[Any] = []

        if stype == "qr":
            qr_content_type = _safe_str(inner.get("content_type") or inner.get("decoded_content_type") or "").lower() or None
            # A QR result envelope has .codes / .decoded; nested analysis holds the payload.
            sub = None
            if qr_content_type == "url":
                sub = inner.get("url_analysis")
            elif qr_content_type == "upi":
                sub = inner.get("upi_analysis")
            elif qr_content_type == "text":
                sub = inner.get("message_analysis")
                decoded_text = _as_list(inner.get("decoded"))[0] if inner.get("decoded") else inner.get("decoded_content")
            if sub is None:
                sub = inner
            # Risk from the QR envelope (authoritative for the artifact).
            urls, domains = _extract_urls_and_domains(inner)
            if sub is not inner:
                s_urls, s_domains = _extract_urls_and_domains(sub)
                urls = urls or s_urls
                domains = domains or s_domains
            parse = sub.get("parse") if isinstance(sub, dict) else None
            if isinstance(parse, dict) and parse.get("scheme") == "upi":
                payee = parse.get("payee_address")
                try:
                    amount = float(parse["amount"]) if parse.get("amount") is not None else None
                except (TypeError, ValueError):
                    amount = None
                currency = parse.get("currency") or None
                txn_ref = parse.get("transaction_ref") or None
            indicators = sub.get("indicators", []) if isinstance(sub, dict) else []
            scam_type = _safe_str(sub.get("scam_type") or inner.get("scam_type") or "") or None
        else:
            urls, domains = _extract_urls_and_domains(inner)
            parse = inner.get("parse") if isinstance(inner, dict) else None
            # Unified UPI engine result wraps the parse inside nested upi_analysis.
            nested_upi = inner.get("upi_analysis") if isinstance(inner, dict) else None
            if isinstance(nested_upi, dict):
                parse = parse or nested_upi.get("parse")
                if payee is None:
                    payee = nested_upi.get("payee_address")
            if isinstance(parse, dict):
                if parse.get("scheme") == "upi":
                    payee = parse.get("payee_address") or payee
                    try:
                        amount = float(parse["amount"]) if parse.get("amount") is not None else None
                    except (TypeError, ValueError):
                        amount = None
                    currency = parse.get("currency") or None
                    txn_ref = parse.get("transaction_ref") or None
            elif stype == "upi":
                payee = inner.get("payee_address") or payee
            indicators = inner.get("detected_indicators", inner.get("indicators", [])) or []
            scam_type = _safe_str(inner.get("scam_type") or "") or None

        if stype is None:
            raise StageBuildError(
                f"stage {idx}: could not determine artifact type from the supplied analysis. "
                "Supply a 'type'/'input_type' field or a recognized engine result."
            )
        if stype not in SUPPORTED_TYPES:
            raise StageBuildError(f"stage {idx}: unsupported artifact type {stype!r}")

        stage = cls(
            idx=idx,
            type=stype,
            label=_type_label(stype),
            risk_score=0,
            risk_level="",
            is_suspicious=False,
            indicators=[str(i) for i in indicators or []],
            scam_type=scam_type,
            urls=urls,
            domains=domains,
            payee_address=payee,
            amount=amount,
            currency=currency,
            transaction_ref=txn_ref,
            content_type=qr_content_type,
            decoded_text=decoded_text,
            raw=analysis,
            provenance="engine" if isinstance(unified_engine, dict) else "raw_engine",
        )
        stage._normalize_risk(inner if inner else analysis)
        return stage

    @classmethod
    def from_dict(cls, d: Dict[str, Any], idx: int) -> "Stage":
        """Normalize an explicitly structured stage dict.

        Expected fields: ``type`` (required), ``risk_score``/``risk_level``,
        ``is_suspicious``/``suspicious``, ``indicators``, ``scam_type``,
        ``urls``/``domain``/``url``, ``payee_address``/``amount``/``currency``,
        ``content_type``, ``decoded_text``.
        """
        if not isinstance(d, dict):
            raise StageBuildError(f"stage {idx}: structured stage must be a dict")
        stype = d.get("type") or d.get("input_type")
        if not isinstance(stype, str) or stype not in SUPPORTED_TYPES:
            raise StageBuildError(f"stage {idx}: structured stage requires a valid 'type' in {SUPPORTED_TYPES}")
        risk = d.get("risk_score", 0)
        try:
            risk = int(round(float(risk))) if risk is not None else 0
        except (TypeError, ValueError):
            risk = 0
        urls = [u for u in _as_list(d.get("urls") or d.get("url")) if u]
        domains = [u for u in _as_list(d.get("domains") or d.get("domain")) if u]
        amount = d.get("amount")
        try:
            amount = float(amount) if amount is not None else None
        except (TypeError, ValueError):
            amount = None
        stage = cls(
            idx=idx,
            type=stype,
            label=_type_label(stype),
            risk_score=risk,
            risk_level=_safe_str(d.get("risk_level") or "").upper() or _level_for_score(risk),
            is_suspicious=bool(d.get("is_suspicious", d.get("suspicious", d.get("is_scam", False)))),
            indicators=[str(i) for i in _as_list(d.get("indicators"))],
            scam_type=d.get("scam_type"),
            urls=urls,
            domains=domains,
            payee_address=d.get("payee_address"),
            amount=amount,
            currency=d.get("currency"),
            transaction_ref=d.get("transaction_ref"),
            content_type=d.get("content_type"),
            decoded_text=d.get("decoded_text"),
            raw=d,
            provenance="structured",
        )
        return stage

    # -- sensitive/payment signal helpers (see convenience + used by correlation) --
    @property
    def has_credential_signal(self) -> bool:
        inds = " ".join(i.lower() for i in self.indicators)
        combined = (inds + " " + _safe_str(self.scam_type).lower()).lower()
        for tok in ("kyc", "credential", "aadhaar", "pan", "otp", "password", "verify", "verify_identity", "sensitive"):
            if tok in combined:
                return True
        for u in self.urls:
            low = u.lower()
            if any(s in low for s in _URL_SENSITIVE_SUBSTRINGS):
                return True
        return False

    @property
    def has_payment_signal(self) -> bool:
        # A stage that requests/points toward payment: UPI, or payment language.
        if self.type == "upi":
            return True
        inds = " ".join(i.lower() for i in self.indicators)
        combined = (inds + " " + _safe_str(self.scam_type).lower() + " " + _safe_str(self.decoded_text or "").lower()).lower()
        return any(tok in combined for tok in ("payment", "upi", "refund", "prize", "claim", "reward", "fee", "cashback", "pay", "transaction"))

    @property
    def has_language_signal(self) -> bool:
        inds = " ".join(i.lower() for i in self.indicators)
        combined = (inds + " " + _safe_str(self.scam_type).lower()).lower()
        for tok in ("urgency", "urgent", "blocked", "expired", "immediately", "last", "suspended", "limited", "action_required", "kyc"):
            if tok in combined:
                return True
        return False

    @property
    def is_payment_stage(self) -> bool:
        return self.type == "upi"

    # -- specialized scam-family signal helpers (used by pattern detection) ----
    def _text(self) -> str:
        return (
            " ".join(i.lower() for i in self.indicators)
            + " " + _safe_str(self.scam_type).lower()
            + " " + _safe_str(self.decoded_text or "").lower()
        ).lower()

    def prize_refund_signal(self) -> bool:
        text = self._text()
        return any(tok in text for tok in ("prize", "refund", "reward", "lucky", "cashback", "rebate", "gift", "won", "draw", "lottery"))

    def support_signal(self) -> bool:
        text = self._text()
        # Explicit customer-care / bank-support impersonation markers. We do NOT
        # treat generic 'brand_impersonation' as a support signal (that indicator
        # fires for many scam types and would over-trigger fake_customer_care).
        markers = (
            "customer_care", "customer care", "helpline", "support", "service_center",
            "fake_customer_care", "representative", "executive", "technical_support",
        )
        stype = _safe_str(self.scam_type).lower()
        return any(m in text for m in markers) or "customer care" in stype or "support" in stype

    def job_signal(self) -> bool:
        text = self._text()
        return any(tok in text for tok in ("job", "work from home", "wfh", "part time", "part-time", "salary", "earn", "hiring"))

    def investment_signal(self) -> bool:
        text = self._text()
        return any(tok in text for tok in ("invest", "investment", "stock", "share", "crypto", "bitcoin", "returns", "profit", "trading"))

    def loan_signal(self) -> bool:
        text = self._text()
        return any(tok in text for tok in ("loan", "credit", "approval", "sanctioned", "borrow"))

    def sorted_domains(self) -> List[str]:
        return sorted({d.lower() for d in self.domains})


def _type_label(stype: str) -> str:
    return {
        "message": "Message",
        "url": "URL",
        "qr": "QR code",
        "upi": "UPI payment",
    }.get(stype, stype.capitalize())


def _level_for_score(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def normalize_stage(material: Any, idx: int = 0, forced_type: Optional[str] = None) -> Stage:
    """Normalize one stage from raw engine result / unified result / structured dict.

    Raises :class:`StageBuildError` if the artifact cannot be normalized so the
    caller can produce a structured error instead of crashing.
    """
    if isinstance(material, Stage):
        material.idx = idx
        return material

    if isinstance(material, dict):
        # A dict with an engine_results wrapper is ALWAYS a full unified/raw engine
        # result -> route through from_engine so nested sub-analysis (url/upi/text
        # inside a QR, url_analysis inside a message) is preserved.
        if isinstance(material.get("engine_results"), dict):
            return Stage.from_engine(material, idx, forced_type=forced_type)
        # Explicitly structured stage dict.
        explicit = material.get("type") or material.get("input_type")
        if isinstance(explicit, str) or _looks_structured(material):
            return Stage.from_dict(material, idx)
        return Stage.from_engine(material, idx, forced_type=forced_type)

    # A chain-stage dict wrapper: {"type": ..., "analysis": {...}}
    if isinstance(material, dict) and isinstance(material.get("analysis"), dict):
        return Stage.from_dict(material, idx) if not forced_type else Stage.from_engine(material["analysis"], idx, forced_type=forced_type)

    raise StageBuildError(f"stage {idx}: cannot normalize {type(material).__name__} into a chain stage")


def _looks_structured(d: Dict[str, Any]) -> bool:
    """A dict looks structured (not raw engine output) if it has an explicit type
    and does not look like a full engine result envelope."""
    if not isinstance(d, dict):
        return False
    if isinstance(d.get("type") or d.get("input_type"), str):
        return True
    if "engine_results" in d:
        return False
    return False
