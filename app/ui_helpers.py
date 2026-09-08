"""Shared helpers and CSS theme for the ScamShield command center UI.

Pure rendering utilities — no detection logic, no scoring, no backend
modifications.  Every function either returns an HTML string or writes
directly to Streamlit using the *already returned* result dicts.
"""
from __future__ import annotations

import math
import html as _html

import streamlit as st

try:
    from scamshield.ml.predict import predict_message as _predict_message  # noqa: F401
    _ML_AVAILABLE = True
except Exception:
    _ML_AVAILABLE = False


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

COLORS = {
    "bg":            "#0a0e17",
    "panel":         "#111827",
    "panel_light":   "#1a2233",
    "border":        "#1e293b",
    "input_bg":      "#161b22",
    "input_border":  "#30363d",
    "accent":        "#00b4d8",
    "accent_dim":    "#0096c7",
    "accent_glow":   "rgba(0,180,216,0.25)",
    "text":          "#e5e7eb",
    "text_sec":      "#9ca3af",
    "text_muted":    "#6b7280",
    "safe":          "#00c853",
    "warning":       "#f59e0b",
    "danger":        "#ff9800",
    "critical":      "#ff1744",
}

RISK_STYLES: dict[str, dict[str, str]] = {
    "LOW":      {"color": "#00c853", "bg": "rgba(0,200,83,0.10)",  "border": "rgba(0,200,83,0.30)"},
    "MEDIUM":   {"color": "#f59e0b", "bg": "rgba(245,158,11,0.10)","border": "rgba(245,158,11,0.30)"},
    "HIGH":     {"color": "#ff9800", "bg": "rgba(255,152,0,0.10)", "border": "rgba(255,152,0,0.30)"},
    "CRITICAL": {"color": "#ff1744", "bg": "rgba(255,23,68,0.10)", "border": "rgba(255,23,68,0.30)"},
}


# ---------------------------------------------------------------------------
# CSS theme — injected once via  st.markdown("<style>…</style>")
# ---------------------------------------------------------------------------

CSS_THEME = """
<style>
/* ================================================================
   SCAMSHIELD COMMAND CENTER — DARK CYBERSECURITY THEME
   ================================================================ */

/* --- global background ---------------------------------------- */
.stApp, [data-testid="stAppViewContainer"], .main .block-container {
    background-color: #0a0e17 !important;
}
.main .block-container {
    padding-top: 1rem !important;
    padding-bottom: 2rem !important;
}

/* --- header --------------------------------------------------- */
[data-testid="stHeader"] { background-color: #0a0e17 !important; }
[data-testid="stHeader"] hr { border-color: #1e293b !important; }

/* --- sidebar -------------------------------------------------- */
[data-testid="stSidebar"] {
    background-color: #0d1117 !important;
    border-right: 1px solid #1e293b !important;
}
[data-testid="stSidebar"] .stMarkdown p,
[data-testid="stSidebar"] .stMarkdown li,
[data-testid="stSidebar"] .stMarkdown h1,
[data-testid="stSidebar"] .stMarkdown h2,
[data-testid="stSidebar"] .stMarkdown h3,
[data-testid="stSidebar"] .stMarkdown h4,
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] span,
[data-testid="stSidebar"] [data-baseweb="radio"] span {
    color: #c9d1d9 !important;
}
[data-testid="stSidebar"] hr {
    border-color: #1e293b !important;
    opacity: 0.4 !important;
}

/* --- main text ------------------------------------------------ */
.stMarkdown p, .stMarkdown li,
.stMarkdown h1, .stMarkdown h2, .stMarkdown h3,
.stMarkdown h4, .stMarkdown h5, .stMarkdown h6 {
    color: #e5e7eb !important;
}
.stMarkdown small, .stMarkdown caption {
    color: #9ca3af !important;
}

/* --- text areas / text inputs --------------------------------- */
.stTextArea textarea, .stTextInput input {
    background-color: #161b22 !important;
    color: #e5e7eb !important;
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
}
.stTextArea textarea:focus, .stTextInput input:focus {
    border-color: #00b4d8 !important;
    box-shadow: 0 0 0 1px #00b4d8 !important;
}

/* --- select boxes / dropdowns --------------------------------- */
.stSelectbox [data-baseweb="select"],
.stMultiSelect [data-baseweb="select"] {
    background-color: #161b22 !important;
    color: #e5e7eb !important;
}
.stSelectbox [data-baseweb="select"] span,
.stMultiSelect [data-baseweb="select"] span {
    color: #e5e7eb !important;
}

/* --- buttons -------------------------------------------------- */
.stButton > button {
    background-color: #161b22 !important;
    color: #e5e7eb !important;
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
    font-weight: 500 !important;
    transition: border-color 0.15s ease, color 0.15s ease !important;
}
.stButton > button:hover {
    border-color: #00b4d8 !important;
    color: #00b4d8 !important;
}
.stFormSubmitButton > button,
.stButton > button[kind="primary"] {
    background-color: #00b4d8 !important;
    color: #0a0e17 !important;
    border: none !important;
    font-weight: 600 !important;
}
.stFormSubmitButton > button:hover,
.stButton > button[kind="primary"]:hover {
    background-color: #0096c7 !important;
}

/* --- forms ---------------------------------------------------- */
[data-testid="stForm"] {
    border: 1px solid #1e293b !important;
    border-radius: 8px !important;
    background-color: #111827 !important;
    padding: 16px !important;
}

/* --- expander ------------------------------------------------- */
details, [data-testid="stExpander"] {
    background-color: #111827 !important;
    border: 1px solid #1e293b !important;
    border-radius: 6px !important;
    margin-bottom: 8px !important;
}
details summary, [data-testid="stExpander"] summary {
    color: #e5e7eb !important;
    font-weight: 500 !important;
}

/* --- metrics -------------------------------------------------- */
[data-testid="stMetric"] {
    background-color: #111827 !important;
    border: 1px solid #1e293b !important;
    border-radius: 6px !important;
    padding: 12px 16px !important;
}
[data-testid="stMetricValue"]  { color: #e5e7eb !important; }
[data-testid="stMetricLabel"] > div { color: #9ca3af !important; }
[data-testid="stMetricDelta"]  { color: #9ca3af !important; }

/* --- file uploader -------------------------------------------- */
[data-testid="stFileUploader"] {
    background-color: #161b22 !important;
    border: 1px dashed #30363d !important;
    border-radius: 6px !important;
}

/* --- code / inline code --------------------------------------- */
code {
    background-color: #161b22 !important;
    color: #00b4d8 !important;
    padding: 2px 6px !important;
    border-radius: 3px !important;
    font-size: 0.85em !important;
}
pre {
    background-color: #161b22 !important;
    border: 1px solid #1e293b !important;
    border-radius: 6px !important;
    padding: 12px !important;
    color: #e5e7eb !important;
}

/* --- tables --------------------------------------------------- */
.stTable { background-color: #111827 !important; }
table { border-color: #1e293b !important; }
th { background-color: #161b22 !important; color: #9ca3af !important; }
td { color: #e5e7eb !important; }

/* --- horizontal rules / dividers ------------------------------ */
hr {
    border-color: #1e293b !important;
    opacity: 0.5 !important;
}

/* --- scrollbar ------------------------------------------------ */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0a0e17; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #484f58; }

/* --- alerts / warnings ---------------------------------------- */
.stAlert, [data-testid="stAlert"] {
    background-color: #111827 !important;
    border: 1px solid #1e293b !important;
}

/* --- JSON viewer inside expanders ----------------------------- */
.json-container, [data-baseweb="json"] {
    background-color: #161b22 !important;
}

/* ================================================================
   END THEME
   ================================================================ */
</style>
"""


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _esc(text: object) -> str:
    """Escape HTML special characters for safe embedding."""
    return _html.escape(str(text))


def risk_color(score: int) -> str:
    """Return a hex colour string for the given 0-100 risk score."""
    if score >= 75:
        return "#ff1744"
    if score >= 50:
        return "#ff9800"
    if score >= 25:
        return "#f59e0b"
    return "#00c853"


def _risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# SVG circular gauge
# ---------------------------------------------------------------------------

def svg_gauge(score: int, level: str, size: int = 130) -> str:
    """Return an inline SVG circular gauge wrapped in a centred <div>."""
    style = RISK_STYLES.get(level, RISK_STYLES["LOW"])
    color = style["color"]
    r = 50
    circumference = 2.0 * math.pi * r
    offset = circumference * (1.0 - max(0.0, min(100.0, float(score))) / 100.0)
    return (
        f'<div style="text-align:center;padding:8px 0;">'
        f'<svg width="{size}" height="{size}" viewBox="0 0 120 120">'
        f'<circle cx="60" cy="60" r="{r}" fill="none" stroke="#1e293b" stroke-width="8"/>'
        f'<circle cx="60" cy="60" r="{r}" fill="none" stroke="{color}" stroke-width="8"'
        f' stroke-dasharray="{circumference:.2f}" stroke-dashoffset="{offset:.2f}"'
        f' transform="rotate(-90 60 60)" stroke-linecap="round"/>'
        f'<text x="60" y="57" text-anchor="middle" fill="{color}"'
        f' font-size="28" font-weight="700" font-family="monospace">{score}</text>'
        f'<text x="60" y="73" text-anchor="middle" fill="#9ca3af"'
        f' font-size="10" font-family="monospace">/ 100</text>'
        f'</svg>'
        f'<div style="color:{color};font-size:13px;font-weight:600;'
        f'margin-top:4px;font-family:monospace;letter-spacing:2px;">{level}</div>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Inline HTML fragments
# ---------------------------------------------------------------------------

def risk_badge(score: int, level: str) -> str:
    s = RISK_STYLES.get(level, RISK_STYLES["LOW"])
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:3px;'
        f'font-family:monospace;font-size:0.8rem;font-weight:600;letter-spacing:1px;'
        f'background:{s["bg"]};color:{s["color"]};'
        f'border:1px solid {s["border"]};">{level}</span>'
    )


def indicator_badges(indicators: list) -> str:
    if not indicators:
        return (
            '<span style="color:#6b7280;font-family:monospace;font-size:0.8rem;">'
            '(none)</span>'
        )
    parts: list[str] = []
    for ind in indicators:
        parts.append(
            f'<span style="display:inline-block;padding:2px 8px;margin:2px;'
            f'border-radius:3px;font-family:monospace;font-size:0.75rem;'
            f'background:#161b22;color:#00b4d8;border:1px solid #1e293b;">'
            f'{_esc(ind)}</span>'
        )
    return " ".join(parts)


def status_pill(text: str, color: str) -> str:
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:3px;'
        f'font-family:monospace;font-size:0.7rem;font-weight:600;letter-spacing:1px;'
        f'background:rgba(0,0,0,0.3);color:{color};'
        f'border:1px solid {color}44;">{_esc(text)}</span>'
    )


# ---------------------------------------------------------------------------
# Structured section rendering (write to Streamlit)
# ---------------------------------------------------------------------------

def section_header(title: str, subtitle: str = "") -> None:
    sub_html = (
        f'<div style="color:#9ca3af;font-size:0.8rem;margin-top:2px;">{_esc(subtitle)}</div>'
        if subtitle else ""
    )
    st.markdown(
        f'<div style="border-bottom:1px solid #1e293b;padding-bottom:8px;margin-bottom:16px;">'
        f'<div style="color:#e5e7eb;font-size:1.1rem;font-weight:600;'
        f'font-family:monospace;letter-spacing:1px;">{_esc(title)}</div>'
        f'{sub_html}'
        f'</div>',
        unsafe_allow_html=True,
    )


def render_risk_header(result: dict) -> None:
    score = result.get("risk_score", 0)
    level = result.get("risk_level", _risk_level(score))
    suspicious = result.get("is_suspicious", False)
    c1, c2 = st.columns([1, 2])
    with c1:
        st.markdown(svg_gauge(score, level), unsafe_allow_html=True)
    with c2:
        status_text = "THREAT DETECTED" if suspicious else "NO THREAT DETECTED"
        status_color = "#ff9800" if suspicious else "#00c853"
        st.markdown(
            f'<div style="padding-top:16px;">'
            f'<div style="color:#9ca3af;font-family:monospace;font-size:0.7rem;'
            f'letter-spacing:2px;margin-bottom:4px;">ASSESSMENT</div>'
            f'<div style="font-size:1.3rem;font-weight:700;color:{status_color};'
            f'font-family:monospace;letter-spacing:1px;">{status_text}</div>'
            f'<div style="margin-top:8px;">{risk_badge(score, level)}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
        scam_type = result.get("scam_type")
        if scam_type and scam_type != "safe":
            st.markdown(
                f'<div style="margin-top:8px;color:#9ca3af;font-family:monospace;'
                f'font-size:0.8rem;">TYPE: <span style="color:#e5e7eb;">'
                f'{_esc(scam_type.replace("_", " ").upper())}</span></div>',
                unsafe_allow_html=True,
            )
        confidence = result.get("confidence", 0)
        ctype = result.get("confidence_type", "heuristic")
        st.markdown(
            f'<div style="margin-top:6px;color:#6b7280;font-family:monospace;'
            f'font-size:0.75rem;">CONFIDENCE: {_esc(str(confidence))}% '
            f'({_esc(ctype)})</div>',
            unsafe_allow_html=True,
        )


def render_summary(result: dict) -> None:
    summary = result.get("summary", "")
    if summary:
        st.markdown(
            f'<div style="background:#111827;border:1px solid #1e293b;border-radius:6px;'
            f'padding:12px 16px;margin:8px 0;color:#e5e7eb;font-size:0.9rem;">'
            f'{_esc(summary)}</div>',
            unsafe_allow_html=True,
        )


def render_indicators(result: dict) -> None:
    section_header("INDICATORS")
    indicators = result.get("indicators", [])
    st.markdown(indicator_badges(indicators), unsafe_allow_html=True)


def render_explanation(result: dict) -> None:
    section_header("EXPLANATION")
    entries = result.get("explanation", [])
    if not entries:
        st.markdown(
            '<span style="color:#6b7280;font-family:monospace;font-size:0.8rem;">'
            'No risk explanations.</span>',
            unsafe_allow_html=True,
        )
        return
    rows: list[str] = []
    for entry in entries:
        severity = (entry.get("severity") or "low").lower()
        sev_color = {
            "critical": "#ff1744", "high": "#ff9800",
            "medium": "#f59e0b", "low": "#6b7280",
        }.get(severity, "#6b7280")
        score_val = entry.get("score", 0)
        reason = _esc(entry.get("reason", ""))
        evidence = entry.get("evidence", "")
        ev_html = (
            f' <span style="color:#6b7280;font-size:0.8rem;">'
            f'[{_esc(evidence)}]</span>'
            if evidence else ""
        )
        rows.append(
            f'<div style="padding:6px 0;border-bottom:1px solid #1e293b22;display:flex;'
            f'gap:8px;align-items:baseline;">'
            f'<span style="color:{sev_color};font-family:monospace;font-size:0.7rem;'
            f'min-width:60px;text-transform:uppercase;">{_esc(severity)}</span>'
            f'<span style="color:#00b4d8;font-family:monospace;font-size:0.75rem;'
            f'min-width:32px;">+{score_val:.0f}</span>'
            f'<span style="color:#e5e7eb;font-size:0.85rem;">{reason}{ev_html}</span>'
            f'</div>'
        )
    st.markdown("".join(rows), unsafe_allow_html=True)


def render_recommendations(result: dict) -> None:
    section_header("RECOMMENDATIONS")
    recs = result.get("recommendations", [])
    if not recs:
        st.markdown(
            '<span style="color:#6b7280;font-family:monospace;font-size:0.8rem;">'
            'No recommendations.</span>',
            unsafe_allow_html=True,
        )
        return
    rows: list[str] = []
    for rec in recs:
        rows.append(
            f'<div style="padding:5px 0;color:#e5e7eb;font-size:0.85rem;'
            f'border-bottom:1px solid #1e293b22;">'
            f'<span style="color:#00b4d8;margin-right:6px;">&#9656;</span>'
            f'{_esc(rec)}</div>'
        )
    st.markdown("".join(rows), unsafe_allow_html=True)


def render_evidence(result: dict) -> None:
    section_header("EVIDENCE")
    evidence = result.get("evidence", {})
    if not evidence:
        st.markdown(
            '<span style="color:#6b7280;font-family:monospace;font-size:0.8rem;">'
            'No evidence available.</span>',
            unsafe_allow_html=True,
        )
        return
    rows: list[str] = []
    for key, value in evidence.items():
        if isinstance(value, list):
            val_str = ", ".join(str(v) for v in value)
        elif isinstance(value, dict):
            parts = []
            for k, v in value.items():
                parts.append(f"{k}: {v}")
            val_str = "; ".join(parts)
        else:
            val_str = str(value)
        rows.append(
            f'<div style="padding:4px 0;border-bottom:1px solid #1e293b22;display:flex;gap:8px;">'
            f'<span style="color:#9ca3af;font-family:monospace;font-size:0.75rem;'
            f'min-width:120px;">{_esc(key)}</span>'
            f'<span style="color:#e5e7eb;font-size:0.85rem;word-break:break-all;">'
            f'{_esc(val_str)}</span></div>'
        )
    st.markdown("".join(rows), unsafe_allow_html=True)


def render_warnings(result: dict) -> None:
    warnings = result.get("warnings", [])
    if warnings:
        combined = " ".join(str(w) for w in warnings)
        st.markdown(
            f'<div style="background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);'
            f'border-radius:6px;padding:10px 14px;margin:8px 0;'
            f'color:#f59e0b;font-size:0.8rem;font-family:monospace;">'
            f'{_esc(combined)}</div>',
            unsafe_allow_html=True,
        )


def render_ml_section(result: dict) -> None:
    engine_results = result.get("engine_results", {})
    ml = engine_results.get("ml_analysis")
    if not ml:
        return
    section_header("LOCAL ML INTELLIGENCE")
    available = ml.get("model_available", False)
    if not available:
        st.markdown(
            '<span style="color:#6b7280;font-family:monospace;font-size:0.8rem;">'
            'ML model unavailable.</span>',
            unsafe_allow_html=True,
        )
        warning = ml.get("warning")
        if warning:
            st.markdown(
                f'<div style="color:#9ca3af;font-size:0.8rem;margin-top:4px;">'
                f'{_esc(warning)}</div>',
                unsafe_allow_html=True,
            )
        return
    pred = ml.get("prediction", "-")
    pred_color = "#ff9800" if pred == "scam" else "#00c853"
    score_val = ml.get("score")
    confidence = ml.get("confidence")
    ctype = ml.get("confidence_type", "-")
    model = ml.get("model", "-")
    features = ml.get("features_used", "-")
    rows = [
        f'<div style="background:#111827;border:1px solid #1e293b;border-radius:6px;padding:12px 16px;">',
        f'<div style="display:flex;gap:24px;flex-wrap:wrap;">',
        f'<div><span style="color:#9ca3af;font-family:monospace;font-size:0.7rem;'
        f'letter-spacing:1px;">PREDICTION</span><br/>'
        f'<span style="color:{pred_color};font-size:1.1rem;font-weight:700;'
        f'font-family:monospace;">{_esc(str(pred).upper())}</span></div>',
        f'<div><span style="color:#9ca3af;font-family:monospace;font-size:0.7rem;'
        f'letter-spacing:1px;">ML SCORE</span><br/>'
        f'<span style="color:#e5e7eb;font-size:1.1rem;font-weight:700;'
        f'font-family:monospace;">{_esc(str(score_val))}/100</span></div>',
        f'<div><span style="color:#9ca3af;font-family:monospace;font-size:0.7rem;'
        f'letter-spacing:1px;">CONFIDENCE</span><br/>'
        f'<span style="color:#e5e7eb;font-size:1.1rem;font-weight:700;'
        f'font-family:monospace;">{_esc(str(confidence))}%</span></div>',
        f'<div><span style="color:#9ca3af;font-family:monospace;font-size:0.7rem;'
        f'letter-spacing:1px;">TYPE</span><br/>'
        f'<span style="color:#e5e7eb;font-size:0.85rem;'
        f'font-family:monospace;">{_esc(ctype)}</span></div>',
        f'</div>',
        f'<div style="margin-top:8px;color:#6b7280;font-family:monospace;font-size:0.7rem;">'
        f'MODEL: {_esc(str(model))} | FEATURES: {_esc(str(features))}</div>',
        f'<div style="margin-top:6px;color:#6b7280;font-size:0.75rem;">'
        f'ML evidence is separate from the deterministic security verdict.</div>',
        f'</div>',
    ]
    st.markdown("".join(rows), unsafe_allow_html=True)


def render_engine_results(result: dict) -> None:
    engine_results = result.get("engine_results", {})
    if not engine_results:
        return
    with st.expander("RAW ENGINE RESULTS", expanded=False):
        st.json(engine_results)


# ---------------------------------------------------------------------------
# Full result renderer (common section for all scanners)
# ---------------------------------------------------------------------------

def render_full_result(result: dict, *, show_ml: bool = False) -> None:
    if not result.get("success", False):
        error = result.get("error", "Analysis failed.")
        error_type = result.get("error_type", "unknown")
        st.markdown(
            f'<div style="background:rgba(255,23,68,0.08);border:1px solid rgba(255,23,68,0.2);'
            f'border-radius:6px;padding:16px;margin:8px 0;">'
            f'<div style="color:#ff1744;font-weight:600;font-family:monospace;'
            f'letter-spacing:1px;margin-bottom:4px;">ERROR: {_esc(error_type.upper())}</div>'
            f'<div style="color:#e5e7eb;font-size:0.9rem;">{_esc(error)}</div></div>',
            unsafe_allow_html=True,
        )
        render_recommendations(result)
        return
    render_risk_header(result)
    st.markdown('<div style="height:8px;"></div>', unsafe_allow_html=True)
    render_summary(result)
    render_indicators(result)
    render_explanation(result)
    render_recommendations(result)
    render_evidence(result)
    render_warnings(result)
    if show_ml:
        render_ml_section(result)
    render_engine_results(result)


# ---------------------------------------------------------------------------
# Chain visualization
# ---------------------------------------------------------------------------

def chain_flow_html(stages: list, relationships: list, pattern: str | None = None) -> str:
    """Return an inline-HTML vertical attack-chain flowchart."""
    rel_map: dict[tuple[int, int], dict] = {}
    for rel in relationships:
        key = (rel.get("source_idx", -1), rel.get("dest_idx", -1))
        rel_map[key] = rel

    parts: list[str] = [
        '<div style="display:flex;flex-direction:column;align-items:center;'
        'gap:0;padding:1rem;">'
    ]

    if pattern:
        parts.append(
            f'<div style="color:#00b4d8;font-family:monospace;font-size:0.8rem;'
            f'letter-spacing:2px;margin-bottom:12px;text-transform:uppercase;">'
            f'PATTERN: {_esc(pattern.replace("_", " "))}</div>'
        )

    for idx, stage in enumerate(stages):
        score = stage.get("risk_score", 0)
        level = stage.get("risk_level", _risk_level(score))
        stype = stage.get("type", "unknown")
        is_suspicious = stage.get("is_suspicious", False)
        style = RISK_STYLES.get(level, RISK_STYLES["LOW"])
        border_color = style["color"] if is_suspicious else "#30363d"
        scam_type = stage.get("scam_type", "")
        scam_line = (
            f'<div style="color:#9ca3af;font-family:monospace;font-size:0.7rem;'
            f'margin-top:2px;">{_esc(scam_type.replace("_", " ").upper() if scam_type else "")}</div>'
            if scam_type and scam_type != "safe" else ""
        )
        parts.append(
            f'<div style="background:#111827;border:1px solid {border_color};'
            f'border-radius:6px;padding:10px 20px;min-width:220px;max-width:300px;'
            f'text-align:center;margin:4px 0;">'
            f'<div style="color:#6b7280;font-family:monospace;font-size:0.65rem;'
            f'letter-spacing:1px;">STAGE {idx + 1} &mdash; {_esc(stype.upper())}</div>'
            f'<div style="color:{style["color"]};font-family:monospace;font-size:0.95rem;'
            f'font-weight:700;margin-top:4px;">{score} / 100 {_esc(level)}</div>'
            f'{scam_line}'
            f'</div>'
        )

        if idx < len(stages) - 1:
            key = (idx, idx + 1)
            rel = rel_map.get(key)
            if rel:
                rel_label = rel.get("label", rel.get("relation", ""))
                strength = rel.get("strength", 0)
                match_type = rel.get("match_type", "")
                parts.append(
                    f'<div style="display:flex;flex-direction:column;align-items:center;'
                    f'padding:2px 0;">'
                    f'<div style="color:#30363d;font-size:1.2rem;line-height:1;">&#8595;</div>'
                    f'<div style="color:#6b7280;font-family:monospace;font-size:0.6rem;'
                    f'text-transform:uppercase;max-width:240px;text-align:center;">'
                    f'{_esc(rel_label)}'
                    f'{" [" + _esc(match_type) + "]" if match_type else ""}'
                    f'{" (strength: " + str(round(strength, 2)) + ")" if strength else ""}'
                    f'</div></div>'
                )
            else:
                parts.append(
                    f'<div style="padding:2px 0;">'
                    f'<div style="color:#1e293b;font-size:1.2rem;line-height:1;">&#8595;</div>'
                    f'</div>'
                )

    parts.append("</div>")
    return "\n".join(parts)


def render_chain_verdict(result: dict) -> None:
    classification = result.get("classification", "none")
    chain_pattern = result.get("chain_pattern")
    score = result.get("risk_score", 0)
    level = result.get("risk_level", _risk_level(score))

    if classification == "multi_stage_scam":
        verdict_color = "#ff1744"
        verdict_text = "MULTI-STAGE SCAM DETECTED"
    elif classification == "potential_chain":
        verdict_color = "#f59e0b"
        verdict_text = "POTENTIAL CHAIN"
    else:
        verdict_color = "#00c853"
        verdict_text = "NO CHAIN DETECTED"

    st.markdown(
        f'<div style="text-align:center;padding:12px 0;">'
        f'<div style="color:#9ca3af;font-family:monospace;font-size:0.7rem;'
        f'letter-spacing:2px;">CHAIN CLASSIFICATION</div>'
        f'<div style="color:{verdict_color};font-size:1.4rem;font-weight:700;'
        f'font-family:monospace;letter-spacing:2px;margin-top:4px;">'
        f'{verdict_text}</div>'
        f'{f"""<div style="margin-top:8px;">{risk_badge(score, level)}</div>""" if score else ""}'
        f'</div>',
        unsafe_allow_html=True,
    )

    stages = result.get("stages", [])
    relationships = result.get("relationships", [])
    st.markdown(chain_flow_html(stages, relationships, chain_pattern), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# URL intelligence detail panel
# ---------------------------------------------------------------------------

def render_url_intelligence(result: dict) -> None:
    evidence = result.get("evidence", {})
    if not evidence or evidence.get("source") != "url":
        return
    section_header("URL INTELLIGENCE")
    fields = [
        ("hostname", evidence.get("url_hostname")),
        ("root_domain", evidence.get("url_root_domain")),
        ("subdomains", evidence.get("url_subdomains")),
        ("scheme", evidence.get("url_scheme")),
        ("port", evidence.get("url_port")),
        ("path", evidence.get("url_path")),
        ("query", evidence.get("url_query")),
        ("fragment", evidence.get("url_fragment")),
        ("tld", evidence.get("url_tld")),
    ]
    rows: list[str] = []
    for label, value in fields:
        if value is None or value == "":
            continue
        rows.append(
            f'<div style="padding:4px 0;border-bottom:1px solid #1e293b22;display:flex;gap:8px;">'
            f'<span style="color:#9ca3af;font-family:monospace;font-size:0.75rem;'
            f'min-width:110px;">{_esc(label)}</span>'
            f'<span style="color:#e5e7eb;font-size:0.85rem;word-break:break-all;">'
            f'{_esc(str(value))}</span></div>'
        )
    if rows:
        st.markdown("".join(rows), unsafe_allow_html=True)
    urls = evidence.get("urls", [])
    domains = evidence.get("domains", [])
    if urls:
        st.markdown(
            '<div style="margin-top:8px;color:#9ca3af;font-family:monospace;font-size:0.7rem;'
            'letter-spacing:1px;">DETECTED URLS</div>',
            unsafe_allow_html=True,
        )
        for u in urls:
            st.markdown(
                f'<div style="color:#00b4d8;font-family:monospace;font-size:0.8rem;'
                f'padding:2px 0;word-break:break-all;">{_esc(str(u))}</div>',
                unsafe_allow_html=True,
            )
    if domains:
        st.markdown(
            '<div style="margin-top:8px;color:#9ca3af;font-family:monospace;font-size:0.7rem;'
            'letter-spacing:1px;">DOMAINS</div>',
            unsafe_allow_html=True,
        )
        for d in domains:
            st.markdown(
                f'<div style="color:#e5e7eb;font-family:monospace;font-size:0.8rem;'
                f'padding:2px 0;">{_esc(str(d))}</div>',
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# QR decoded-content detail panel
# ---------------------------------------------------------------------------

def render_qr_detail(result: dict) -> None:
    status = result.get("status", "")
    content_type = result.get("content_type", "")
    decoded = result.get("decoded_content")
    if decoded is not None:
        st.markdown(
            f'<div style="margin-top:8px;"><span style="color:#9ca3af;'
            f'font-family:monospace;font-size:0.7rem;letter-spacing:1px;">'
            f'DECODED CONTENT</span><br/>'
            f'<code style="font-size:0.85rem;">{_esc(str(decoded))}</code></div>',
            unsafe_allow_html=True,
        )
    codes = result.get("codes")
    if codes and len(codes) > 1:
        st.markdown(
            f'<div style="margin-top:8px;"><span style="color:#9ca3af;'
            f'font-family:monospace;font-size:0.7rem;letter-spacing:1px;">'
            f'DECODED PAYLOADS ({len(codes)})</span></div>',
            unsafe_allow_html=True,
        )
        for i, code in enumerate(codes):
            st.markdown(
                f'<div style="color:#e5e7eb;font-family:monospace;font-size:0.8rem;'
                f'padding:2px 0 2px 12px;border-left:2px solid #1e293b;">'
                f'{i + 1}. {_esc(str(code))}</div>',
                unsafe_allow_html=True,
            )
    url_analysis = result.get("url_analysis")
    if url_analysis and isinstance(url_analysis, dict):
        st.markdown('<hr/>', unsafe_allow_html=True)
        render_url_intelligence(url_analysis)
    upi_analysis = result.get("upi_analysis")
    if upi_analysis and isinstance(upi_analysis, dict):
        st.markdown(
            '<div style="margin-top:12px;"><span style="color:#9ca3af;'
            'font-family:monospace;font-size:0.7rem;letter-spacing:1px;">'
            'PAYMENT DESTINATION</span></div>',
            unsafe_allow_html=True,
        )
        upi_parse = upi_analysis.get("parse", {})
        upi_fields = [
            ("Payee Name", upi_parse.get("payee_name")),
            ("UPI ID", upi_parse.get("payee_address")),
            ("Amount", upi_parse.get("amount")),
            ("Currency", upi_parse.get("currency")),
            ("Note", upi_parse.get("transaction_note")),
            ("Merchant Code", upi_parse.get("merchant_code")),
        ]
        for label, value in upi_fields:
            if value is None or value == "":
                continue
            st.markdown(
                f'<div style="padding:3px 0;display:flex;gap:8px;">'
                f'<span style="color:#9ca3af;font-family:monospace;font-size:0.75rem;'
                f'min-width:110px;">{_esc(label)}</span>'
                f'<span style="color:#e5e7eb;font-size:0.85rem;">{_esc(str(value))}</span></div>',
                unsafe_allow_html=True,
            )
    message_analysis = result.get("message_analysis")
    if message_analysis and isinstance(message_analysis, dict):
        st.markdown('<hr/>', unsafe_allow_html=True)
        st.markdown(
            '<div style="color:#9ca3af;font-family:monospace;font-size:0.7rem;'
            'letter-spacing:1px;">TEXT ANALYSIS</div>',
            unsafe_allow_html=True,
        )
        mtype = message_analysis.get("scam_type", "-")
        mrisk = message_analysis.get("risk_level", "-")
        minds = message_analysis.get("detected_indicators", [])
        st.markdown(
            f'<div style="padding:4px 0;">'
            f'<span style="color:#e5e7eb;font-size:0.85rem;">Type: {_esc(str(mtype))}</span>'
            f'&nbsp;&nbsp;{risk_badge(message_analysis.get("risk_score", 0), mrisk)}</div>',
            unsafe_allow_html=True,
        )
        if minds:
            st.markdown(indicator_badges(minds), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# UPI detail panel
# ---------------------------------------------------------------------------

def render_upi_detail(result: dict) -> None:
    evidence = result.get("evidence", {})
    if not evidence or evidence.get("source") != "upi":
        return
    section_header("UPI PAYMENT DESTINATION")
    upi = evidence.get("upi", {})
    if not upi:
        return
    fields = [
        ("Payee Address", upi.get("payee_address")),
        ("Payee Name", upi.get("payee_name")),
        ("Amount", upi.get("amount")),
        ("Currency", upi.get("currency")),
        ("Transaction Note", upi.get("transaction_note")),
        ("Merchant Code", upi.get("merchant_code")),
        ("Transaction Ref", upi.get("transaction_ref")),
        ("Valid UPI", upi.get("valid_upi")),
    ]
    rows: list[str] = []
    for label, value in fields:
        if value is None or value == "":
            continue
        rows.append(
            f'<div style="padding:4px 0;border-bottom:1px solid #1e293b22;display:flex;gap:8px;">'
            f'<span style="color:#9ca3af;font-family:monospace;font-size:0.75rem;'
            f'min-width:120px;">{_esc(label)}</span>'
            f'<span style="color:#e5e7eb;font-size:0.85rem;">{_esc(str(value))}</span></div>'
        )
    if rows:
        st.markdown("".join(rows), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Session history helpers
# ---------------------------------------------------------------------------

def add_history_entry(
    input_type: str,
    risk_score: int,
    risk_level: str,
    scam_type: str | None,
    is_suspicious: bool,
    label: str = "",
) -> None:
    from datetime import datetime
    history = st.session_state.get("history", [])
    history.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": input_type.upper(),
        "score": risk_score,
        "level": risk_level,
        "scam_type": scam_type or "-",
        "suspicious": is_suspicious,
        "label": label[:40] if label else "",
    })
    st.session_state["history"] = history


def render_history_sidebar() -> None:
    history = st.session_state.get("history", [])
    st.sidebar.markdown(
        '<div style="color:#9ca3af;font-family:monospace;font-size:0.7rem;'
        'letter-spacing:2px;margin-bottom:8px;">SESSION HISTORY</div>',
        unsafe_allow_html=True,
    )
    if not history:
        st.sidebar.markdown(
            '<div style="color:#6b7280;font-size:0.8rem;">No scans in current session</div>',
            unsafe_allow_html=True,
        )
        return
    rows: list[str] = []
    for entry in reversed(history[-20:]):
        level = entry.get("level", "LOW")
        style = RISK_STYLES.get(level, RISK_STYLES["LOW"])
        rows.append(
            f'<div style="padding:4px 0;border-bottom:1px solid #1e293b33;'
            f'display:flex;gap:6px;align-items:center;">'
            f'<span style="color:#6b7280;font-family:monospace;font-size:0.65rem;'
            f'min-width:52px;">{_esc(entry.get("time", ""))}</span>'
            f'<span style="color:#00b4d8;font-family:monospace;font-size:0.65rem;'
            f'min-width:50px;">{_esc(entry.get("type", ""))}</span>'
            f'<span style="color:{style["color"]};font-family:monospace;font-size:0.7rem;'
            f'font-weight:600;min-width:24px;">{entry.get("score", 0)}</span>'
            f'</div>'
        )
    st.sidebar.markdown("".join(rows), unsafe_allow_html=True)
    total = len(history)
    suspicious = sum(1 for e in history if e.get("suspicious"))
    st.sidebar.markdown(
        f'<div style="margin-top:8px;color:#6b7280;font-family:monospace;font-size:0.7rem;">'
        f'{total} scan(s) | {suspicious} flagged</div>',
        unsafe_allow_html=True,
    )
    if st.sidebar.button("Clear Session History", use_container_width=True):
        st.session_state["history"] = []
        st.rerun()
