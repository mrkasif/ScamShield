#!/usr/bin/env python3
"""Generate app/ui.py - run once with: python scripts/gen_ui.py"""
import pathlib, textwrap

UI_PY = r'''"""ScamShield Command Center - Streamlit Frontend.

Launch:   streamlit run app/ui.py

Every scan result comes from the real ScamShield analysis functions.
No hardcoded risk scores, no fake indicators, no fabricated history.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import streamlit as st

_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from scamshield import analyze, analyze_chain
from app.ui_helpers import (
    CSS_THEME, COLORS, RISK_STYLES, _risk_level, _esc,
    svg_gauge, risk_badge, risk_color, indicator_badges,
    status_pill, section_header, render_full_result,
    render_url_intelligence, render_qr_detail, render_upi_detail,
    chain_flow_html, render_chain_verdict, render_explanation,
    render_history_sidebar, add_history_entry,
)

st.set_page_config(
    page_title="ScamShield",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)
st.markdown(CSS_THEME, unsafe_allow_html=True)


def _init_state() -> None:
    defaults = {
        "nav": "Overview", "history": [], "message_result": None,
        "url_result": None, "upi_result": None, "chain_stages": [],
        "chain_result": None, "qr_result": None,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val

_init_state()


def _render_sidebar() -> str:
    with st.sidebar:
        st.markdown(
            '<div style="padding:4px 0 12px 0;border-bottom:1px solid #1e293b;">'
            '<div style="color:#00b4d8;font-family:monospace;font-size:1.1rem;'
            'font-weight:700;letter-spacing:3px;">SCAMSHIELD</div>'
            '<div style="color:#6b7280;font-family:monospace;font-size:0.65rem;'
            'margin-top:2px;">Indian Digital Scam Intelligence</div></div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div style="height:12px;"></div>', unsafe_allow_html=True)
        nav_options = ["Overview", "Message", "URL", "QR", "UPI", "Attack Chain"]
        nav = st.radio("Navigation", nav_options,
                        index=nav_options.index(st.session_state.nav),
                        label_visibility="collapsed")
        st.session_state.nav = nav
        st.markdown('<div style="height:8px;"></div>', unsafe_allow_html=True)
        st.markdown('<hr/>', unsafe_allow_html=True)
        render_history_sidebar()
        st.markdown('<div style="height:12px;"></div>', unsafe_allow_html=True)
        st.markdown('<hr/>', unsafe_allow_html=True)
        try:
            import scamshield as _ss
            version = getattr(_ss, "__version__", "0.3.0")
        except Exception:
            version = "?"
        from app.ui_helpers import _ML_AVAILABLE
        st.markdown(
            '<div style="color:#6b7280;font-family:monospace;font-size:0.65rem;'
            'letter-spacing:1px;">SYSTEM</div>'
            '<div style="margin-top:4px;display:flex;gap:8px;flex-wrap:wrap;">'
            + status_pill("LOCAL ENGINE", "#00c853")
            + status_pill("OFFLINE", "#00c853")
            + status_pill("ML " + ("READY" if _ML_AVAILABLE else "N/A"),
                           "#00b4d8" if _ML_AVAILABLE else "#6b7280")
            + '</div>'
            '<div style="margin-top:6px;color:#4b5563;font-family:monospace;font-size:0.6rem;">'
            'v' + _esc(version) + '</div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div style="height:12px;"></div>', unsafe_allow_html=True)
        st.markdown(
            '<div style="background:#111827;border:1px solid #1e293b;border-radius:6px;'
            'padding:10px 12px;">'
            '<div style="color:#9ca3af;font-family:monospace;font-size:0.65rem;'
            'letter-spacing:1px;margin-bottom:4px;">LOCAL-FIRST ANALYSIS</div>'
            '<div style="color:#6b7280;font-size:0.7rem;line-height:1.4;">'
            'ScamShield analyzes locally. It does not open URLs, '
            'contact external APIs, execute attachments, or send '
            'content to external services.</div></div>',
            unsafe_allow_html=True,
        )
    return nav


def _render_header() -> None:
    st.markdown(
        '<div style="padding:0 0 12px 0;border-bottom:1px solid #1e293b;margin-bottom:16px;">'
        '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;">'
        '<div>'
        '<span style="color:#00b4d8;font-family:monospace;font-size:1.6rem;'
        'font-weight:700;letter-spacing:4px;">SCAMSHIELD</span>'
        '<span style="color:#6b7280;font-family:monospace;font-size:0.8rem;'
        'margin-left:12px;">Indian Digital Scam Intelligence &amp; Prevention System</span>'
        '</div></div></div>',
        unsafe_allow_html=True,
    )


def _render_overview() -> None:
    section_header("COMMAND CENTER OVERVIEW")
    st.markdown(
        '<div style="color:#9ca3af;font-size:0.85rem;margin-bottom:16px;">'
        'Select a scanner from the sidebar, or use a quick action below.</div>',
        unsafe_allow_html=True,
    )
    from app.ui_helpers import _ML_AVAILABLE
    capabilities = [
        ("MESSAGE INTELLIGENCE", "Multilingual scam detection with Hinglish support", True),
        ("URL INTELLIGENCE", "Structural phishing indicator analysis", True),
        ("QR SECURITY", "QR decode, URL/UPI/text routing, multi-code support", True),
        ("UPI ANALYSIS", "Payment destination risk assessment", True),
        ("LOCAL ML", "TF-IDF + Logistic Regression baseline classifier", _ML_AVAILABLE),
        ("ATTACK CHAIN", "Multi-stage scam correlation and pattern detection", True),
    ]
    rows_html = []
    for i in range(0, len(capabilities), 3):
        cols = []
        for title, desc, ok in capabilities[i:i + 3]:
            color = "#00c853" if ok else "#6b7280"
            label = "OPERATIONAL" if ok else "N/A"
            cols.append(
                '<div style="background:#111827;border:1px solid #1e293b;border-radius:6px;'
                'padding:14px 16px;flex:1;min-width:200px;">'
                '<div style="color:#00b4d8;font-family:monospace;font-size:0.7rem;'
                'letter-spacing:1px;margin-bottom:6px;">' + _esc(title) + '</div>'
                '<div style="color:#9ca3af;font-size:0.8rem;line-height:1.4;">'
                + _esc(desc) + '</div>'
                '<div style="margin-top:8px;">'
                + status_pill(label, color) + '</div></div>'
            )
        rows_html.append(
            '<div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap;">'
            + "".join(cols) + '</div>'
        )
    st.markdown("".join(rows_html), unsafe_allow_html=True)
    st.markdown('<div style="height:16px;"></div>', unsafe_allow_html=True)

    history = st.session_state.get("history", [])
    section_header("SESSION STATISTICS")
    if not history:
        st.markdown(
            '<div style="color:#6b7280;font-family:monospace;font-size:0.85rem;">'
            'No scans in current session</div>',
            unsafe_allow_html=True,
        )
    else:
        total = len(history)
        flagged = sum(1 for e in history if e.get("suspicious"))
        critical = sum(1 for e in history if e.get("level") == "CRITICAL")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Total Scans", total)
        with c2:
            st.metric("Flagged", flagged)
        with c3:
            st.metric("Critical", critical)

    st.markdown('<div style="height:16px;"></div>', unsafe_allow_html=True)
    section_header("QUICK ACTIONS")
    c1, c2, c3, c4, c5 = st.columns(5)
    for col, label, nav in zip(
        [c1, c2, c3, c4, c5],
        ["Analyze Message", "Analyze URL", "Analyze QR", "Analyze UPI", "Build Attack Chain"],
        ["Message", "URL", "QR", "UPI", "Attack Chain"],
    ):
        with col:
            if st.button(label, use_container_width=True):
                st.session_state.nav = nav
                st.rerun()


def _render_message() -> None:
    section_header("MESSAGE SCANNER", "Analyze SMS, chat messages, or text for scam indicators")
    with st.form("message_form", clear_on_submit=False):
        text = st.text_area("Message", height=140,
                            placeholder="Paste or type an SMS, WhatsApp, or chat message here...",
                            label_visibility="collapsed")
        c1, c2, _ = st.columns([1, 1, 4])
        with c1:
            submitted = st.form_submit_button("Analyze Message", use_container_width=True)
        with c2:
            clear = st.form_submit_button("Clear", use_container_width=True)
    if clear:
        st.session_state.message_result = None
        st.rerun()
    if submitted and text and text.strip():
        with st.spinner("Analyzing..."):
            result = analyze("message", text.strip())
        st.session_state.message_result = result
        add_history_entry("message", result.get("risk_score", 0),
                          result.get("risk_level", "LOW"), result.get("scam_type"),
                          result.get("is_suspicious", False), text.strip()[:60])
    result = st.session_state.message_result
    if result is not None:
        render_full_result(result, show_ml=True)
        urls = result.get("evidence", {}).get("urls", [])
        if urls:
            st.markdown('<div style="height:8px;"></div>', unsafe_allow_html=True)
            section_header("EXTRACTED URLS")
            for u in urls:
                st.markdown(
                    '<div style="padding:4px 0;color:#00b4d8;font-family:monospace;'
                    'font-size:0.85rem;word-break:break-all;">' + _esc(str(u)) + '</div>',
                    unsafe_allow_html=True,
                )


def _render_url() -> None:
    section_header("URL SCANNER", "Static structural analysis - the link is never opened")
    with st.form("url_form", clear_on_submit=False):
        url = st.text_input("URL", placeholder="https://example.com/suspicious-path",
                            label_visibility="collapsed")
        c1, c2, _ = st.columns([1, 1, 4])
        with c1:
            submitted = st.form_submit_button("Analyze URL", use_container_width=True)
        with c2:
            clear = st.form_submit_button("Clear", use_container_width=True)
    if clear:
        st.session_state.url_result = None
        st.rerun()
    if submitted and url and url.strip():
        with st.spinner("Analyzing..."):
            result = analyze("url", url.strip())
        st.session_state.url_result = result
        add_history_entry("url", result.get("risk_score", 0),
                          result.get("risk_level", "LOW"), result.get("scam_type"),
                          result.get("is_suspicious", False), url.strip()[:60])
    result = st.session_state.url_result
    if result is not None:
        render_full_result(result)
        render_url_intelligence(result)
    st.markdown(
        '<div style="margin-top:16px;background:#111827;border:1px solid #1e293b;'
        'border-radius:6px;padding:10px 14px;color:#6b7280;font-family:monospace;'
        'font-size:0.75rem;">'
        'URLs are analyzed locally and are never opened by ScamShield.</div>',
        unsafe_allow_html=True,
    )


def _render_qr() -> None:
    section_header("QR SCANNER", "Decode and analyze QR images locally - nothing is executed")
    uploaded = st.file_uploader("Upload QR code image",
                                type=["png", "jpg", "jpeg", "webp"],
                                label_visibility="collapsed")
    if uploaded:
        st.image(uploaded, width=200, caption="Uploaded QR")
        col_a, col_b = st.columns(2)
        with col_a:
            analyze_clicked = st.button("Analyze QR", use_container_width=True)
        with col_b:
            clear_clicked = st.button("Clear", use_container_width=True)
        if clear_clicked:
            st.session_state.qr_result = None
            st.rerun()
        if analyze_clicked:
            suffix = Path(uploaded.name).suffix if uploaded.name else ".png"
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(uploaded.read())
                    tmp_path = tmp.name
                with st.spinner("Decoding and analyzing..."):
                    result = analyze("qr", tmp_path)
                st.session_state.qr_result = result
                add_history_entry("qr", result.get("risk_score", 0),
                                  result.get("risk_level", "LOW"), result.get("scam_type"),
                                  result.get("is_suspicious", False), uploaded.name or "qr")
            finally:
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
    result = st.session_state.qr_result
    if result is not None:
        status = result.get("status", "DECODED")
        content_type = result.get("content_type", "unknown")
        if status in ("NOT DECODED", "ERROR"):
            st.markdown(
                '<div style="background:rgba(255,23,68,0.08);border:1px solid rgba(255,23,68,0.2);'
                'border-radius:6px;padding:12px 16px;margin:8px 0;color:#ff1744;'
                'font-family:monospace;">' + _esc(status) + '</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div style="color:#9ca3af;font-family:monospace;font-size:0.7rem;'
                'letter-spacing:1px;margin-bottom:4px;">CONTENT TYPE: '
                '<span style="color:#00b4d8;">' + _esc(content_type.upper())
                + '</span></div>',
                unsafe_allow_html=True,
            )
        render_full_result(result)
        render_qr_detail(result)


def _render_upi() -> None:
    section_header("UPI SCANNER", "Analyze a UPI payment URI - payments are never executed")
    with st.form("upi_form", clear_on_submit=False):
        upi_uri = st.text_input("UPI URI",
                                placeholder="upi://pay?pa=merchant@example&pn=Merchant&am=100",
                                label_visibility="collapsed")
        c1, c2, _ = st.columns([1, 1, 4])
        with c1:
            submitted = st.form_submit_button("Analyze UPI", use_container_width=True)
        with c2:
            clear = st.form_submit_button("Clear", use_container_width=True)
    if clear:
        st.session_state.upi_result = None
        st.rerun()
    if submitted and upi_uri and upi_uri.strip():
        with st.spinner("Analyzing..."):
            result = analyze("upi", upi_uri.strip())
        st.session_state.upi_result = result
        add_history_entry("upi", result.get("risk_score", 0),
                          result.get("risk_level", "LOW"), result.get("scam_type"),
                          result.get("is_suspicious", False), upi_uri.strip()[:60])
    result = st.session_state.upi_result
    if result is not None:
        render_full_result(result)
        render_upi_detail(result)
    st.markdown(
        '<div style="margin-top:16px;background:#111827;border:1px solid #1e293b;'
        'border-radius:6px;padding:10px 14px;color:#6b7280;font-family:monospace;'
        'font-size:0.75rem;">'
        'UPI URIs are analyzed locally. No payment is ever executed.</div>',
        unsafe_allow_html=True,
    )


def _render_attack_chain() -> None:
    section_header(
        "ATTACK CHAIN WORKSPACE",
        "Build multi-stage scam chains from independently analyzed artifacts",
    )
    stages = st.session_state.chain_stages

    if stages:
        section_header("CURRENT STAGES")
        for idx, stage in enumerate(stages):
            r = stage.get("result", {})
            score = r.get("risk_score", 0)
            level = r.get("risk_level", "LOW")
            style = RISK_STYLES.get(level, RISK_STYLES["LOW"])
            st.markdown(
                '<div style="background:#111827;border:1px solid ' + style["color"] + '44;'
                'border-radius:6px;padding:8px 14px;margin:4px 0;display:flex;'
                'align-items:center;justify-content:space-between;">'
                '<div>'
                '<span style="color:#6b7280;font-family:monospace;font-size:0.65rem;'
                'letter-spacing:1px;">STAGE ' + str(idx + 1) + ' - '
                + _esc(stage["type"].upper()) + '</span>'
                '<span style="color:' + style["color"] + ';font-family:monospace;'
                'font-size:0.85rem;font-weight:600;margin-left:12px;">'
                + str(score) + '/100 ' + _esc(level) + '</span>'
                '</div></div>',
                unsafe_allow_html=True,
            )
            st.markdown(
                '<div style="color:#6b7280;font-size:0.8rem;padding:2px 0 2px 14px;">'
                + _esc(r.get("summary", "")) + '</div>',
                unsafe_allow_html=True,
            )

        build_col, clear_col, _ = st.columns([1, 1, 4])
        with build_col:
            if st.button("Build Attack Chain", type="primary", use_container_width=True):
                if len(stages) >= 2:
                    results = [s["result"] for s in stages if s.get("result")]
                    with st.spinner("Building chain..."):
                        chain_result = analyze_chain(results)
                    st.session_state.chain_result = chain_result
                    add_history_entry(
                        "chain", chain_result.get("risk_score", 0),
                        chain_result.get("risk_level", "LOW"),
                        chain_result.get("chain_pattern"),
                        chain_result.get("is_suspicious", False),
                        chain_result.get("chain_pattern", "chain"),
                    )
                else:
                    st.warning("Add at least 2 stages to build a chain.")
        with clear_col:
            if st.button("Clear Chain", use_container_width=True):
                st.session_state.chain_stages = []
                st.session_state.chain_result = None
                st.rerun()

        result = st.session_state.chain_result
        if result is not None:
            st.markdown('<div style="height:8px;"></div>', unsafe_allow_html=True)
            render_chain_verdict(result)
            st.markdown('<div style="height:8px;"></div>', unsafe_allow_html=True)
            chain_expl = result.get("explanation", [])
            if chain_expl:
                section_header("CHAIN EXPLANATION")
                for entry in chain_expl:
                    sev = (entry.get("severity", "low")).lower()
                    sev_color = {"critical": "#ff1744", "high": "#ff9800",
                                 "medium": "#f59e0b", "low": "#6b7280"}.get(sev, "#6b7280")
                    reason = entry.get("reason", "")
                    ev = entry.get("evidence", "")
                    ev_text = " [" + ev + "]" if ev else ""
                    st.markdown(
                        '<div style="padding:4px 0;border-bottom:1px solid #1e293b22;">'
                        '<span style="color:' + sev_color + ';font-family:monospace;'
                        'font-size:0.7rem;">' + _esc(sev.upper()) + "</span> "
                        '<span style="color:#e5e7eb;font-size:0.85rem;">'
                        + _esc(reason) + _esc(ev_text) + "</span></div>",
                        unsafe_allow_html=True,
                    )
            recs = result.get("recommendations", [])
            if recs:
                section_header("RECOMMENDATIONS")
                for rec in recs:
                    st.markdown(
                        '<div style="padding:4px 0;color:#e5e7eb;font-size:0.85rem;">'
                        '<span style="color:#00b4d8;margin-right:6px;">&#9656;</span>'
                        + _esc(rec) + "</div>",
                        unsafe_allow_html=True,
                    )
            with st.expander("RAW CHAIN JSON", expanded=False):
                st.json(result)

    st.markdown('<div style="height:16px;"></div>', unsafe_allow_html=True)
    section_header("ADD STAGE")
    with st.form("chain_stage_form", clear_on_submit=True):
        stage_type = st.selectbox("Artifact type", ["message", "url", "upi", "qr"],
                                  label_visibility="visible")
        if stage_type == "qr":
            stage_input = st.file_uploader("QR image", type=["png", "jpg", "jpeg", "webp"],
                                           label_visibility="collapsed")
        else:
            stage_input = st.text_area(
                "Input", height=80, label_visibility="collapsed",
                placeholder="Enter " + stage_type + " content...")
        add_clicked = st.form_submit_button("Add Stage", use_container_width=True)

    if add_clicked:
        if stage_type == "qr" and stage_input is not None:
            suffix = Path(stage_input.name).suffix if stage_input.name else ".png"
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(stage_input.read())
                    tmp_path = tmp.name
                stage_result = analyze("qr", tmp_path)
            finally:
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
            stages.append({"type": stage_type, "content": stage_input.name,
                           "result": stage_result})
            st.session_state.chain_stages = stages
            st.rerun()
        elif stage_type != "qr" and stage_input and stage_input.strip():
            stage_result = analyze(stage_type, stage_input.strip())
            stages.append({"type": stage_type, "content": stage_input.strip(),
                           "result": stage_result})
            st.session_state.chain_stages = stages
            st.rerun()
        elif stage_type == "qr":
            st.warning("Upload a QR image first.")

    st.markdown(
        '<div style="margin-top:16px;background:#111827;border:1px solid #1e293b;'
        'border-radius:6px;padding:10px 14px;color:#6b7280;font-family:monospace;'
        'font-size:0.75rem;">'
        'Chain analysis correlates independently-analyzed artifacts. '
        'Each stage is analyzed by the existing engines. The chain layer '
        'never re-implements detection or opens URLs.</div>',
        unsafe_allow_html=True,
    )


def main() -> None:
    _render_header()
    nav = _render_sidebar()
    if nav == "Overview":
        _render_overview()
    elif nav == "Message":
        _render_message()
    elif nav == "URL":
        _render_url()
    elif nav == "QR":
        _render_qr()
    elif nav == "UPI":
        _render_upi()
    elif nav == "Attack Chain":
        _render_attack_chain()


if __name__ == "__main__":
    main()
'''

dest = pathlib.Path(__file__).resolve().parents[1] / "app" / "ui.py"
dest.write_text(UI_PY.lstrip("\n"), encoding="utf-8")
print(f"Written {dest} ({len(UI_PY)} chars)")
