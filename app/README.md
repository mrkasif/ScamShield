# App — ScamShield command-center tools and legacy prototype

**Application layer for the ScamShield project.**

> **Note**: The FINAL user-facing frontend is the **Flask Web Command Center**
> in `web/` (see `web/README.md`). The project in this directory — the
> **Streamlit** prototype plus the CLI tools — is retained but is **not** the
> final architecture.

The legacy Streamlit command center wraps the existing analysis engines in
`src/scamshield/`. It is a **command center interface** — not a mockup. Every
scan result comes from the real ScamShield analysis functions; there is **no
hardcoded risk score, indicator, chart, or history**.

## Status

**Legacy (kept for reference).** Streamlit is superseded by the Flask frontend
in `web/`.

## Structure

```
app/
├── ui.py             Server entrypoint — `streamlit run app/ui.py`
├── ui_helpers.py     CSS theme + pure rendering helpers (gauges, sections, chain flow)
├── scan.py           existing message CLI (unchanged)
├── url_scan.py       existing URL CLI (unchanged)
├── qr_scan.py        existing QR CLI (unchanged)
├── ml_scan.py        existing ML CLI (unchanged)
├── analyze.py        existing unified CLI (unchanged)
└── README.md         this file
```

The existing CLIs are deliberately left untouched; they are not converted into
Streamlit pages.

## Installation

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt
```

## Launch

```bash
streamlit run app/ui.py
```

Open the printed local URL (default `http://localhost:8501`). The app runs
**fully locally** on a normal laptop — no network, no GPU, no external API.

## Scanners / sections

| Section | What it does |
|---|---|
| Overview | Command-center landing: system capabilities, session statistics (derived from the current session only), quick-scan actions |
| Message | Multilingual message analysis via `scamshield.analyze("message", ...)` with ML section |
| URL | Static structural analysis via `scamshield.analyze("url", ...)` — never opens the link |
| QR | Upload PNG/JPG/WEBP, saved to a temp file, analyzed via `scamshield.analyze("qr", path)`, then deleted |
| UPI | UPI URI analysis via `scamshield.analyze("upi", ...)` — never executes a payment |
| Attack Chain | Build multi-stage chains from independently-analyzed artifacts and run `scamshield.analyze_chain([...])` |

## Real backend functions connected

All results are produced by the existing engines through the unified API:

- `scamshield.analyze("message" | "url" | "qr" | "upi", ...)`
- `scamshield.analyze_chain([...])`
- Local ML already integrated inside message analysis (`engine_results["ml_analysis"]`),
  displayed as a separate, clearly-labelled section.

The UI is a thin renderer only: it **never re-implements scoring or detection**
and does not duplicate the engines' logic.

## QR handling

`st.file_uploader` returns in-memory bytes. The UI:

1. Writes the uploaded bytes to a `tempfile.NamedTemporaryFile(delete=False, suffix=...)`,
2. Calls `analyze("qr", temp_path)`,
3. Deletes the temp file in a `finally` block.

Invalid images, undetected QRs, and malformed files produce structured engine
results and are shown gracefully — the app never crashes on bad uploads.

## Attack-chain workflow

1. Add artefacts one at a time (message / URL / UPI / QR), each **independently
   analyzed first** by the existing engine.
2. Accumulate the real analysis results as "stages".
3. Click **Build Attack Chain** → runs `scamshield.analyze_chain([...])` on the
   real results.
4. The verdict (`multi_stage_scam` / `potential_chain` / `none`), chain score,
   chain pattern and a vertical stage/relationship flowchart are rendered from
   the actual `stages`, `relationships`, and `chain_pattern` fields.

The chain layer never re-implements detection and never opens URLs.

## Session history

For every successful scan, a lightweight in-session record is kept
(timestamp, input type, risk score, risk level, scam type, suspicious flag).
No database is used and no scan content is persisted. History is shown in the
sidebar and on the Overview; **Clear Session History** clears it. If nothing
has been scanned it shows `No scans in current session` — no fabricated
statistics.

## ML display

When `engine_results["ml_analysis"]` is present, a dedicated **Local ML
Intelligence** panel shows the model prediction, ML score, confidence and
confidence type, with an explicit note that ML evidence is **separate** from the
deterministic security verdict and is not a calibrated certainty. If the model
is unavailable, the panel reports it rather than crashing.

## Local / offline architecture

```
Streamlit UI
    ↓
scamshield.analyze() / analyze_chain()
    ↓
existing engines (message / URL / QR / UPI / ML / chain)
```

Analysis is deterministic and fully local. The UI never opens URLs, resolves
DNS, downloads content, executes attachments or payments, or contacts external
threat-intelligence / AI services.

## Privacy

- Submitted content is analyzed locally and is **not** transmitted anywhere.
- Session history stores only risk metadata (score, level, type, flag) — never
  the message/URL/UPI content.
- No credentials, OTPs, passwords, or card numbers are surfaced.

## Limitations

- QR input requires a local temp file because the engine consumes a filesystem
  path (bytes are not passed directly).
- Session history is in-memory only and is cleared on refresh/restart.
- ML confidence is the model's score, not a calibrated probability; the
  deterministic rule engine remains the authoritative verdict.

## Tests

Frontend smoke tests live in `tests/test_frontend.py`. They verify module
imports, real-analyzer connectivity (message/URL/UPI/chain), QR temp-file
handling, absence of hardcoded results, and ML-unavailable handling without
requiring a browser automation framework.

```bash
python -m pytest tests/ -q   # 472 = 456 engine/API/research + 16 frontend smoke tests
```
