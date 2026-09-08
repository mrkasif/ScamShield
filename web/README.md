# ScamShield Web Command Center (final frontend)

The **final user-facing frontend** is a lightweight **Flask + HTML + CSS +
vanilla JavaScript** application. It is a *thin HTTP layer* only: every response
comes from the real `scamshield.analyze()` / `scamshield.analyze_chain()` calls.
There is **no duplicated detection, scoring or chain logic** anywhere in this
package and none in the browser — the vanilla JS just renders the JSON the API
returns.

```
web/
├── app.py              Flask application (app factory + WSGI `app` object)
├── __init__.py         package marker
├── templates/
│   └── index.html      single-page command center (shell + all 8 pages)
└── static/
    ├── style.css       cybersecurity command-center theme (responsive, a11y)
    └── app.js          vanilla JS client (renders real API responses only)
```

## Pages (single-page app)

| Page | What it shows |
|------|---------------|
| Overview | hero + primary actions, capability grid (from real engines), analysis architecture flow |
| Message Intelligence | textarea + counter, rule-based verdict, indicators, explanation, recommendations, URL evidence, **Local ML signal kept separate** |
| URL Intelligence | domain/parse table, URL threat indicators, explanation, recommendations, static-only security notice |
| QR Analyzer | drag-and-drop upload, image preview, decoded content, content type, sub-analysis (URL/UPI/text), multi-QR states, error states |
| UPI Analyzer | structured payment-request fields, verdict, indicators, explanation, recommendation, no-payment notice |
| Attack Chain | stage queue, horizontal (desktop) / vertical (mobile) chain flow, relationships, classification banner |
| Research / Evaluation | real dashboard from `models/research/` artifacts injected at page load (comparison, latency, leakage, dataset stats, limitations) |
| System Status | live `/api/health` status + capability rows |

The Research page reads **real generated artifacts** (`evaluation_summary.json`,
`latency_results.json`, `leakage_report.json`) — `web/app.py` reads them at
`GET /` time and embeds them as JSON. No metrics are fabricated; if the
artifacts are missing the page explains how to generate them.

## Run locally

```bash
pip install -r requirements.txt        # includes flask
python web/app.py                      # or: python -m web.app
# Open http://127.0.0.1:5000
```

Environment variables (only used when running `python web/app.py`):

| Variable | Default | Meaning |
|----------|---------|---------|
| `SCAMSHIELD_HOST` | `127.0.0.1` | listen host |
| `SCAMSHIELD_PORT` | `5000` | listen port |
| `SCAMSHIELD_DEBUG` | `0` | set `1` for the Flask debugger |

## Deployment / hosting compatibility

The module is WSGI-ready and hosts anywhere normal Python runs:

```bash
# Flask dev server
flask --app web.app run

# Any WSGI server
gunicorn web.app:app          # or uwsgi / waitress on any PaaS
```

No database, no authentication, no external APIs, no cloud-dependent service,
no client-side dependencies (no build step, no bundler). The app is fully
static-serving capable — just serve this directory behind a WSGI server.

## API endpoints

| Method | Path | Request | Returns |
|--------|------|---------|---------|
| `GET` | `/` | - | `index.html` command center |
| `GET` | `/api/health` | - | service name/version, `offline: true`, ML-availability |
| `POST` | `/api/analyze/message` | `{"message": "..."}` | unified message result (rule engine + local ML) |
| `POST` | `/api/analyze/url` | `{"url": "..."}` | unified URL result (static, never opened) |
| `POST` | `/api/analyze/upi` | `{"upi": "..."}` | unified UPI result (static, never executed) |
| `POST` | `/api/analyze/qr` | multipart `qr_image` file | unified QR result (local decode) |
| `POST` | `/api/analyze/chain` | `{"stages": [...]}` | unified chain result |

Every analyze endpoint returns the **real, unchanged** unified analyzer result:
`success, input_type, risk_score, risk_level, is_suspicious, scam_type,
confidence, summary, indicators, explanation, recommendations, evidence,
engine_results, warnings` (plus `classification/chain_pattern/stages/
relationships` for chain). A 400 (`error_type: "validation"`) is returned for
malformed input, 413 for oversized QR uploads, and 404/405 for unknown
routes/methods.

## QR security handling

1. The uploaded file must be present with a `.png/.jpg/.jpeg/.webp/.gif/.bmp`
   extension and must not exceed **5 MiB**.
2. The bytes are written to a temporary file via `tempfile.NamedTemporaryFile`.
3. The existing QR engine decodes and analyses the image **fully locally**;
   decoded URL payloads are analysed statically (never opened, never resolved),
   and UPI payloads are never executed.
4. The temporary file is **always deleted in a `finally` block** (verified by
   `tests/test_flask_api.py::test_qr_temp_file_cleaned_up`).

## Security model

- **No network access** anywhere: verified by a monkeypatched-socket test
  (`test_flask_layer_makes_no_network_requests`) that proves every endpoint
  completes with sockets disabled.
- URLs are **never opened/visited/resolved/downloaded**; analysis is static and
  structural only.
- QR content and UPI URIs are **never executed**; payments are never initiated.
- No authentication, no cookies/sessions of consequence, no database. Private
  input is processed in-memory and never persisted (QR temp files are deleted).
- Output is escaped in the browser (no HTML injection via analyzed content).

## UI / UX / accessibility

- Reusable risk component renders the **backend's exact** `risk_score` /
  `risk_level` (levels are never recomputed in JS) with a short count-up meter
  that is disabled under `prefers-reduced-motion`.
- Lightweight CSS-only animations (panel fade, meter transition, chain reveal);
  no animation libraries, no particle effects.
- Semantic HTML, real `<label>` elements, `aria-live` result regions,
  keyboard-accessible nav and upload area (Enter/Space opens the file picker),
  visible `:focus-visible` outlines, text-plus-color risk labels (never
  color-only), readable contrast.
- Responsive: sidebar + main on desktop; collapsible off-canvas sidebar +
  backdrop on tablet; stacked full-width panels and a vertical chain flow on
  mobile. No horizontal overflow (`overflow-x: hidden`).
- Result views include a "View Raw Result" toggle (safe, escaped JSON) for
  demo/debugging without dumping raw JSON by default.

## Privacy model

- Messages/URLs/UPI strings are never written to disk.
- QR images are temporarily written to disk solely for local decoding and are
  deleted immediately afterwards.
- The research evaluation (`python -m app.research_eval`) sanitises any
  persisted examples (OTP/phone/card/account/UPI/URL/email/IP redacted).

## Honest limitations

- Heuristic risk estimates, not calibrated probabilities; do not claim universal
  scam detection or live threat intelligence.
- URL analysis is static only — no DNS, no reputation, no content fetch.
- The labelled dataset is small/synthetic; evaluation numbers do not generalise
  to production traffic (see `src/scamshield/research/README.md`).

## Tests

```bash
python -m pytest tests/test_flask_api.py tests/test_web_scenarios.py -q   # 52 tests
```