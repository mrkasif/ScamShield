# ScamShield

**Indian Digital Scam Intelligence & Prevention System**
Aavishkar college innovation/research prototype (zero-budget, lightweight, explainable).

---

## Problem

Indian users increasingly encounter scams through:

- **SMS** and messaging platforms (WhatsApp, Telegram, etc.)
- **Malicious/suspicious URLs** embedded in messages
- **QR codes** that redirect to fraudulent payment or credential-harvesting pages
- **Social engineering** tactics exploiting urgency, fear, or impersonation

These scams span multiple Indian languages and code-mixed Hinglish, which limits the effectiveness of detection tools designed primarily for English or single-language inputs. Existing approaches may not adequately address the combination of Indian scam patterns, multilingual content, Hinglish code-mixing, and the need for explainable, actionable results.

## Proposed system

ScamShield is a research prototype intended to analyze suspicious digital content and provide:

- **Risk score**: 0-100
- **Risk level**: e.g., low / medium / high / critical
- **Scam category**: e.g., Fake KYC, UPI/payment scam, phishing, etc.
- **Explainable reasons**: human-readable justifications for the classification
- **Safety recommendations**: actionable advice for the user

ScamShield is **not** a binary scam/safe detector. It classifies the type of scam and explains why, so users can take informed action.

## Supported scam categories

| Category | Description |
|----------|-------------|
| Fake KYC | Messages claiming KYC expiry requiring immediate action |
| UPI/payment scams | Fraudulent UPI collect requests, fake refund links |
| Bank impersonation | Messages impersonating banks requesting OTP/PIN |
| Phishing | Links mimicking legitimate services to steal credentials |
| Fake customer care | Scammers posing as support staff requesting sensitive info |
| Job scams | Fake job offers requiring registration fees or personal data |
| Investment scams | Guaranteed-return or crypto doubling schemes |
| Loan scams | Fake pre-approved loans requiring upfront fees |
| Delivery scams | Fake customs/courier payment demands |
| Lottery/prize scams | Fake prize notifications requiring processing fees |
| Social-media impersonation | Impersonating relatives or contacts requesting money |
| Other social-engineering | Miscellaneous scam patterns (electricity, SIM, court, etc.) |

## Languages

- English (`en`)
- Hindi (`hi`)
- Marathi (`mr`)
- Hinglish (code-mixed English-Hindi)

## Research direction

**This is a research investigation, not a claim that we invented scam detection.**

The research focus is the **combination** of:

- Indian-focused scam data (synthetic + curated public datasets)
- Multilingual support across English, Hindi, Marathi, and Hinglish
- Hinglish handling (code-mixed text that standard NLP pipelines often misclassify)
- Explainable AI: human-readable reasons behind every classification
- Risk scoring: a continuous 0-100 score rather than a binary decision
- Scam-type classification: identifying the specific scam category
- Message analysis: NLP-based text classification
- URL analysis: heuristic and feature-based URL risk assessment
- QR analysis: decoding QR content and analyzing destinations
- Lightweight implementation: preference for models that run without GPU
- Multi-stage scam-chain analysis: correlating related scam artifacts into a chain (implemented as a research/prototype correlation layer - `src/scamshield/chain`)

## Architecture

```
User Input
    |
    +--> Message (text)
    |
    +--> URL (string)
    |
    +--> QR Code (image)
          |
          v
     Input / Ingestion
     (normalize, extract, decode)
          |
          v
   Analysis Components
     /      |       \
    /       |        \
  NLP      URL       QR
    \       |        /
     \      |       /
          v
  Unified ScamShield Analyzer   (src/scamshield/analyzer.py)
  (routes input, normalizes every engine result, never re-implements scoring)
          |
          v
      Unified Result
  (score, level, suspicious, scam_type, confidence, summary,
   indicators, explanation, recommendations, evidence, engine_results)
          |
          v
   Flask Web App / API          (web/)  <-- final frontend (run locally)
```

**Note**: Multi-stage scam-chain detection (identifying sequences of related scam artifacts) is implemented in `src/scamshield/chain` as a **research/prototype correlation layer** — see the component section below.

## Research methodology

The intended research workflow:

```
Dataset
  --> preprocessing (sanitization, normalization, label cleaning)
  --> train / validation / test split (stratified, frozen test set)
  --> baseline ML models (TF-IDF + classifiers)
  --> evaluation (precision, recall, F1, confusion matrix)
  --> model improvement (feature engineering, hyperparameter tuning)
  --> explainability (feature importance, rule extraction)
  --> risk engine (score calibration, threshold selection)
  --> URL analysis (heuristic features, domain reputation signals)
  --> QR analysis (decode, destination analysis)
  --> prototype integration
  --> unseen testing and demonstration
```

### Intended baseline models

Initial experiments will compare lightweight, interpretable models:

- TF-IDF + Logistic Regression
- TF-IDF + Naive Bayes (Multinomial)
- TF-IDF + Linear SVM

A lightweight model is preferred if it performs comparably to heavier alternatives, since the goal is deployability without GPU.

## Current status

| Component | Status |
|-----------|--------|
| Project structure | Done |
| Dataset (synthetic + public) | Foundation built; `scripts/build_dataset.py` generates labelled splits |
| Dataset schema | Defined |
| Research gap documentation | Drafted; needs literature review |
| Message intelligence engine (rule-based, multilingual) | **Working** - `scamshield.nlp.analyze_message()` |
| Tests for message engine | 50 passing unit tests |
| URL intelligence engine (static, local, explainable, advanced) | **Working** - `scamshield.url.analyze_url()` |
| Tests for URL engine | 95 passing unit tests |
| Local ML intelligence (TF-IDF + Logistic Regression, offline) | **Working** - `scamshield.ml.predict_message()`, `python -m src.scamshield.ml.train` |
| Tests for ML engine | 40 passing unit tests |
| ML training pipeline + metrics/report generation | **Working** - `src/scamshield/ml/train.py`, `models/metrics.json`, `models/evaluation_report.md` |
| Evaluation framework | Working for the ML baseline (accuracy/precision/recall/F1/confusion) |
| Explainability | Rule-based explanations + recommendations shipped with the engine |
| Risk engine | Rule-based 0-100 scoring + levels shipped with the engine |
| URL analysis | **Working** static URL risk engine; destination risk analysis (DNS, content) not yet implemented |
| QR analysis | **Working** - `scamshield.qr.analyze_qr()` (local decode + UPI/URL/text routing) |
| Tests for QR engine | 56 passing unit tests |
| Unified ScamShield Analyzer | **Working** - `scamshield.analyze()` (one schema over message/URL/QR/UPI) |
| Tests for unified analyzer | 84 passing unit tests |
| Multi-stage scam-chain analysis | **Working** - `scamshield.analyze_chain()`, `scamshield.analyze("chain", [...])` (research/prototype correlation layer) |
| Tests for chain analysis | 49 passing unit tests |
| Streamlit Command Center UI | **LEGACY prototype** - `streamlit run app/ui.py` (retained in the repo, NOT the final frontend) |
| Tests for frontend smoke layer | 16 passing unit tests |
| Flask Web Command Center | **FINAL frontend** - `python web/app.py` or `python -m web.app` (Flask + vanilla JS, one API over all engines) |
| Tests for Flask API + E2E scenarios | 52 passing unit tests |
| User interface | **Final** - Flask web app (`web/`) |
| Research & Evaluation Lab | **Working** - `python -m app.research_eval` (dataset/ML/rule/combined eval, latency, leakage audit) |
| Tests for research evaluation | 30 passing unit tests |

The repository currently contains the **dataset foundation**, **research
documentation**, **working message, URL, QR, local-ML and chain-correlation
components**, the **Flask Web Command Center (final frontend)**, and the
**research & evaluation lab** (below).
Cloud/API integration and future steps remain.

### Working message scanner (first version)

A zero-dependency, fully local, deterministic **rule-based** message scanner
is implemented in `src/scamshield/nlp`. It analyses one SMS / chat message at
a time and returns a risk score (0-100), risk level, scam category,
detected indicators, extracted URLs, human-readable explanations and safety
recommendations. It supports English, Hindi, Marathi and Hinglish.

```bash
# Scan one message (prints a readable report)
python -m app.scan "Your KYC has expired. Verify immediately at this link."
#   Risk Score: 58/100  Risk Level: HIGH  Classification: fake_kyc

# Interactive REPL mode
python -m app.scan

# Run the tests
python -m pytest tests/test_scamshield.py -q
```

The engine is deterministic (identical output for identical input), runs
without internet or a GPU, and uses no paid APIs. It is not trained ML - the
rules and heuristics are curated dictionaries and weighted combinations
documented in `src/scamshield/nlp/README.md`.

### Working URL intelligence engine (second component - advanced)

A local, **static** URL risk engine is implemented in `src/scamshield/url`.
It analyses a URL's *structure* for phishing indicators - raw IP hosts,
embedded credentials, punycode/IDN, **registrable-domain awareness**
(`domains.py`: root_domain / subdomains / tld), **brand impersonation with
sub-domain placement** (`paypal.account-verify.com`), **typosquatting /
look-alike domains** (`paypai.com`, `gooogle.com`, `amaz0n.com`),
**Unicode / mixed-script homoglyphs** (`payрal.com`), suspicious query
parameter names (`password`, `otp`, `card`, ...), nested/encoded URLs,
hex-encoded hosts, cheap TLDs, hyphen/numeric-domain abuse, and complexity
caps so size alone can never force a verdict - and returns a 0-100 risk
score, level, suspicion flag, indicators, explanations (with concrete
evidence) and contextual recommendations. It also exposes **attachment
filename** and **sender display-name vs domain** metadata heuristics
(`analyze_attachment_filename`, `assess_sender`).

It is **static-only**: it never opens, resolves, follows, downloads, executes
or phone-homes to any service, and requires no API key or internet access.

```bash
# Scan one URL (prints a readable report with parsed domains + evidence)
python -m app.url_scan "https://secure-sbi-verify.example.com/login"
#   Risk Score: 72/100  Risk Level: HIGH  Suspicious: YES

# Interactive REPL mode
python -m app.url_scan

# Run the URL tests (95 tests)
python -m pytest tests/test_url_engine.py -q
```

The message scanner automatically augments its output with the URL engine:
`analyze_message()` returns `url_analysis` (per-URL results) and
`combined_risk` (a capped message+URL score that is always >= the strongest
single signal) without changing any existing fields. Full documentation:
`src/scamshield/url/README.md`.

### Working QR security analyzer (third component)

A **local, offline, deterministic** QR analyzer is implemented in
`src/scamshield/qr`. It decodes QR images with the `cv2.QRCodeDetector`
shipped with `opencv-python-headless` (no network, no QR API), classifies each
decoded payload (`url` / `upi` / `text` / `unknown`) and routes it to the
matching engine: URLs go to the static URL engine (`url_analysis`), text to
the message engine (`message_analysis`) and UPI payment URIs to a new static
`upi.py` parser + scorer (`upi_analysis`). UPI scoring is fully transparent -
every point is listed in the explanation with its indicator, severity, reason
and evidence (e.g. `payment_destination_detected` +8, `embedded_payment_amount`
+10, threshold releases ≥10k/50k/100k, urgency/refund/KYC/OTP note-language).
A normal merchant-pay QR stays LOW; refund/prize/urgent notes with high
amounts reach HIGH/CRITICAL - but the analyzer never claims a specific UPI ID
is fraudulent, it always says *verify the recipient*. Multi-QR images combine
all code risks with the same documented 70% strongest+weaker rule used for
message+URL, so the combined score is always >= the strongest single code.
Unknown payloads (`mailto:`, `geo:`, ...) are never auto-malicious.

```bash
# Scan a QR image (prints a readable report; never opens the URL / executes
# the payment)
python -m app.qr_scan "tests/fixtures/qr/upi_refund_scan.png"

# Generate safe synthetic demo fixtures
python scripts/generate_qr_fixtures.py

# Run the QR tests (56 tests)
python -m pytest tests/test_qr_engine.py -q
```

Full documentation: `src/scamshield/qr/README.md`.

### Unified ScamShield Analyzer (fourth component - orchestration layer)

The single entry point a future UI/API calls. It routes each input to the
matching engine - message → `scamshield.nlp`, URL → `scamshield.url`, QR →
`scamshield.qr` (and UPI strings through the QR content analyzer) - and
normalizes every result into **one consistent schema**, without re-implementing
any engine's detection or scoring.

```python
from scamshield import analyze, analyze_batch, detect_input_type

analyze("message", "Your KYC has expired. Click the link now.")
analyze("url", "https://secure-sbi-verify.example.com/login")
analyze("qr", "tests/fixtures/qr/url_suspicious.png")
analyze("upi", "upi://pay?pa=merchant@upi&pn=Store&am=60&cu=INR")
```

Every result carries `success, input_type, risk_score(0-100), risk_level
(LOW/MEDIUM/HIGH/CRITICAL), is_suspicious, scam_type, confidence,
confidence_type, confidence_note, summary, indicators, explanation,
recommendations, evidence, engine_results` (the full original engine result is
always preserved under `engine_results`). Errors are returned as structured
results (`success=False, error, error_type, status="ERROR"`, score 0/LOW) -
the analyzer never crashes on empty messages, malformed URLs, missing/corrupt
QR files, unsupported types or invalid arguments.

`detect_input_type()` conservatively guesses `url` / `upi` / `message` from a
string (only `^https?://` and `^upi:` prefixes - a bare `example.com` or image
path falls back to `message`), and `analyze_batch()` analyses many items
(dict or `(type, content)` form, auto-detecting the type when omitted) in
deterministic input order. Analysis is fully **local, deterministic and
offline** - no network, no URL opening, no payment execution, no external
APIs.

```bash
python -m app.analyze                              # interactive menu
python -m app.analyze --type url --input "https://secure-sbi-verify.example.com/login"
python -m app.analyze --type qr --input "tests/fixtures/qr/url_suspicious.png"
python -m app.analyze --type upi --input "upi://pay?pa=scam@refunds&am=50000&tn=reward"
python -m app.analyze --type message --input "Your KYC has expired..." --json

# Full test suite (472 = 50 message + 95 URL + 56 QR + 84 unified + 40 ML + 49 chain + 28 Flask API + 16 frontend + 30 research + 24 web scenarios)
python -m pytest tests/ -q
```

The existing `python -m app.scan`, `python -m app.url_scan` and
`python -m app.qr_scan` demos are untouched. Full documentation:
`src/scamshield/README.md`.

### Local ML intelligence (fifth component)

A lightweight, **completely local** binary `scam`/`safe` classifier using
**TF-IDF + Logistic Regression** (`src/scamshield/ml`). It is an **additional
intelligence layer**, not a replacement for the deterministic message engine.

It trains on the existing dataset (`data/train/messages.csv`) and reports
metrics on the **frozen** test split:

```bash
# Train once (reproducible, fully offline)
python -m src.scamshield.ml.train

# Predict a single message
python -m app.ml_scan "Your account will be blocked. Verify KYC immediately..."

# In Python
from scamshield.ml import predict_message
predict_message("Your KYC has expired. Click the link now.")
# -> {"success": True, "prediction": "scam", "score": 67,
#     "confidence": 67.1, "confidence_type": "model_probability", ...}
```

If the model has not been trained, `predict_message` returns a graceful
`ML model unavailable` result instead of crashing.

**Unified analyzer integration**: `scamshield.analyze("message", ...)` now
exposes the ML result under `engine_results["ml_analysis"]` while the full
deterministic result stays under `engine_results["message"]`. The two scores
are **kept separate - never averaged** - and the authoritative top-level
`risk_score` / `risk_level` / `is_suspicious` remain driven purely by the
deterministic rule engine, so a weak or missing ML prediction can never hide a
real security signal.

**Evaluation** (see `models/metrics.json` and `models/evaluation_report.md`):
test-set accuracy ~0.99, precision 1.0, recall ~0.99, F1 ~0.99 on this small
synthetic dataset - with an honest discussion of false negatives (missed
scams) vs false positives (safe flagged as scam), class imbalance, and
**cross-split leakage** (99 shared texts). Confidence is the model's raw
predicted-class probability, **not** a calibrated estimate, and is labelled as
such. Full documentation, rationale, and limitations:
`src/scamshield/ml/README.md`.

### Multi-stage scam / attack-chain analysis (sixth component - correlation layer)

A **research/prototype correlation layer** (`src/scamshield/chain`) that
deterministically correlates **already-analysed** message / URL / QR / UPI
artifacts into possible multi-stage scam chains — e.g. a KYC phishing flow:

```
message → suspicious URL → credential request → UPI payment
```

It never re-implements detection and never opens URLs, resolves DNS, downloads,
crawls, executes QR payloads, or contacts any external/threat-intel service —
it is **completely offline** and operates strictly on the supplied engine
results. Correlations are explainable (each relationship carries a relation
name, label, strength, match type and concrete evidence) and artifacts are
matched by exact URL / registrable-root domain / UPI payee where supported. The
recognized chain patterns are `kyc_phishing`, `payment_scam`, `prize_refund`,
`fake_customer_care`, `job_scam`, `investment_scam` and `loan_scam`.

The 0-100 chain score is transparent (`scoring.py`): it is **never a simple
average** and is **never lower than the strongest individual stage**; each
bonus is capped (`stage_bonus` decays geometrically, `rel_bonus` is squared +
capped at 40, a 2-stage category consistency bonus caps at 8, progress +8,
pattern +6). Results use the existing risk levels and `confidence_type:
"heuristic"`. Classification is `none` | `potential_chain` | `multi_stage_scam`;
a lone artifact is never `multi_stage_scam`, and blank evidence never yields a
chain.

```python
from scamshield import analyze, analyze_chain

analyze_chain([message_result, url_result, upi_result])
analyze("chain", [message_result, url_result, upi_result])  # unified mode
```

Chain mode preserves the FULL individual engine results under
`engine_results["chain_per_stage"]` and promotes the chain verdict to the
unified top-level fields. Everything is JSON-serializable and fully local.

**Honest caveats**: this is correlation of independent detections, not proof of
intent; if the individual engines do not flag a stage, the chain does not invent
suspicion; patterns are Indian-scam-centric and not calibrated against
production traffic; one artifact is never a chain. See
`src/scamshield/chain/README.md`.

### Flask Web Command Center (final frontend)

The **final user-facing frontend** is a lightweight **Flask + HTML + CSS +
vanilla JavaScript** application in `web/`. It is a thin HTTP layer ONLY: every
response comes from the real `scamshield.analyze()` / `scamshield.analyze_chain()`
calls. There is no duplicated detection, scoring, or chain logic in Flask and
none in the browser.

```bash
# Local development
python web/app.py
# or
python -m web.app
# Environment variables: SCAMSHIELD_HOST (127.0.0.1), SCAMSHIELD_PORT (5000),
# SCAMSHIELD_DEBUG (0/1).
```

WSGI-ready: the module exports `app` (`web.app:app`), so it can be served by
any normal WSGI server/Paas (gunicorn, uwsgi, Waitress, Fly/Render/HuggingFace,
etc.) with no cloud-specific code. No database, no authentication, no external
APIs, no network access.

The single-page interface contains eight pages: **Overview** (hero, capability
grid, analysis architecture), **Message Intelligence**, **URL Intelligence**,
**QR Analyzer**, **UPI Analyzer**, **Attack Chain** (multi-stage flow with
relationship links), **Research / Evaluation** (real dashboard built from the
`models/research/` artifacts injected at page load), and **System Status**.
Risk scores/levels always come from the backend (never recomputed in JS), and
the local ML signal is shown separately from the authoritative rule-based
verdict. Lightweight CSS animations respect `prefers-reduced-motion`; the
layout is responsive (off-canvas sidebar on tablet, stacked panels on mobile).

Endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | single-page command center |
| GET | `/api/health` | service / version / offline status |
| POST | `/api/analyze/message` | `{"message": "..."}` -> rule + local ML |
| POST | `/api/analyze/url` | `{"url": "..."}` -> static URL analysis (never opened) |
| POST | `/api/analyze/upi` | `{"upi": "..."}` -> static UPI URI analysis (never executed) |
| POST | `/api/analyze/qr` | multipart `qr_image` -> local decode, temp file always cleaned up |
| POST | `/api/analyze/chain` | `{"stages": [...]}` -> multi-stage chain analysis |

QR handling in the web layer: the uploaded image is validated (size 5 MiB,
PNG/JPG/WebP/BMP/GIF), written to a temporary file, analysed with the existing
QR engine, and the file is always deleted in a `finally` block. Decoded URL
payloads are analysed statically - never opened, never resolved, no DNS, and
UPI payloads are never executed. Full documentation: `web/README.md`.

```bash
# Flask API integration + end-to-end scenario tests (52 tests)
python -m pytest tests/test_flask_api.py tests/test_web_scenarios.py -q
```

### Streamlit Command Center UI (legacy prototype - NOT the final frontend)

A **Streamlit** command center (`app/ui.py`) was the original prototype
frontend. It remains in the repository but is **not** the final architecture.

```bash
streamlit run app/ui.py
```

Sections: **Overview** (capability grid + session statistics + quick scan),
**Message** (multilingual message analysis incl. local-ML panel), **URL** (static
structural analysis - never opens the link), **QR** (upload → temp file →
`analyze("qr", path)` → temp file deleted), **UPI** (up-prefix analysis - never
executes a payment), and **Attack Chain** (independently analyze several
artifacts, then run `scamshield.analyze_chain([...])` and view the real chain
pattern, score and stage/relationship flow).

Features: dark cybersecurity theme with CSS/SVG gauges (no emojis), session
history in `st.session_state` (metadata only - never message/URL content, no
database), graceful error handling for invalid QR/malformed inputs, and honest
local-first privacy messaging. Full documentation: `app/README.md`.

```bash
# Frontend smoke tests (16 tests: imports, real-analyzer connectivity,
# QR temp-file roundtrip, no-hardcoded-results, ML-unavailable handling)
python -m pytest tests/test_frontend.py -q
```

### Research & Evaluation Lab (eighth component - benchmarking)

A reproducible, **completely local** evaluation framework
(`src/scamshield/research/`, CLI `app/research_eval.py`) that measures how well
the existing system performs against the labelled dataset — without changing
any detection or scoring logic and without network access.

```bash
# Run the full evaluation (also writes artefacts under models/research/)
python -m app.research_eval

# Machine-readable output
python -m app.research_eval --json

# Skip latency measurement for a faster run
python -m app.research_eval --skip-latency
```

Capabilities:

- **Dataset evaluation** — raw vs deduped sample counts, class distribution,
  scam categories, languages, sources.
- **ML evaluation** — accuracy/precision/recall/F1/confusion on the frozen test
  set using the existing trained model.
- **Rule-engine evaluation** — same metrics for the deterministic message
  analyzer, clearly distinguished from ML.
- **Combined analyzer evaluation** — the unified `scamshield.analyze()`
  (documented: on message inputs its verdict is rule-driven by design).
- **Model vs Rule vs Combined comparison** — machine-readable CSV table.
- **Language/Text-group evaluation** — per-language (en/hi/mr/hinglish) metrics.
- **Scam-category evaluation** — per-category one-vs-rest metrics where
  statistically meaningful.
- **FP/FN analysis** — representative misclassified examples, sanitised.
- **Detection latency** — mean/median/min/max/stdev over repeated runs.
- **Leakage audit** — exact + normalised cross-split overlap, plus a
  runtime leakage-clean evaluation subset (original dataset untouched).

Artefacts written to `models/research/`: `evaluation_summary.json`,
`model_comparison.csv`, `confusion_matrices.json`, `language_results.json`,
`category_results.json`, `latency_results.json`, `leakage_report.json`,
`fp_fn_examples.json`, `evaluation_report.md`.

**Research integrity**: the evaluation is deterministic, offline, and does not
claim production readiness — it explicitly documents dataset size, class
imbalance, cross-split leakage, and engine/ML/URL/QR limitations. Full
methodology: `src/scamshield/research/README.md`.

```bash
# Research evaluation tests (30 tests)
python -m pytest tests/test_research.py -q
```

## Project layout

```
data/              labelled datasets (Step 2)
  raw/             original public downloads
  processed/       full labelled table + summary
  train/           training split
  validation/      validation split
  test/            frozen held-out test split

src/scamshield/    analysis engine (Steps 3-8)
  ingest/          input normalization
  nlp/             message/text processing and scam classification (WORKING engine)
  url/             static URL risk engine (WORKING engine) - see url/README.md
  qr/              static QR decode + URL/UPI/text routing (WORKING engine) - see qr/README.md
  ml/              local ML intelligence (TF-IDF + LogReg) (WORKING) - see ml/README.md
  chain/           multi-stage scam-chain correlation (WORKING) - see chain/README.md
  research/        Research & Evaluation Lab (WORKING) - see research/README.md
  analyzer.py      Unified ScamShield Analyzer (WORKING) - one schema over message/URL/QR/UPI/ML/chain
  risk/            risk score engine (0-100) - currently folded into nlp/
  explain/         human-readable explanation generation - currently folded into nlp/

models/            trained ML artifacts - `scamshield_tfidf.joblib` (committed for deployment),
                   `metrics.json`, `evaluation_report.md
  research/        research evaluation artefacts (JSON/CSV/Markdown)
app/               legacy CLI demos + legacy Streamlit prototype `app/ui.py` (Step 9; NOT the final frontend) - see app/README.md
web/               FINAL frontend - Flask app `web/app.py` + `templates/index.html` + `static/app.js`/`static/style.css` - see web/README.md
tests/             unit tests (`tests/test_scamshield.py`, `tests/test_url_engine.py`, `tests/test_qr_engine.py`, `tests/test_unified_analyzer.py`, `tests/test_ml_engine.py`, `tests/test_chain_analysis.py`, `tests/test_frontend.py`, `tests/test_research.py`, `tests/test_flask_api.py`, `tests/test_web_scenarios.py`)
scripts/           dataset building, training, evaluation entry points
research/          notes, metrics, gap analysis, demo cases
```

## Setup (local, free)

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
pip install -r requirements.txt
```

Do not install paid APIs or commercial datasets.

## Deploy locally

```bash
python web/app.py          # dev server -> http://127.0.0.1:5000
# or production-style (reads gunicorn.conf.py):
gunicorn web.app:app
```

Environment variables (all optional; safe defaults; **debug is off by default**):

| Variable | Default | Meaning |
|---|---|---|
| `HOST` / `SCAMSHIELD_HOST` | `127.0.0.1` (dev) / `0.0.0.0` (gunicorn) | Listen host |
| `PORT` / `SCAMSHIELD_PORT` | `5000` | Listen port (Render injects `PORT`) |
| `DEBUG` / `SCAMSHIELD_DEBUG` | `0` | Set `1` to enable dev debugger |

## Deploy to Render

1. **Push the project to GitHub** (`.gitignore` keeps virtualenvs/caches/logs out; the trained ML model `models/scamshield_tfidf.joblib` is committed so prediction works on Render too).
2. On the Render dashboard, create a new **Web Service** and **connect the GitHub repository**.
3. **Build command:** `pip install -r requirements.txt`
4. **Start command:** `gunicorn web.app:app`
5. Render sets the **`PORT`** environment variable automatically. The repo's `gunicorn.conf.py` reads it and binds `0.0.0.0:PORT`, so no additional settings are needed.
6. Optional but recommended: add the **health check path** `/api/health` (already defined in the provided `render.yaml`). A ready-made Blueprint is included, or you can build the service by hand.
7. No secrets, API keys or external services are required — the app runs fully offline and static-only. If the model were ever absent, `/api/health` reports `ml_model_available: false` and every engine keeps working.

You can also use the included `render.yaml` via **Render Blueprints** to create the identical web service automatically.

## Privacy

The project follows strict privacy rules:

- Never store real OTPs, passwords, account/card numbers, personal addresses, phone numbers, or private messages in the dataset
- Synthetic examples and legally usable public datasets are preferred
- The dataset uses placeholders: `[OTP]`, `[PHONE]`, `[ACCOUNT]`, `XX12` (last-4 style), `http://*.example.in`, RFC 5737 test IPs
- No real authentication credentials or unnecessary personally identifiable information

See `data/schema.md` for the full privacy specification.

## Licence

Prototype code: to be decided. Dataset files must keep their **original** licences in `data/LICENCES.md`.
