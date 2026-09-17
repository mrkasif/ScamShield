# ScamShield Analysis Engine

`src/scamshield/` contains the modular analysis engine for the Indian Digital Scam Intelligence & Prevention System (ScamShield).

## Intended architecture

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
     Input / Ingestion        (ingest/)
          |
          v
   Analysis Components
     /      |       \
    /       |        \
  NLP( )  URL( )   QR( )
    \       |        /
     \      |       /
          v
   Unified ScamShield Analyzer   (analyzer.py - this layer)
          |
          v
      Unified Result
          |
          v
   Flask Web App / API          (web/)   <-- final frontend
```

## Current implemented modules

| Module | Responsibility | Status |
|--------|---------------|--------|
| `ingest/` | Normalizes incoming user input (message text, URL strings, QR images) into a common structure | Planned |
| `nlp/` | Message/text processing and scam classification (binary scam/safe and scam-type) | **Working** - `analyze_message()` |
| `url/` | Suspicious URL feature extraction and analysis | **Working** - `analyze_url()` |
| `qr/` | QR decoding and analysis of decoded destinations | **Working** - `analyze_qr()`, `analyze_qr_content()` |
| `ml/` | Local ML intelligence (TF-IDF + Logistic Regression, binary scam/safe) | **Working** - `predict_message()` - see `ml/README.md` |
| `chain/` | Multi-stage scam / attack-chain correlation of already-analysed artifacts | **Working** - `analyze_chain()` - see `chain/README.md` |
| `link_change/` | Phishing Link Purifier / Link Safety Monitor - static normalization + baseline-vs-current change monitoring | **Working** - `analyze_link_change()` - see `link_change/README.md` |
| `safetyzones.py` | Unified Safety-Zone System (GREEN/YELLOW/RED) + explainable `risk_assessment` + truthful `risk_breakdown` - pure derivation from the existing authoritative score, no re-scoring | **Working** - `zone_for_score()`, `attach_risk_presentation()` |
| `research/` | Reproducible local Research & Evaluation Lab - dataset/ML/rule/combined eval, latency, leakage audit | **Working** - `python -m app.research_eval` - see `research/README.md` |
| `analyzer.py` | **Unified ScamShield Analyzer** - orchestrates the engines into ONE consistent result schema | **Working** |
| `risk/` | Combines evidence from NLP + URL + QR into a 0-100 risk score | Folded into the engines / `analyzer.py` |
| `explain/` | Converts model outputs and features into human-readable reasons and safety recommendations | Folded into the engines / `analyzer.py` |

## Unified ScamShield Analyzer

The **orchestration layer** a future UI/API calls. It does **not** re-implement
message, URL, QR or UPI detection/scoring - it routes each input to the
matching engine and normalizes every result into one consistent schema.

## Final frontend

The FINAL user-facing frontend is the **Flask Web Command Center** in `web/`
(`python web/app.py`). It is a thin HTTP layer over `scamshield.analyze()` /
`analyze_chain()` — see `web/README.md`. The earlier Streamlit prototype in
`app/ui.py` is retained but is NOT the final architecture.

```python
from scamshield import analyze, analyze_batch, detect_input_type, analyze_chain

analyze("message", "Your KYC has expired. Click the link now.")
analyze("url", "https://secure-sbi-verify.example.com/login")
analyze("qr", "tests/fixtures/qr/url_suspicious.png")
analyze("upi", "upi://pay?pa=merchant@upi&pn=Store&am=60&cu=INR")
analyze("chain", [message_result, url_result, upi_result])   # multi-stage chain
analyze("link_change", {"url": "https://example.com/support"})                # purify/inspect one link
analyze("link_change", {"baseline_url": "https://example.com/support",        # compare baseline vs current
                        "current_url": "https://example.com/support?redirect=evil.example"})

detect_input_type("https://example.com")   # "url"
detect_input_type("upi://pay?pa=a@upi")    # "upi"
detect_input_type("hello there")           # "message"

results = analyze_batch([
    {"type": "url", "content": "https://example.com"},
    {"content": "upi://pay?pa=a@upi&am=10"},                      # auto-detect
    ("qr", "tests/fixtures/qr/url_suspicious.png"),              # tuple form
])
```

### `analyze_chain([...])` — multi-stage scam chain analysis

`analyze_chain` is the **framework-independent chain entrypoint** (also exposed
as `analyze("chain", [...])`). It takes an ordered list of **already-analysed**
artifacts (unified results, raw engine results, or structured stage dicts) and
correlates them into a possible multi-stage scam chain. See `chain/README.md`
for the full methodology.

Top-level chain fields: `classification` (`none` | `potential_chain` |
`multi_stage_scam`), `chain_pattern` (e.g. `kyc_phishing`), `risk_score`,
`risk_level`, `is_suspicious`, `stages`, `relationships`, `explanation`,
`recommendations`, `evidence.score_breakdown`. The FULL individual engine
results are preserved under `engine_results["chain_per_stage"]`.

### Input types

`"message" | "url" | "qr" | "upi" | "chain" | "link_change"`.

Aliases for `link_change`: `"link-change"`, `"linkchange"`, `"purify"`,
`"purifier"`, `"link_purifier"`, `"link_safety"`, `"link_monitor"`, `"compare"`.

- **`message`** - routed to `scamshield.nlp.analyze_message()`.
- **`url`** - routed to `scamshield.url.analyze_url()`.
- **`qr`** - a QR **image path** routed to `scamshield.qr.analyze_qr()`.
- **`upi`** - a decoded UPI URI **string** routed through the existing
  `scamshield.qr.analyze_qr_content()`.
- **`chain`** - an ordered **list of already-analysed artifacts** routed to the
  chain correlation layer (`scamshield.chain`) - see `chain/README.md`.

Accepted aliases: `msg`/`text` → `message`; `link` → `url`;
`qrcode`/`qr_image`/`image` → `qr`; `upi_uri` → `upi`;
`chain_analysis`/`multistage` → `chain`. An unknown type returns a structured
error (`success=False`, `error_type="unsupported_type"`).

### `detect_input_type(content)`

Conservative auto-detection - returns `"url" | "upi" | "message"`:

- `^https?://` (case-insensitive) → `"url"`
- `^upi:(//)?` → `"upi"`
- everything else (including bare domains like `example.com`, image paths and
  non-string values) → `"message"` (never a dangerous guess).

### Unified result schema (top level)

Every successful analysis contains:

| Field | Meaning |
|-------|---------|
| `success` | `True` (a structured error is returned instead when `False`) |
| `input_type` | `message` / `url` / `qr` / `upi` |
| `status` | engine status (`ANALYSED`, `DECODED`, `NOT DECODED`, ...) |
| `risk_score` | integer 0-100, derived from the underlying engine score |
| `risk_level` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` per 0-24 / 25-49 / 50-74 / 75-100 |
| `is_suspicious` | boolean verdict |
| `scam_type` | one of the normalized scam-type vocabulary (below) |
| `confidence` | heuristic float 0-100 from the engine |
| `confidence_type` | always `"heuristic"` |
| `confidence_note` | "Heuristic confidence estimate, not a calibrated statistical probability." |
| `summary` | one-line, deterministic, evidence-based summary |
| `indicators` | list of detected indicator names |
| `explanation` | list of `{indicator, severity, score, reason, evidence}` |
| `recommendations` | list of actionable advice strings |
| `evidence` | dict of facts actually available for that input (see below) |
| `engine_results` | `{input_type: <full original engine result>}` - never stripped; for `message` inputs also includes `ml_analysis` |
| `warnings` | list of caveats (incl. the confidence note) |

**Error result** (`success=False`): `error`, `error_type`
(`unsupported_type` / `validation` / `engine_error`), `status="ERROR"`,
`risk_score=0`, `risk_level="LOW"`, `scam_type=None`. The analyzer never
crashes on an empty message, a malformed URL, a missing/corrupt QR file, an
unsupported type or invalid argument types - each is normalized to such a
result.

### Scam-type vocabulary

`phishing, fake_kyc, upi_payment, bank_impersonation, fake_customer_care,
job_scam, investment_scam, loan_scam, delivery_scam, lottery_prize,
social_media_impersonation, government_impersonation, credential_theft,
other, safe` - a `safe` / `other` fallback always exists.

- `message` → engine value when in the vocabulary, else `other`/`safe`.
- `url` → `phishing` if suspicious else `safe`.
- `upi` → `upi_payment` if suspicious else `safe`.
- `qr` → depends on content type (`url` → phishing, `upi` → upi_payment,
  `text` → message type, `unknown` → other/safe, `NOT DECODED` → safe).

### Evidence model

Only information that is actually available for the given input is emitted:

- **message** → `source`, plus decoded `urls` and `domains` when the message
  contains a URL.
- **url** → `source`, `urls`, `domains`, and parsed fields `url_scheme`,
  `url_hostname`, `url_root_domain`, `url_subdomains`, `url_tld`, `url_port`,
  `url_path`, `url_query`, `url_fragment`. **Parsed credentials are never
  surfaced** (username/password fields are omitted).
- **qr** → `source`, `file`, `status`, `content_type`, `decoded`,
  `decoded_count`, `multiple_codes`, `codes`, `decoded_content`, plus
  `upi`/`urls`/`domains` when a UPI / URL payload was decoded.
- **upi** → `source`, `upi` (parsed payee/amount/note/... when available).

The analyzer does **not** emit fields the engines do not produce (e.g. no
`language` - no language detection exists; no `attachments` - the message
engine has none).

### Confidence

The engines produce heuristic confidence values (the message engine returns a
float 0-100 rounded to 1 decimal place; the URL and QR engines return
integers). The unified layer preserves these as `confidence` and always labels
them `confidence_type="heuristic"` with the explicit `confidence_note` caveat -
they are **never** presented as calibrated statistical probabilities.

### Summary / recommendation generation

Deterministic and evidence-based - there is no LLM. Summaries are assembled
from the normalized scam type, risk level, detected indicators and parsed
facts; recommendations come from the underlying engine.

### ML integration (message inputs)

For `message` inputs the unified analyzer **also** runs the local ML
classifier (`scamshield.ml.predict_message`) and exposes it under
`engine_results["ml_analysis"]`, alongside the full deterministic result under
`engine_results["message"]`:

```text
engine_results:
    message:      { ... deterministic rule result (is_scam, risk_score, ...) ... }
    ml_analysis:  { prediction, score, confidence, confidence_type, ... }
```

**The two scores are never averaged or blended.** The authoritative top-level
`risk_score`, `risk_level`, `is_suspicious` and `scam_type` remain driven
**entirely by the deterministic rule engine**, so a weak or missing ML
prediction can never hide a real security signal. If the model is unavailable,
`analyze()` still succeeds and `ml_analysis` reports
`model_available: False`. ML confidence uses `confidence_type` of either
`model_probability` (Logistic Regression) or `normalized_decision_score`
(explicitly not a probability), and is never presented as certainty. See
`ml/README.md`.

### Determinism, locality and security

Analysis is fully **local and deterministic** (identical input → identical
output, no random seeds, results returned in input order for batches). It
makes **no network requests**, opens **no URLs**, executes **no payments**,
uses **no external APIs and no API keys**. The dive into host reputation,
content fetching and DNS is intentionally out of scope.

### Framework independence

`from scamshield import analyze` is a plain Python function - no HTTP
framework, no global state - so a web UI / HTTP API can call it directly
(the final `web/` Flask frontend already returns `analyze(...)` serialized to
JSON, which is fully JSON-serializable).

## Command line

A small demo CLI provides a consistent interface over all four types
(`python -m app.scan`, `python -m app.url_scan` and `python -m app.qr_scan`
remain untouched):

```bash
python -m app.analyze                              # interactive menu
python -m app.analyze --type message --input "Your KYC has expired..."
python -m app.analyze --type url --input "https://secure-sbi-verify.example.com/login"
python -m app.analyze --type qr --input "tests/fixtures/qr/url_suspicious.png"
python -m app.analyze --type upi --input "upi://pay?pa=scam@refunds&am=50000&tn=reward"
python -m app.analyze --type url --input "https://example.com" --json   # raw JSON
```

## Tests

```bash
python -m pytest tests/ -q
# 550 passed (50 message + 95 URL + 56 QR + 84 unified analyzer
#             + 40 ML intelligence + 49 chain correlation + 37 link_change purifier
#             + 37 safety zones + 16 frontend + 30 research evaluation + 56 Flask API & E2E scenarios)
```

The unified layer is covered by `tests/test_unified_analyzer.py` (84 tests,
including a monkeypatched-socket no-network guard). The chain layer is covered
by `tests/test_chain_analysis.py` (49 tests). The research & evaluation lab is
covered by `tests/test_research.py` (30 tests). The safety-zone / explainable
risk layer is covered by `tests/test_safetyzones.py` (37 tests: exact
GREEN/YELLOW/RED boundary behaviour, evidence-only reasons/breakdowns, schema
compatibility, link-change integration and no-network guards). The final Flask
frontend is covered by `tests/test_flask_api.py` and `tests/test_web_scenarios.py`
(56 tests, including QR temp-file cleanup, the link-change endpoint, and a
no-network guard). The build-time reload no-network guard covers every engine
including `link_change`.

### Research & Evaluation Lab

`python -m app.research_eval` runs a fully local, deterministic evaluation of
the existing system against the labelled dataset — see `research/README.md` for
methodology and `models/research/` for generated artefacts. It never modifies
dataset files and never touches the network.
