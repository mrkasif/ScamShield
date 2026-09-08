# ScamShield Research & Evaluation Lab

A reproducible, completely local evaluation framework that measures how well
the existing ScamShield system performs against the labelled dataset. No network,
no external APIs, no model changes — evaluation only.

## Quick start

```bash
# Full evaluation (writes artefacts under models/research/)
python -m app.research_eval

# Machine-readable JSON output
python -m app.research_eval --json

# Skip latency measurement (faster)
python -m app.research_eval --skip-latency

# Custom output directory
python -m app.research_eval --output-dir my_eval_output

# Custom latency iterations
python -m app.research_eval --iterations 50
```

## Module structure

```
src/scamshield/research/
├── __init__.py          exports run_full_evaluation, write_artifacts
├── datasets.py          load/train/validation/test splits, profile, dedup
├── leakage.py           formal normalised + exact cross-split leakage audit
├── evaluate.py          rule / ML / combined evaluators, comparison table
├── stratified.py        per-language and per-category stratified evaluation
├── latency.py           deterministic repeated latency measurement
├── sanitize.py          defensive text sanitisation for FP/FN examples
├── metrics.py           binary classification metrics (reuses ml.evaluate)
├── runner.py            orchestration + JSON/CSV/MD artifact writer
└── README.md            this file
```

## What is evaluated

### Systems compared

| System | Positive prediction | Source |
|--------|-------------------|--------|
| **Rule Engine** | `is_scam == True` | `scamshield.nlp.analyze_message()` |
| **Local ML** | `prediction == "scam"` | `scamshield.ml.predict_message()` |
| **Combined ScamShield** | `is_suspicious == True` | `scamshield.analyze("message", ...)` |

For messages, the combined ScamShield verdict is driven entirely by the
deterministic rule engine — ML is kept separate under `engine_results` and
does not alter the top-level `is_suspicious`. The combined result therefore
matches the rule engine on the message benchmark **by design**; this is an
honest design property, not a bug.

### Metrics computed

- Accuracy, Precision, Recall, F1 (binary: scam vs safe)
- Confusion matrix (TP, TN, FP, FN)
- Per-language stratified metrics (English, Hindi, Marathi, Hinglish)
- Per-category one-vs-rest metrics (where sample size >= 5)
- False Positive / False Negative representative examples (sanitised)
- Detection latency (mean, median, min, max, stdev)

### Dataset

- **Processed**: `data/processed/messages.csv` — full labelled table
- **Splits**: `data/train/messages.csv`, `data/validation/messages.csv`, `data/test/messages.csv`
- **Frozen**: the test split is never used for training or model selection
- **Labels**: binary `scam`/`safe`, plus `scam_type`, `language`, `source` metadata
- **Schema**: see `data/schema.md`
- **Privacy**: no real PII — placeholders only (`[OTP]`, `[PHONE]`, `[ACCOUNT]`, etc.)

## Artefacts written

All artefacts are written under `models/research/` (configurable):

| File | Contents |
|------|----------|
| `evaluation_summary.json` | Complete evaluation summary (machine-readable) |
| `model_comparison.csv` | System comparison table (System / Accuracy / Precision / Recall / F1) |
| `confusion_matrices.json` | Confusion matrix for each system |
| `language_results.json` | Per-language evaluation breakdown |
| `category_results.json` | Per-category one-vs-rest evaluation |
| `latency_results.json` | Engine latency measurements |
| `leakage_report.json` | Formal leakage audit (normalised + exact) |
| `fp_fn_examples.json` | Sanitised representative misclassified examples |
| `evaluation_report.md` | Full human-readable Markdown report |

## Reproducibility

- All evaluation is deterministic — no random seeds, no stochastic processes
- Same inputs always produce same outputs
- Dataset splits are documented and frozen
- All file paths are documented in the summary output
- No network access is made during evaluation

## Limitations and research integrity

**Do not interpret high evaluation scores as production readiness.**

- The dataset is synthetic (template-generated) — scores do not generalise
  to real-world scam traffic
- Cross-split normalised leakage means held-out metrics are somewhat
  optimistic
- The ML model is trained on ~285 samples — too small for reliable
  generalisation
- The rule engine is deliberately conservative (favours recall over
  precision); expect more false positives
- URL analysis is static/structural only — no reputation, DNS or content
  analysis
- QR decoding depends on the local OpenCV backend
- No live threat intelligence or external APIs are used
- Language stratification results are indicative only; per-language sample
  sizes are small
- The combined ScamShield message verdict is driven by the rule engine
  by design — ML evidence is separate and does not alter the top-level
  verdict

## Running the research module directly (Python API)

```python
from scamshield.research import run_full_evaluation, write_artifacts

summary = run_full_evaluation(data_root="data", include_latency=True)
write_artifacts(summary, "models/research")
```

## Tests

```bash
# Research evaluation framework tests
python -m pytest tests/test_research.py -q

# Full test suite (should remain green)
python -m pytest tests/ -q
```
