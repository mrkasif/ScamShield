# Models

Trained ML artifacts for the ScamShield pipeline are stored here.

## Status

**Implemented** - a binary `scam`/`safe` classifier (TF-IDF + Logistic
Regression) has been trained and evaluated. See
`src/scamshield/ml/README.md` for full documentation.

## Files

| File | Purpose |
|------|---------|
| `scamshield_tfidf.joblib` | The trained model bundle `{vectorizer, classifier, meta}` (git-ignored) |
| `metrics.json` | Machine-readable evaluation metrics (validation + test) |
| `evaluation_report.md` | Human-readable evaluation report |
| `README.md` | This file |

The `.joblib` / `.pkl` / `.pt` model files are **git-ignored** by default
(see `.gitignore`) so the repository stays small; `metrics.json` and
`evaluation_report.md` are plain text and can be committed.

## Retraining

```bash
python -m src.scamshield.ml.train
```

Trains on `data/train/messages.csv`, tunes/validates on
`data/validation/messages.csv`, and reports final numbers on the **frozen**
`data/test/messages.csv` (never used for training or model selection).

## Chosen baseline

- **TF-IDF** (word 1-2 grams + char 3-5 grams via `FeatureUnion`)
- **Logistic Regression** linear classifier (`class_weight="balanced"`)

Selected for speed, interpretability and reproducibility on a small, sparse,
multilingual (en/hi/mr/hinglish) scam-message dataset. See
`src/scamshield/ml/README.md` for the rationale and limitations.

## Planned future models (not yet built)

- Scam-type (multiclass) classifier - deferred because the current dataset has
  too few examples per category.
- Comparators: Naive Bayes / Linear SVM baselines.
