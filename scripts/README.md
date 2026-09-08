# Scripts

| File | Step | Role | Status |
|------|------|------|--------|
| `build_dataset.py` | 2 | Build labelled CSV splits (stdlib only) | Implemented |
| `train_binary.py` | 3 | Scam vs safe baseline training | Not yet |
| `train_type.py` | 4 | Scam-type classifier training | Not yet |
| `evaluate.py` | 5 | Metrics on the frozen test set | Not yet |

## `build_dataset.py`

Generates the labelled dataset for the ScamShield project. Run from the repo root:

```bash
python scripts/build_dataset.py
```

Behavior:

1. Builds synthetic multilingual scam + safe examples in English, Hindi, Marathi, and Hinglish (all 13 scam categories).
2. Optionally loads and curates rows from `data/raw/ultra_premium_scam_dataset.csv` (HuggingFace public dataset). Urgency-phrased "legit" rows are excluded as noisy.
3. Sanitizes each text (phone → `[PHONE]`, account → `[ACCOUNT]`, OTP → `[OTP]`).
4. Deduplicates, then applies a **stratified split** (by label/type/language) into train (~70%), validation (~15%), test (~15%), seeded at 42.
5. Writes:
   - `data/processed/messages.csv` (full table with `split` column)
   - `data/train/messages.csv`
   - `data/validation/messages.csv`
   - `data/test/messages.csv` (frozen)
   - `data/processed/summary.json` (counts by label/type/language/source)

The test split is frozen (seed-stable) and must not be used for training or model selection.
