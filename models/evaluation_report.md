# ScamShield ML Evaluation Report

## Validation set

- **Model**: scamshield_ml_tfidf_logreg
- **Samples (n)**: 83 (train=285, validation=83, test=106)
- **Class distribution**: {'scam': 61, 'safe': 22}
- **Training class distribution**: {'safe': 105, 'scam': 180}

| Metric | Value |
|--------|-------|
| accuracy | 0.9639 |
| precision | 0.9677 |
| recall | 0.9836 |
| f1 | 0.9756 |

### Confusion matrix (positive='scam')

| | Predicted scam | Predicted safe |
|---|---|---|
| Actual scam | 60 (TP) | 1 (FN) |
| Actual safe | 2 (FP) | 20 (TN) |

- **False negatives (missed scams)**: 1
- **False positives (safe flagged)**: 2

> False negatives = scam predicted as safe (missed threats - the higher-risk error for users). False positives = safe predicted as scam (harms trust / causes friction).
> Note: the dataset is class-imbalanced (safe vs scam counts differ). Accuracy alone is misleading; precision/recall/F1 and the confusion matrix are the reported headline.


## Test set (frozen held-out)

- **Model**: scamshield_ml_tfidf_logreg
- **Samples (n)**: 106 (train=285, validation=83, test=106)
- **Class distribution**: {'scam': 80, 'safe': 26}
- **Training class distribution**: {'safe': 105, 'scam': 180}

| Metric | Value |
|--------|-------|
| accuracy | 0.9906 |
| precision | 1.0 |
| recall | 0.9875 |
| f1 | 0.9937 |

### Confusion matrix (positive='scam')

| | Predicted scam | Predicted safe |
|---|---|---|
| Actual scam | 79 (TP) | 1 (FN) |
| Actual safe | 0 (FP) | 26 (TN) |

- **False negatives (missed scams)**: 1
- **False positives (safe flagged)**: 0

> False negatives = scam predicted as safe (missed threats - the higher-risk error for users). False positives = safe predicted as scam (harms trust / causes friction).
> Note: the dataset is class-imbalanced (safe vs scam counts differ). Accuracy alone is misleading; precision/recall/F1 and the confusion matrix are the reported headline.
