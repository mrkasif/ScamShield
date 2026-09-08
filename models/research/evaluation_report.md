# ScamShield Research Evaluation Report

- **Generated**: 2026-09-08T13:06:48.906620+00:00
- **Random seed**: N/A (deterministic, no stochastic process)

## 1. Dataset Profile

| Split | Raw rows | Deduplicated rows |
|-------|---------|-------------------|
| Train | 356 | 285 |
| Validation | 88 | 83 |
| Test | 110 | 106 |
| **Total** | **554** | **474** |

**Test set (deduped, n=106)**
- scam: 80 | safe: 26
- languages: {'hinglish': 29, 'hi': 24, 'en': 32, 'mr': 21}
- scam categories: {'delivery': 6, 'loan': 5, 'kyc': 15, 'bank_impersonation': 15, 'upi_payment': 11, 'investment': 4, 'job': 4, 'lottery': 4, 'customer_care': 4, 'other': 4, 'social_impersonation': 4, 'phishing': 4}

## 2. Leakage Audit

- **Normalised texts in multiple splits**: 99
- **Exact texts in multiple splits**: 12
- **Overlap type**: normalised
- **Affected pairs**: ['train-validation', 'train-test', 'validation-test']
- **Recommendation**: 99 normalised text(s) appear in more than one split. To obtain a leakage-clean evaluation, exclude test rows whose normalised text appears in train or validation before computing held-out metrics. The original dataset files must not be modified; the leakage is detected and reported, and a leakage-clean evaluation subset can be derived at runtime.

## 3. System Comparison (frozen test set)

| System | Accuracy | Precision | Recall | F1 | n |
|--------|----------|-----------|--------|----|---|
| Rule Engine | 0.7736 | 0.9667 | 0.7250 | 0.8286 | 106 |
| Local ML | 0.9906 | 1.0000 | 0.9875 | 0.9937 | 106 |
| Combined ScamShield | 0.7736 | 0.9667 | 0.7250 | 0.8286 | 106 |

**Positive prediction definitions**:

- Rule: positive='scam' when the deterministic rule engine fires: nlp.analyze_message(text)['is_scam'] == True.
- ML:   positive='scam' when the trained TF-IDF + Logistic Regression model predicts scam: ml.predict_message(text)['prediction'] == 'scam' (model_available must be True).
- Combined: positive='scam' when the unified analyzer classifies the message as suspicious: scamshield.analyze('message', text)['is_suspicious'] == True. On message inputs, the top-level verdict is driven by the deterministic rule engine; ML is attached under engine_results but does not alter the top-level is_suspicious. The combined result therefore matches the rule engine on the message benchmark by design.

## 4. Leakage-Clean Combined Evaluation

- Leakage-clean subset: 37 of 106 test samples retained (69 excluded because their normalised text appeared in train or validation).

## 5. Detection Latency

- Iterations per engine: 20
- **message**: mean=28.210ms, median=27.681ms, min=27.239ms, max=31.400ms
- **url**: mean=1.809ms, median=1.583ms, min=1.548ms, max=4.268ms
- **upi**: mean=0.247ms, median=0.148ms, min=0.068ms, max=2.407ms
- **qr**: mean=23.282ms, median=22.990ms, min=21.545ms, max=26.788ms
- **unified_message**: mean=27.784ms, median=27.615ms, min=25.758ms, max=29.545ms

## 6. Per-Language Evaluation (Combined)

- **en** (n=32): accuracy=0.8125, precision=0.9048, recall=0.8261, F1=0.8636
- **hi** (n=24): accuracy=0.75, precision=1.0, recall=0.6842, F1=0.8125
- **hinglish** (n=29): accuracy=0.8276, precision=1.0, recall=0.7619, F1=0.8649
- **mr** (n=21): accuracy=0.6667, precision=1.0, recall=0.5882, F1=0.7407

## 7. Per-Category Evaluation (Combined, one-vs-rest)

| Category | n | Accuracy | Precision | Recall | F1 |
|----------|---|----------|-----------|--------|----|
| bank_impersonation | 15 | 0.5 | 0.1833 | 0.7333 | 0.2933 |
| delivery | 6 | 0.4528 | 0.0667 | 0.6667 | 0.1212 |
| kyc | 15 | 0.5566 | 0.2333 | 0.9333 | 0.3733 |
| loan | 5 | 0.4623 | 0.0667 | 0.8 | 0.1231 |
| upi_payment | 11 | 0.4811 | 0.1333 | 0.7273 | 0.2254 |

## 8. Representative Misclassified Examples (Rule Engine)

### False Negatives (22 total)

- `ss-000020` [scam→safe] lang=hi scam_type=bank_impersonation
  > आपका बैंक खाता सत्यापन लंबित है, कृपया तुरंत अपडेट करें immediately
- `ss-000027` [scam→safe] lang=mr scam_type=delivery
  > पार्सल कस्टम्स मध्ये अडकले. ₹35 [URL] वर भरा.
- `ss-000052` [scam→safe] lang=en scam_type=upi_payment
  > Your Paytm payment of Rs 1 failed. Pay the remaining Rs 1 on [URL] to receive a refund.
- `ss-000057` [scam→safe] lang=hi scam_type=delivery
  > पार्सल कस्टम में अटका है। ₹35 [URL] पर दें।
- `ss-000060` [scam→safe] lang=hinglish scam_type=bank_impersonation
  > Aapka ATM card block ho gaya hai, details update kare abhi kare

### False Positives (2 total)

- `ss-000091` [safe→scam] lang=en
  > SBI: UPI is active. Do not share UPI PIN with anyone, including people claiming to be staff.
- `ss-000276` [safe→scam] lang=en
  > Your loan EMI is paid. SBI will not call to ask for a processing fee refund.

## 9. Limitations and Research Integrity Notes

- The labelled dataset is synthetic (template-generated) and a small public sample — evaluation numbers do not generalise to production traffic.
- Cross-split normalised leakage means held-out metrics are somewhat optimistic.
- The rule engine is deliberately conservative; its design favours recall (catching scams) over precision and may produce more false positives.
- The ML model is trained on a tiny, class-imbalanced dataset; its reported metrics are not reliable indicators of production performance.
- URL reputation / DNS / live content analysis are out of scope; the URL engine is static and structural only.
- QR decoding depends on the local cv2 backend; QR latency varies by image.
- No live threat intelligence or external APIs are used anywhere in the pipeline.
- Language stratification results are indicative only; per-language sample sizes are small and should not be extrapolated.
- The combined ScamShield message verdict is driven entirely by the deterministic rule engine by design; ML is kept separate under engine_results and does not alter the top-level verdict.
