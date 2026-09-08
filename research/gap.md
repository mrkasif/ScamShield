# Research Gap

**Indian Digital Scam Intelligence & Prevention System (ScamShield)**

Draft research gap statement.

## Problem

Indian users increasingly receive scam messages and links across:

- SMS
- WhatsApp, Telegram, and other messaging platforms
- Malicious/suspicious URLs
- QR codes
- Social-engineering schemes (KYC, UPI, bank impersonation, jobs, etc.)

These messages appear in multiple Indian languages (Hindi, Marathi, etc.) and in code-mixed Hinglish, complicating detection for tools designed around English-only or single-language inputs.

We do **not** claim that AI-based scam detection is a novel invention. Scam/fraud detection is an established field with substantial prior work. The scope of this investigation is the **combination** of factors that existing tools may not adequately address together.

## Existing solutions (to be completed with literature review)

*(Pending: list 4-6 relevant tools/papers, noting for each: what it detects, language coverage, binary vs. typed classification, explainability, and whether it handles Hinglish/multilingual inputs.)*

## Proposed research gap

The gap this project investigates is the **combination** of:

1. **Indian-focused scam data** - patterns specific to Indian platforms (UPI, PhonePe, GPay, Paytm, BHIM, Aadhaar, KYC, bank impersonation)
2. **Multilingual support** - English, Hindi, Marathi
3. **Hinglish handling** - code-mixed text that standard English/Devanagari NLP pipelines often handle poorly
4. **Scam-type classification** - not just binary scam/safe, but identifying the specific scam category
5. **Explainable AI** - human-readable reasons for every decision, enabling user trust and understanding
6. **Risk scoring** - a continuous 0-100 score rather than a hard binary threshold
7. **Multi-input analysis** - processing messages, URLs, and QR codes together
8. **Lightweight models** - models that run without GPU, suitable for low-cost deployment

Individually, several of these capabilities exist in various products and papers. The **proposed investigation** is whether these requirements can be combined effectively in one lightweight, explainable prototype using free/open-source components, and how well baseline models perform on Indian-focused multilingual data.

## Research questions (draft)

- How well do classical baseline models (TF-IDF + Logistic Regression / Naive Bayes / Linear SVM) perform on Indian multilingual scam data?
- Does a lightweight model perform comparably to heavier alternatives, making it suitable for low-cost deployment?
- Can explainability be provided in a way that is meaningful to non-technical Indian users (across languages)?
- How should evidence from message text, URLs, and QR codes be combined into a single risk score?

## Proposed methodology

Dataset (synthetic + curated public data, multilingual, sanitised)
→ preprocessing
→ stratified train/validation/test split (frozen test set)
→ baseline ML models
→ comparative evaluation (precision, recall, F1, confusion matrix)
→ model improvement (feature engineering, hyperparameter tuning)
→ explainability layer
→ risk engine
→ URL/QR analysis
→ prototype integration
→ unseen testing

## What we do not claim

- We did not invent AI scam detection.
- We do not claim our dataset is exhaustive or perfectly representative of all Indian scam patterns.
- We do not claim our models outperform all existing commercial products.
- We do not claim perfect or production-ready accuracy; results will be reported honestly with limitations.

## Limitations (to be confirmed during experiments)

- Public dataset noise and labelling inconsistencies
- Limited Marathi coverage relative to English/Hindi
- Synthetic data may not capture the full distribution of real scam messages
- Baseline models may not capture long-range semantics in code-mixed text
- Hinglish is a spectrum; a single `hinglish` label may be coarse

## Future scope (not required for initial prototype)

- Multi-stage scam-chain analysis: detecting sequences of related scam messages rather than isolated instances
- Financial-risk scoring and multi-input fusion improvements
- Real-time simulation of live scam detection
