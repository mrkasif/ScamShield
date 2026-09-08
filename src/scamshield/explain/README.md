# `explain/` - Explainability Layer

Responsible for: **Converting model outputs and features into human-readable reasons.**

Intended responsibilities (Step 6 - not yet implemented):

- Translate model features, indicators, and risk evidence into plain-language reasons
- Explain *why* a message/URL/QR was flagged as suspicious
- Produce the final safety recommendation in user-friendly language
- Interface with the risk score and scam-type classification

This is the layer that makes the system **explainable** (as opposed to a black-box classifier).
