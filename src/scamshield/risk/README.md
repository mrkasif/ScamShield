# `risk/` - Risk Engine

Responsible for: **Combining evidence into a 0-100 risk score.**

Intended responsibilities (Step 6 - not yet implemented):

- Combine evidence from NLP, URL, and QR analysis components
- Produce a calibrated risk score in the range 0-100
- Map the score to a risk level (low / medium / high / critical)
- Provide the final scam-type classification
- Generate recommended safety actions

Output feeds into the Explainability layer (`explain/`) and then to the user.
