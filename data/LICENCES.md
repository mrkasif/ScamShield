# ScamShield Dataset Licences

Record each source before use. Do not add a dataset if the licence is unclear or forbids redistribution.

| Source | URL | Licence | Date added | Notes |
|--------|-----|---------|------------|-------|
| ScamShield synthetic messages | `scripts/build_dataset.py` | Original to this project (use freely for Aavishkar) | 2026-09-06 | Privacy-safe templates. Placeholders only. Not real user SMS. |
| Indian Multilingual Scam Message Dataset (Karan Verma) | https://huggingface.co/datasets/karanverma19/Indian_Multilingual_Scam_Message_Dataset | Apache-2.0 | 2026-09-06 | File: `data/raw/ultra_premium_scam_dataset.csv`. Noisy templates; noisy "legit" rows with urgency phrases were **not** mapped into train/val/test. |

## Not used (and why)

| Source | Why skipped |
|--------|-------------|
| `gandharvbakshi/SMS-dataset-OTP-OTP_INTENT_Phishing` | Mix of real-world SMS; OTP/PII risk even if MIT-licensed. |
| Kaggle Indian social-media fraud set | Needs a Kaggle account; not required for v1. |
| `anmolshrivastav/scam-hum-india` | Licence on the card was not verified before use; English-only. |

## Verification notes

- The licence for `karanverma19/Indian_Multilingual_Scam_Message_Dataset` is listed as Apache-2.0 on the HuggingFace page. **This should be independently verified** before any public distribution of the project.
- The ScamShield synthetic data is original to this project and free to use for Aavishkar purposes. Formal licensing for public release is TBD.
- **Do not add any dataset source whose licence has not been explicitly verified.**

## Dataset safety

The final research dataset must **NOT** contain real:

- OTPs
- Passwords
- Bank account numbers
- Card numbers
- Private messages
- Personal addresses
- Real authentication credentials
- Unnecessary personally identifiable information

Synthetic examples and legally usable public datasets are preferred. The current dataset has been sanitised using placeholder substitution in `scripts/build_dataset.py`, but **full privacy audit of the public dataset rows has not been completed yet**.
