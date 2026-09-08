# ScamShield Multi-Stage Scam / Attack Chain Analysis

> **Status**: research/prototype correlation layer. This component is **not** a
> guarantee that a sequence of artifacts is malicious — it is a deterministic,
> explainable *correlation* of independently-detected risk signals.

This layer answers the following question:

> *Do the individually-analyzed artifacts (message, URL, QR, UPI) form a
> suspicious sequence — a possible multi-stage scam chain?*

Examples of the kind of sequence it detects:

```
SMS / Message
      ↓
Suspicious URL
      ↓
Credential / KYC Request
      ↓
UPI / Payment Request
```

```
Stage 1: Fake KYC SMS
Stage 2: Link to a suspicious verification domain
Stage 3: Sensitive-information (Aadhaar/OTP) request
Stage 4: Payment / UPI request
```

## Purpose

Individual detection is powerful but **context-free**: a message, a URL, a QR
code and a UPI URI are each analysed in isolation. Attackers routinely chain
these artifacts: a fake SMS embeds a phishing URL, the URL collects
credentials, and the payoff is a UPI payment. Correlating them turns four
moderate-risk artifacts into one high-conviction, explainable chain.

Multi-stage scam / attack-chain analysis itself is NOT a newly invented concept
— it is a long-established technique in fraud analytics. This package is an
**implemented correlation / research enhancement for Indian scam analysis**,
applied to the existing ScamShield engines.

## Non-goals (important)

The chain layer is **deliberately not**:

* another detection engine — it never re-runs message/URL/QR/UPI rules;
* an LLM / AI that "reads" the chain and produces prose;
* a web connector — it never opens URLs, resolves DNS, follows redirects,
  downloads content, crawls sites, or calls threat-intelligence APIs;
* a payment executor or data transmitter — text never leaves the process.

## Architecture

```
src/scamshield/chain/
├── __init__.py      public API (analyze_chain, Stage, ...)
├── models.py        normalized Stage representation + input normalization
├── correlate.py     relationship detection + artifact matching
├── scoring.py       transparent 0–100 chain scoring formula
├── explain.py       chain patterns + explanations + recommendations
├── analyzer.py      orchestration entrypoint (analyze_chain)
└── README.md        this file
```

### Data flow

```
[message/url/qr/upi engine results]        (already analysed — never re-analysed)
        │  normalize_stage()  (models.py)
        ▼
[Stage list: type, risk, indicators, urls, domains, payee, ...]
        │  build_relationships()  (correlate.py)
        ▼
[explained relationships + artifact matches]
        │  detect_pattern()  (explain.py)
        ▼
[recognized chain pattern, if any]
        │  score_chain()  (scoring.py)
        ▼
[0–100 chain score + breakdown]
        │  analyze_chain()  (analyzer.py)
        ▼
[JSON result: classification, pattern, relationships, explanation, ...]
```

## Input

`analyze_chain(stages)` accepts an ordered list where each item is **any already
analysed artifact**:

* a raw engine result (`scamshield.nlp.analyze_message`, `analyze_url`,
  `analyze_qr`, `analyze_qr_content`);
* a unified analyzer result (`scamshield.analyze` / `analyze("message", ...)`
  etc., which carries `engine_results`);
* an explicitly structured stage dict:
  `{"type": "url", "risk_score": 72, "urls": [...], ...}`;
* a `Stage` instance.

Each item is normalized into a `Stage` that preserves:

* stage ID / input order,
* artifact type (`message | url | qr | upi`),
* the original analysis result (`raw`),
* risk score / risk level / suspicious flag,
* scam type,
* indicators,
* extracted URLs / registrable domains,
* UPI metadata (payee address, amount, currency, transaction reference).

The chain analyzer does **not** duplicate the NLP / URL / QR / UPI detection
logic — it reads only the normalized fields above.

## Supported chain shapes

The analyzer does not force every stage type to appear. It supports any ordered
subset of `message`, `url`, `qr`, `upi`, e.g.:

```
message → url
message → qr → upi
message → url → upi
url    → credential request
qr     → url
qr     → upi
```

## Correlation methodology (`correlate.py`)

Correlations are **deterministic and explainable** — each relationship carries a
machine-readable `relation`, a human `label`, a `strength` (0..1), a
`match_type`, and concrete `evidence` strings.

### Relationship types

| Source → Destination | Relation | When |
|---|---|---|
| message → url / qr | `message_leads_to_url` | message references a URL, or is suspicious with compatible signals |
| message → upi / qr | `message_leads_to_payment` | message asks for money / has payment or urgency language |
| url → upi | `url_to_payment_continuation` | suspicious URL leads into a payment destination |
| qr → url | `qr_to_url_continuation` | QR decodes to the separately-analysed URL |
| qr → upi | `qr_to_upi_continuation` | QR decodes to the analysed UPI destination |
| flagged + consistent | `consistent_flagged_sequence` | both suspicious with the same scam family |

A relationship is **only emitted when there is real evidence**. A plain safe
message followed by an unrelated suspicious URL contributes **no** relationship
and is not classified as a chain — it depends on the individual artifacts.

### Artifact matching

* **URLs**: scheme/hostname normalized via a local, scheme-requiring parser.
  Exact string matches (host + path, case-insensitive) become `match_type:
  "exact"`; shared registrable root (e.g. `login.example.com` vs
  `verify.example.com`) becomes `match_type: "domain"`.
* **UPI**: normalized payee address matches become `match_type: "upi"`. Amount
  and transaction/reference identifiers are compared only when already present
  in the supplied analysis.
* Credentials embedded in URLs are **never** exposed; the chain never resolves
  DNS, visits URLs, or follows redirects.

## Recognized chain patterns (`explain.py`)

Patterns are **decision functions** over normalized stage signals (source
language family + destination type). Each input maps to at most ONE primary
pattern; if none matches, `chain_pattern` is `None` (never forced).

| Pattern | Source signal | Destination |
|---|---|---|
| `kyc_phishing` | KYC / account-warning / credential language, or QR→verification URL | credential-sensitive URL / credential request |
| `payment_scam` | generic urgent / payment message (not prize/job/loan/etc.) | UPI / payment destination |
| `prize_refund` | prize / refund / reward / cashback language | payment destination |
| `fake_customer_care` | customer-care / helpline / bank impersonation | URL or payment request |
| `job_scam` | job / work-from-home / salary language | URL or payment request |
| `investment_scam` | investment / crypto / trading language | URL or payment request |
| `loan_scam` | loan / credit / approval language | URL or payment request |

These are **patterns, not hardcoded claims** that every sequence is malicious.

## Scoring formula (`scoring.py`)

The chain score is **not a simple average** of the stage scores. It is:

```
floor       = max(stage.risk_score)                         # never diluted
stage_bonus = Σ_{i=1..N} STAGE_INCREMENT / 2^(i-1)          # diminishing
rel_bonus   = min( RELATION_BONUS_CAP, Σ strength² · RELATION_WEIGHT )
category    = min( CATEGORY_BONUS_CAP, n_consistent · CATEGORY_BONUS )  # n>=2
progress    = PROGRESS_BONUS   (sensitive-information/payment progression)
pattern     = PATTERN_BONUS    (recognized chain pattern)

raw         = floor + stage_bonus + rel_bonus + category + progress + pattern
score       = min(100, raw)
```

### Constants (all deliberately small/capped)

| Constant | Value | Meaning |
|---|---|---|
| `STAGE_INCREMENT` | 7 | marginal bonus per suspicious stage |
| `RELATION_WEIGHT` | 26.0 | weight of validated relationship strength |
| `RELATION_BONUS_CAP` | 40.0 | hard cap on total relationship bonus |
| `CATEGORY_BONUS` | 4.0 | per consistent-category flagged stage |
| `CATEGORY_BONUS_CAP` | 8.0 | hard cap on category bonus |
| `PROGRESS_BONUS` | 8.0 | sensitive-info/payment progression bonus |
| `PATTERN_BONUS` | 6.0 | recognized-pattern bonus |

### Guarantees

* The chain score is **never lower than the strongest individual stage**.
* A single repeated indicator **cannot inflate the score**: stage_bonus decays
  geometrically, relationship strength is squared+capped, and every bonus has a
  hard cap.
* The score saturates at `100`.

### Risk levels

The chain reuses the existing normalized scale — there is **no second,
incompatible risk-level system**:

| Range | Level |
|---|---|
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–74 | HIGH |
| 75–100 | CRITICAL |

Every result publishes `risk_score` and `risk_level` and includes the numeric
breakdown under `evidence.score_breakdown` for transparency.

## Classification

Each chain is normalized into one of:

* `none` — no correlated multi-stage sequence;
* `potential_chain` — some correlation/evidence but not strong enough to claim;
* `multi_stage_scam` — a strong, correlated, cross-stage scam progression.

`chain_pattern` is one of: `kyc_phishing`, `payment_scam`, `prize_refund`,
`fake_customer_care`, `job_scam`, `investment_scam`, `loan_scam`, `mixed` (or
`None` when no pattern is supported).

## Explainability

The result contains:

1. `stages` — what each stage represents and its normalized signals;
2. `relationships` — why stages are connected, with match_type + evidence;
3. `chain_pattern` — which pattern was detected (if any);
4. `evidence.score_breakdown` + `explanation` — why the final score was assigned;
5. `recommendations` — deterministic, actionable next steps.

Example generated prose:

```
Stage 1 (Message): flagged suspicious (HIGH, risk 67/100); scam category:
fake_kyc; contains KYC/credential/verification language; contains
urgency/account-warning language.
Relationship stage 1 -> stage 2 (message_leads_to_url): Message leads to a
suspicious URL.
  evidence: the exact URL appears in both stages: https://secure-sbi-...
Chain pattern detected: kyc_phishing.
```

Evidence is always grounded in the actual stage/relationship data — the chain
**never invents evidence**.

## Unified analyzer integration

Two integration points (both additive; nothing in the existing API breaks):

```python
from scamshield import analyze_chain
analyze_chain([message_result, url_result, upi_result])

from scamshield import analyze
analyze("chain", [message_result, url_result, upi_result])
```

The existing individual calls — `analyze("message", ...)`,
`analyze("url", ...)`, `analyze("qr", ...)`, `analyze("upi", ...)` — continue
to work unchanged. Chain mode:

* preserves the FULL individual engine results under
  `engine_results["chain_per_stage"]`;
* exposes the chain verdict under `engine_results["chain"]`;
* promotes the chain verdict to the unified top-level fields
  (`risk_score`, `risk_level`, `is_suspicious`, plus `classification`,
  `chain_pattern`, `stages`, `relationships`).

The chain analyzer is an additional layer, not a replacement.

## Robustness

The chain analyzer never crashes on malformed input:

* empty chains → `classification: none`, `risk_score: 0`;
* non-list / non-dict stages → structured warnings (not crashes);
* unsupported artifact types → warnings;
* duplicate / repeated stages → preserved in input order, deduplicated at the
  indicator level, and the scoring caps prevent inflation;
* missing engine results → graceful `none`.

`confidence` is always `confidence_type: "heuristic"` — it mirrors the chain
score and is **not** called a statistical probability.

## Security & offline guarantee

This component is completely offline. It never:

* opens URLs,
* resolves DNS,
* follows redirects,
* downloads content,
* crawls websites,
* executes files or QR payloads,
* contacts threat-intelligence APIs,
* contacts payment services,
* calls external AI APIs,
* transmits user data.

It operates strictly on the supplied analysis results and metadata. Data-safety:
no credentials, OTPs, passwords, card numbers, or tokens are ever persisted or
exposed — only derived risk signals and normalized domain/payee metadata.

## Limitations & false-positive considerations

* **It is correlation, not proof.** Two independently-flagged artifacts that
  merely appear in the same conversation are correlated only when concrete
  evidence links them (matching URL / domain / payee / category / progression).
  Even then the verdict is `potential_chain` unless strong and multi-stage.
* **The chain cannot rescue a weak individual detection.** If the individual
  engines do not flag a message or UPI, the chain layer does not invent
  suspicion (see the honest `none` results in the manual verification).
* **The dataset and patterns are Indian-scam-centric.** Patterns are tuned to
  common KYC / UPI / prize-refund / customer-care / job / loan flows; novel or
  out-of-India flows will not be recognized and should not be assumed safe.
* **Heuristic scoring.** The score is deterministic and explainable but is a
  heuristic, not calibrated against labelled production traffic; absolute
  numbers should be read as relative strength, not as probabilities.
* **Single artifact ≠ chain.** A lone suspicious URL is flagged by the URL
  engine but is **not** `multi_stage_scam`.
* **No intent attribution.** The chain reports structure and correlation. It
  does not and cannot prove the sender's intent.

## Why correlation is useful

Four moderate individual signals (a phishing SMS, a look-alike domain, a
credential-form URL, a UPI URI to an unknown payee) are each easy to dismiss.
Chained, they match a recognized progression and unlock *specific* advice:
"this is a KYC-phishing chain — do not enter Aadhaar/OTP, do not pay, contact
your bank." That is the difference between independent detection and
multi-stage analysis.