# Phishing Link Purifier / Link Safety Monitor (`scamshield.link_change`)

A **sibling analysis module** of the existing engines. It inspects a single link,
or compares a previously observed (baseline) link against a current one, and
reports structural changes that matter for phishing safety.

It is a **purifier in the inspection sense only**: links are safely normalized
and shown for review. ScamShield **never repairs, generates, opens, resolves or
follows** links.

---

## Two modes

| Mode | Entry point | Purpose |
|------|-------------|---------|
| `purify` | `purify_url(url)` | Normalize + inspect one link statically |
| `compare` | `compare_urls(baseline, current)` | Structural change monitoring between a baseline and the current link |

Both are also reachable through the unified analyzer:

```python
from scamshield import analyze

analyze("link_change", {"url": "https://example.com/support"})
# -> mode: "purify"

analyze("link_change", {"baseline_url": "https://example.com/support",
                        "current_url": "https://example.com/support?redirect=evil.example"})
# -> mode: "compare"

# aliases: "link-change", "linkchange", "purify", "purifier",
#          "link_purifier", "link_safety", "link_monitor", "compare"
```

`analyze("link_change", ...)` accepts either a `str` (purify) or a dict with
`"url"`, or `"baseline_url"` + `"current_url"` (with `"baseline"`/`"current"`
as compare aliases).

## Safe destination analysis

`destination_analysis` and `safe_destination` are additional evidence fields
on the same link_change result. They do not change the authoritative outer-URL
`risk_score`, `risk_level`, `is_suspicious`, or Safety-Zone presentation.

ScamShield **does not repair arbitrary phishing URLs by guessing their
legitimate destination**. It only:

1. inspects the submitted URL statically;
2. extracts an explicitly embedded destination from a redirect parameter,
   nested URL, encoded URL, or another redirect-like structure already
   detected by the existing engine;
3. analyzes that destination independently with the unchanged
   `scamshield.url.analyze_url`;
4. labels it `VERIFIED`, `SUSPICIOUS`, or `UNKNOWN`;
5. returns one conservative result:
   `SAFE_DESTINATION_AVAILABLE`, `UNSAFE_DESTINATION`,
   `DESTINATION_UNKNOWN`, or `NO_DESTINATION_FOUND`.

The outer and destination scores are both retained separately. They are never
averaged.

### Status rules

- `VERIFIED`: the extracted hostname exactly matches an official domain from
  ScamShield's existing `BRAND_PROFILES` evidence, and its independent URL
  analysis reports no indicators. Because this requires both exact trusted-domain
  evidence and a clean independent analysis, HTTPS, successful parsing, a
  normal-looking path, or "no indicators" alone can never produce `VERIFIED`.
- `SUSPICIOUS`: the destination's own URL analysis is independently suspicious
  or triggers a decisive existing URL indicator, such as brand impersonation,
  typosquatting, an IP-address host, embedded credentials, an unusual scheme,
  nested/encoded redirection, or a sensitive query-parameter pattern.
- `UNKNOWN`: there is insufficient deterministic evidence to establish safety.
  This is the correct conservative answer for ordinary clean-looking
  destinations not backed by existing trusted-domain evidence.
- `NO_DESTINATION_FOUND`: no explicit destination was present, so none was
  invented.

For brand mismatches, the result exposes evidence only:

```text
Detected brand: ExampleBrand
Expected domain: official-domain.example
Submitted domain: fake-brand.example
```

The submitted domain is never changed into the expected domain, and a
destination derived from fuzzy similarity alone is never marked verified.

### Result shape

```json
{
  "original_url_analysis": {
    "url": "https://suspicious.example/redirect?url=...",
    "risk_score": 72,
    "risk_level": "HIGH",
    "is_suspicious": true,
    "indicators": ["suspicious_redirect_parameter", "..."]
  },
  "destination_analysis": {
    "found": true,
    "candidate_count": 1,
    "truncated": false,
    "candidates": [
      {
        "url": "https://secure-sbi-verify.example/login",
        "source": "redirect_parameter",
        "destination_parameter": "url",
        "decode_layers": 0,
        "status": "SUSPICIOUS",
        "risk_score": 66,
        "risk_level": "HIGH",
        "is_suspicious": true,
        "indicators": ["brand_impersonation", "..."],
        "brand_evidence": {
          "detected_brand": "sbi",
          "submitted_hostname": "secure-sbi-verify.example",
          "submitted_root_domain": "secure-sbi-verify.example",
          "expected_domains": ["onlinesbi.com", "sbi.co.in", "sbicard.com"],
          "exact_official_match": false
        },
        "analysis": {}
      }
    ]
  },
  "safe_destination": {
    "available": false,
    "url": null,
    "status": "UNSAFE_DESTINATION",
    "reason": "...",
    "safe_action": "Destination appears suspicious — keep blocked."
  }
}
```

`candidate.analysis` contains the complete unchanged output from
`analyze_url(candidate)`. `destination_parameter` is populated when the
destination came from an explicit redirect parameter; whole-string nested or
encoded discoveries report `nested_url` or `encoded_url`.

There is deliberately no automatic redirect endpoint. A future local wrapper
may only present the extracted destination for explicit user confirmation:
never redirect automatically, never fetch or preload the destination, and only
use a destination whose returned object has `available: true`. A destination
marked `VERIFIED` is a deterministic trust/domain-evidence assessment, not a
live guarantee that the destination is legitimate or will remain safe.

## What it reports

A unified-link-change result (all `engine_results["link_change"]` values are
duplicated at the top level for the UI):

- `mode`, `original_url`, `normalized_url`, `current_url`, `baseline_url`,
  `baseline_normalized_url` — the inspected/displayed representations.
- `purifier` — boolean flags: `redirect_detected`, `nested_url_detected`,
  `encoded_destination_detected`, `obfuscation_detected`, plus
  `hidden_components` (e.g. `@`-credentials, `%40` tricks, percent-encoded
  nesting) and `purified_representation`.
- `risk_score` / `risk_level` / `is_suspicious` — **always the existing URL
  engine's verdict on the current link** (`scamshield.url.analyze_url`). The
  purifier never overrides, gates or re-scores it.
- In `compare` mode, `comparison`:
  - `changes` — ordered, deduplicated records `{category, kind, risk_impact,
    detail, evidence}`.
  - `change_count`, `risk_increasing_changes`, `compared`.
  - plus informative `change_impact` (bounded to `CHANGE_IMPACT_CAP = 70`),
    `risk_delta` (current score minus baseline score) and `risk_increased`.

### Change categories (`risk_impact` = `neutral` | `risk_increasing` | `negative`)

- `hostname_changed`, `root_domain_changed`, `tld_changed`, `subdomain_changed`
- `scheme_changed`, `port_changed`, `path_changed`, `fragment_changed`,
  `plain_http_introduced`
- `host_became_ip`, `ip_became_host`
- `brand_similarity_introduced` (a known brand profile / homoglyph-like host
  token appears, e.g. `sbi` in `secure-sbi-verify.…` → RISK UP)
- `unicode_or_homoglyph_introduced` (internationalized / mixed-script host)
- `suspicious_tld_introduced`, `domain_complexity_increased`,
  `shortener_introduced`
- `query_parameter_added` / `query_parameter_removed` /
  `query_parameter_value_changed`, each classified as:
  - `redirect_parameter_*` (e.g. `redirect`, `next`, `continue`, `url`) → RISK UP
  - `sensitive_parameter_*` (e.g. `username`, `key`) → RISK UP
  - `tracking_parameter_*` (e.g. `utm_*`, `ref`) → NEUTRAL
  - `destination_parameter_*`
- `redirect_parameter_present` / `nested_url_present` /
  `encoded_destination_present` / `obfuscation_present` /
  `link_changed_from_baseline` — indicator-set diffs (NEW when they appear in
  the current link only)

The summary/explanation text ("RISK UP: redirect_parameter_present … the
current link scores higher …") is generated at build time and points at the
exact reason, matching the existing explainable-output style.

## Offline / no-network guarantee

The module performs **pure static string/structure analysis**:

- No DNS, HTTP(S), socket calls, browser automation, redirect-chain resolution,
  page fetches or external APIs — none, ever.
- URLs are only parsed (`urllib.parse`) and decomposed; nothing is opened or
  followed.
- `parse_url` is crash-proof and the whole module tolerates malformed, empty,
  very long and non-string inputs without raising.
- Both `tests/test_link_change.py::test_link_change_makes_no_network_requests`
  and the extended Flask-layer no-network guard (`test_flask_api.py`) prove the
  whole flow completes with sockets disabled.

## Reuse, not re-implementation

All detectors come from the existing URL Intelligence engine
(`scamshield.url`); the link_change layer never re-scores. It reuses:

- `parse_url` for crash-proof parsing,
- `detect_all` + the indicator names for `indicator_set` diffs,
- `patterns.py` for redirect/sensitive/tracking parameter names, shorteners,
  brand profiles, homoglyphs, ports and schemes,
- `analyze_url` for the authoritative verdict.

Because link-change results flow through the same `analyze()` wrapper, they also
carry the Safety-Zone presentation keys (`zone`, `zone_label`,
`zone_description`, `recommended_action`, `risk_assessment`, `risk_breakdown`)
derived from that same URL verdict — the zone never comes from a second
scoring system.

## Determinism

Whitespace is stripped, changes are deduplicated and sorted by input order, and
the query diff preserves insertion order. No randomness, no time dependence —
same inputs always produce identical JSON (`test_determinism`).

## Limitations (honest)

- Static inspection only: no reputation, no intent classification of the
  destination, no DNS/reporting cloud.
- `change_impact` is a bounded informational heuristic (cap 70), never a
  threshold that overrides the URL engine.
- Indicator diffs are only computed when the baseline parses to a usable URL, so
  a broken baseline can never make every detector look "new".

## Tests

```bash
python -m pytest tests/test_link_change.py -q    # existing purifier/monitor tests
python -m pytest tests/test_safe_destination.py -q  # safe-destination tests
python -m pytest tests/test_flask_api.py -k link_change -q   # endpoint tests
```