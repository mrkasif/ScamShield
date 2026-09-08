# `url/` - URL Intelligence Engine (advanced, local & explainable)

Responsible for: **static, local, explainable URL risk assessment.**

This module analyses the *structure* of a URL to find phishing/malicious
indicators. It is a **URL risk assessment**, not a claim that a URL is
malicious - and it never opens, resolves, follows, downloads or executes
anything.

```bash
# From the repo root.
python -m pytest tests/test_url_engine.py -q   # run the URL test suite
python -m app.url_scan "https://paypal.account-verify.com/login"
```

## Public API

```python
from scamshield.url import (
    analyze_url,
    combine_message_and_urls,
    analyze_attachment_filename,   # metadata-only attachment heuristic
    assess_sender,                 # display-name vs sender-domain check
)

result = analyze_url("http://secure-sbi-verify.example.com/login")

# result keys
# url               the raw input string
# parse             {scheme, hostname, root_domain, subdomains, tld, port,
#                    username, password, path, query, fragment}
# risk_score        int 0-100
# risk_level        LOW / MEDIUM / HIGH / CRITICAL
# is_suspicious     bool (True when risk_score >= 50)
# confidence        int 0-100
# indicators        list[str]   machine-readable indicator names
# explanation       list[{indicator, severity, score, reason, evidence?}]
# recommendations   list[str]   contextual safety advice
```

The result is fully deterministic: the same URL always produces the same
output.

## Architecture

```
raw URL string
   |
   v
parse.py      urllib.parse (urlsplit) + registrable-domain split
domains.py    root_domain / subdomains / tld (conservative local suffix table)
   |
   v
indicators.py  28 structural + lexical detectors (see below)
   |
   v
scoring.py    explicit point contributions + combination bonuses +
              cross-detector caps, clamp 0-100, deterministic confidence
   |
   v
explain.py    contextual recommendations selected from fired indicators
   |
   v
result dict
```

## Registrable-domain awareness (`domains.py`)

All dots are not equal. `parse_url` now reports the **registrable (root)
domain** via a small conservative local suffix table (no external Public
Suffix List, no network):

| Host | root_domain | subdomains | tld |
|------|-------------|------------|-----|
| `paypal.account-verify.com` | `account-verify.com` | `paypal` | `com` |
| `www.sbi.co.in` | `sbi.co.in` | `www` | `co.in` |
| `www.google.com` | `google.com` | `www` | `com` |
| `a.b.c.example.co.uk` | `example.co.uk` | `a.b.c` | `co.uk` |

Two-label suffixes (`co.in`, `org.uk`, `co.jp`, `com.au`, ...) and common
single-label TLDs are recognised. The engine uses the root domain to decide
*where* a brand word sits (root vs sub-domain) and to report the true
destination in evidence.

## Indicators

### Structural / classic (kept from v1)

| Indicator | Meaning | Severity / points |
|-----------|---------|-------------------|
| `http_scheme` | plain HTTP (no TLS) | low / 6 |
| `unusual_scheme` | non-http(s) scheme (`javascript:`, `data:`, ...) | high / 30 |
| `ip_address_host` | hostname is a raw IP address | high / 34 |
| `punycode_domain` | internationalized `xn--` domain | medium / 12 |
| `embedded_credentials` | `user:password@` in the URL | high / 55 |
| `long_url` | >200 (>500 \\ >2048) characters | low/medium/high / 4/8/14 |
| `excessive_subdomains` | 3+ (5+) levels of sub-domain prefix | low/medium / 6/12 |
| `unusual_port` | explicit non-default web port | medium / 14 |
| `encoding_obfuscation` | heavy percent-encoding (4+, 10+) | low/medium / 8/14 |
| `multiple_at` | more than one `@` symbol | high / 18 |
| `confusing_userinfo` | host-shaped text before `@` | high / 18 |
| `excessive_separators` | `//` or many path levels | low / 5 |
| `short_url_redirector` | local shortener dictionary (never resolved) | medium / 12 |
| `suspicious_keyword` | security words (login, verify, kyc, otp, ...) | low/medium / up to 24 capped |
| `keyword_cluster` | 3+ distinct security words together | medium / 10 |
| `suspicious_redirect_parameter` | `?redirect=` / `?url=` / `?next=` etc. | medium / 12 |
| `brand_impersonation` | brand term in a non-official domain | medium 16 / high 24-30 |

### Advanced (new in this version)

| Indicator | Meaning | Severity / points |
|-----------|---------|-------------------|
| `brand_in_subdomain` | brand word sits above an unrelated root domain | medium / +8 |
| `brand_in_path` | brand word inside the path (needs a security keyword) | low / 6 |
| `possible_brand_typosquatting` | look-alike/homoglyph of a known brand | medium / 14 |
| `internationalized_host` | raw Unicode characters in the hostname | medium / 10 |
| `mixed_script_host` | registrable label mixes alphabets (Latin + Cyrillic/... ) | medium / 12 |
| `suspicious_query_param` | query names like `password`, `otp`, `card`, `cvv`, `account`, `verify`, `token` | low / 5 each (capped 10) |
| `nested_url` | a second `://` inside the URL | medium / 10 |
| `encoded_nested_url` | `://` only visible after percent-decoding | medium / 10 |
| `hex_encoded_host` | hex host decodes to a private/loopback address | medium / 10 |
| `excessive_hyphens` | hyphen-stuffed hostnames | low / 6 |
| `numeric_domain` | registrable name is mostly digits | low / 6 |
| `unusual_tld` | cheap/abuse-prone TLD (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, ...) | low / 4 |
| `long_hostname` | hostname longer than 50 chars | low / 4 |
| `long_path` | path longer than 150 chars | low / 4 |
| `many_query_parameters` | more than 5 query parameters | low / 4 |

### Caps (size alone can never produce a verdict)

- **Keyword cap:** at most 4 distinct security words count (max 24 points);
  `https://bank.example.com/login` stays ~12 and is NOT automatically
  suspicious.
- **Complexity cap:** `long_url + long_hostname + long_path +
  many_query_parameters` are capped together at **20 points**.
- **Query-param cap:** `suspicious_query_param` is capped at **10 points**
  (two params).
- Scores still scale up only when structural indicators (IP host, brand
  impersonation, embedded credentials, ...) co-fire.

## Brand impersonation (root vs sub-domain)

For each brand (SBI, HDFC, ICICI, Axis, PNB, UPI, Paytm, PhonePe, Amazon,
Flipkart, India Post, Aadhaar/UIDAI, Income Tax, Google, PayPal):

1. If the hostname ends with an **official** domain (`sbi.co.in`,
   `hdfcbank.com`, `amazonaws.com`, `paypal.com`, `google.co.in`, ...) it is
   skipped entirely.
2. Otherwise, if a brand token appears in a hostname label it is a
   **preliminary** impersonation signal. **Placement matters**:
   - brand word inside the **root domain** (`secure-sbi-verify.example.com`
     root = `example.com` still counts as sub; `sbi-login.com` root =
     `sbi-login.com`): tier high/30 with a keyword, else medium/16;
   - brand word in a **sub-domain above an unrelated root**
     (`paypal.account-verify.com`, root `account-verify.com`): tier high/24
     with a keyword, else medium/16, **plus** the `brand_in_subdomain` bonus
     (+8, evidence = the actual root domain) so the deception is explained.
3. Generic tokens (`upi`, `post`) additionally require a co-occurring security
   keyword before firing.

## Typosquatting / look-alike domains

`possible_brand_typosquatting` (medium/14) fires when a hostname label:

- is a **homoglyph/leetspeak** twin of a brand token
  (`paypai`→`paypal` with `I/l`, `amaz0n`→`amazon` with `0/o`,
  `g00gle`→`google`), or
- differs by **one edit** for brands of length >= 5 (`gooogle` → `google`), or
- is a **transposition** (same length, distance 2) for brands of length >= 6.

Exact brand words are handled by `brand_impersonation`, official domains are
skipped, and generic tokens (`upi`/`post`) are excluded. `paypai.com` alone
scores ~32 MEDIUM - a look-alike is suspicious but never a verdict on its own.

## Unicode / homoglyph detection

- `internationalized_host` (10) - any raw non-ASCII character in the host;
- `mixed_script_host` (12) - the *registrable label* mixes alphabets
  (`pay` + Cyrillic p = `payрal.com`). An all-Cyrillic name under `.com`
  (`пример.com`) is internationalized but NOT mixed-script, keeping false
  positives low.

## Attachment & sender metadata (architecture)

Both are **pure static metadata checks** - nothing is ever executed, opened or
sent:

- `analyze_attachment_filename(name)` - `.exe/.scr/.bat/.cmd/.com/.msi` are
  HIGH (~60), `.zip/.rar/.7z/.docm/.xlsm` MEDIUM (~35);
- `assess_sender(display_name, sender_email, sender_domain)` - flags when a
  display name claims a brand (`"SBI Customer Care"`) but the real sender
  domain is not one the brand owns.

These are the natural next stage of the same local pipeline and are exposed
now so callers can use them without any network access.

## Safety model (static-only)

The engine guarantees:

- **no** opening/resolving the URL;
- **no** form submission, JS execution, file download or redirect following;
- **no** third-party services and **no** API keys;
- **no** network access of any kind during analysis (`xn--` and Unicode are
  handled by parsing + Unicode tables, never by DNS).

## Message + URL integration

`scamshield.nlp.analyze_message` extracts candidate URLs and runs
`analyze_url` on each. Two new fields are added (existing fields unchanged):

```
url_analysis   list of per-URL results from analyze_url()
               (empty list when the message has no URL)
combined_risk  {
   score,            int 0-100
   level,            LOW/MEDIUM/HIGH/CRITICAL
   message_score,    the message engine's score
   url_scores        list of per-URL scores
}
```

## Combined risk rule

When a message has URLs:

```
strongest = max(message_score, max(url_scores))
weakest   = min(message_score, max(url_scores))
combined  = strongest + (100 - strongest) * (weakest / 100) * 0.7
```

- capped at 100;
- `combined == message_score` when there are no URLs;
- **`combined` is always >= every component signal** - the overall verdict
  never drops below the strongest evidence found;
- strong independent evidence (high message risk **and** high URL risk)
  produces a combined score above either alone;
- the rule is deterministic and documented, never a blind average.

## Examples

```bash
python -m app.url_scan "http://192.168.1.100/login"
#   54/100 HIGH, suspicious=YES  (ip_address_host, suspicious_keyword, http_scheme)

python -m app.url_scan "https://paypal.account-verify.com/login"
#   72/100 HIGH  (brand_impersonation + brand_in_subdomain, evidence:
#                 root_domain = account-verify.com)

python -m app.url_scan "http://paypai.com/verify"
#   32/100 MEDIUM  (possible_brand_typosquatting 'paypai' -> 'paypal')

python -m app.url_scan "https://mail.example.com/login"
#    6/100 LOW  (keyword alone - never a verdict)

python -m app.url_scan "https://www.onlinesbi.com/index.html"
#    0/100 LOW   (official domain, no indicators)
```

## Limitations

- **Static only**: it assesses URL *structure*. It cannot see the page
  content, certificates beyond scheme, DNS, or live reputation.
- Heuristic thresholds (sub-domain depth, length, encoding, port, complexity)
  can be tuned and may mis-rank edge cases.
- The registrable-domain table is a small, conservative local subset of the
  Public Suffix List - exotic or brand-new TLD suffixes may be treated as
  one-label domains.
- Unicode brand look-alikes are recognised (mixed-script + typosquatting) but
  Indic-script spelling of brands is only partially covered.
- Shorteners are recognised, never resolved - the final destination is not
  known.
- The engine intentionally keeps "legitimate-looking" URLs LOW; a
  well-disguised phishing domain with no detectable structure can be missed.