"""ScamShield Phishing Link Purifier / Link Safety Monitor.

Static, local, deterministic defensive analysis of URL structure. It reuses the
existing URL Intelligence engine's detectors and scoring for the authoritative
verdict and adds:

    purify_url(url)                mode 1 - safe normalization + inspection
    compare_urls(baseline, current)  mode 2  - baseline-vs-current change monitor
    analyze_link_change(content)   framework-independent dispatcher (str or dict)

Everything is 100% offline: no DNS, no HTTP, no URL fetching, no browser, no
redirect following, no execution, no external/paid APIs. "Purification" means
normalization and inspection only - this module never generates, repairs,
disguises or weaponizes URLs. See `src/scamshield/link_change/README.md`.
"""

from .engine import (
    analyze_link_change,
    compare_urls,
    normalize_url,
    purify_url,
)

__all__ = ["purify_url", "compare_urls", "analyze_link_change", "normalize_url"]