"""ScamShield analysis engine (models and scoring are added in later steps).

Unified entry point - the orchestrator a future UI/API calls:

    from scamshield import analyze, analyze_batch, detect_input_type, analyze_chain

    analyze("message", "Your KYC has expired...")
    analyze("url", "https://example.com/login")
    analyze("qr", "tests/fixtures/qr/url_suspicious.png")
    analyze("upi", "upi://pay?pa=merchant@upi&pn=Store&am=60&cu=INR")
    analyze_chain([message_result, url_result, upi_result])

Link Purifier / Link Safety Monitor (defensive link-change analysis):

    from scamshield import purify_url, compare_urls
    purify_url("https://example.com/support?redirect=https%3A%2F%2F...")
    compare_urls("https://example.com/support",
                 "https://example.com/support?redirect=https%3A%2F%2F...")

Every engine keeps its own detailed result, available under
result["engine_results"]. See src/scamshield/analyzer.py and
src/scamshield/README.md for the unified result schema.
"""

from .analyzer import analyze, analyze_batch, detect_input_type, analyze_chain
from .link_change import analyze_link_change, compare_urls, purify_url

__version__ = "0.3.0"

__all__ = [
    "analyze", "analyze_batch", "detect_input_type", "analyze_chain",
    "purify_url", "compare_urls", "analyze_link_change", "__version__",
]