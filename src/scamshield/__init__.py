"""ScamShield analysis engine (models and scoring are added in later steps).

Unified entry point - the orchestrator a future UI/API calls:

    from scamshield import analyze, analyze_batch, detect_input_type, analyze_chain

    analyze("message", "Your KYC has expired...")
    analyze("url", "https://example.com/login")
    analyze("qr", "tests/fixtures/qr/url_suspicious.png")
    analyze("upi", "upi://pay?pa=merchant@upi&pn=Store&am=60&cu=INR")
    analyze_chain([message_result, url_result, upi_result])

Each engine keeps its own detailed result, available under
result["engine_results"]. See src/scamshield/analyzer.py and
src/scamshield/README.md for the unified result schema.
"""

from .analyzer import analyze, analyze_batch, detect_input_type, analyze_chain

__version__ = "0.3.0"

__all__ = ["analyze", "analyze_batch", "detect_input_type", "analyze_chain", "__version__"]