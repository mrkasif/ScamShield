"""Deterministic latency measurement for the ScamShield engines.

Runs each engine repeatedly on fixed sample inputs and reports
mean / median / min / max / stdev wall-clock times in milliseconds.
No network requests are made. The same inputs are reused across runs
so measurements are comparable.

Sample inputs are deliberately synthetic and privacy-safe.
"""
from __future__ import annotations

import statistics
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_QR_FIXTURE = str(_REPO_ROOT / "tests" / "fixtures" / "qr" / "url_suspicious.png")

_DEFAULT_SAMPLES: dict[str, dict] = {
    "message": {
        "input_type": "message",
        "content": "Your KYC has expired. Click now to verify immediately or account will be blocked.",
    },
    "url": {
        "input_type": "url",
        "content": "https://secure-sbi-verify.example.com/login",
    },
    "upi": {
        "input_type": "upi",
        "content": "upi://pay?pa=merchant@okaxis&pn=Merchant&am=500&cu=INR",
    },
    "qr": {
        "input_type": "qr",
        "content": _QR_FIXTURE,
    },
    "unified_message": {
        "input_type": "message",
        "content": "You have won a lottery of Rs 50,00,000. Claim now before deadline.",
    },
}


def _time_one(engine_fn, content, input_type) -> float:
    """Run a single analysis and return wall-clock time in milliseconds."""
    t0 = time.perf_counter()
    if input_type == "qr":
        from ..analyzer import analyze
        analyze(input_type, content)
    else:
        engine_fn(content)
    t1 = time.perf_counter()
    return (t1 - t0) * 1000.0


def _get_engine_fn(input_type: str):
    if input_type == "message":
        from ..nlp.engine import analyze_message
        return analyze_message
    if input_type == "url":
        from ..url.engine import analyze_url
        return analyze_url
    if input_type == "upi":
        from ..qr import analyze_qr_content
        return analyze_qr_content
    if input_type == "qr":
        from ..analyzer import analyze
        return lambda path: analyze("qr", path)
    raise ValueError(f"Unknown input_type: {input_type}")


def measure_latencies(
    *,
    samples: dict[str, dict] | None = None,
    iterations: int = 20,
) -> dict:
    """Measure engine latency for each sample.

    Args:
        samples: override sample inputs (default: synthetic privacy-safe inputs).
        iterations: number of runs per sample (default 20 for stable stats).

    Returns::

        {
            "iterations": int,
            "engines": {
                "message": {
                    "mean_ms": ..., "median_ms": ..., "min_ms": ...,
                    "max_ms": ..., "stdev_ms": ..., "n": iterations
                },
                ...
            }
        }
    """
    samples = samples or _DEFAULT_SAMPLES
    results: dict[str, dict] = {}

    for name, sample in samples.items():
        input_type = sample["input_type"]
        content    = sample["content"]
        engine_fn  = _get_engine_fn(input_type)

        times: list[float] = []
        for _ in range(iterations):
            t = _time_one(engine_fn, content, input_type)
            times.append(t)

        results[name] = {
            "mean_ms":   round(statistics.mean(times), 3),
            "median_ms": round(statistics.median(times), 3),
            "min_ms":    round(min(times), 3),
            "max_ms":    round(max(times), 3),
            "stdev_ms":  round(statistics.stdev(times), 3) if len(times) >= 2 else 0.0,
            "n":         iterations,
            "input_type": input_type,
        }

    return {"iterations": iterations, "engines": results}
