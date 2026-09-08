"""Gunicorn configuration for ScamShield (Render / cloud/container hosts).

Every Python service gets a free `PORT` environment variable on Render.
This config binds 0.0.0.0:PORT so the standard production command:

    gunicorn web.app:app

"just works" on Render with no extra CLI flags. It is auto-loaded by
Gunicorn from the current working directory (repo root).

Environment variables (all optional, safe defaults):
    HOST              listen host        (default 0.0.0.0)
    PORT              listen port        (default 5000; Render injects PORT)
    DEBUG             gunicorn log debug (default 0)
"""

import os


def _env_bool(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


host = os.environ.get("HOST") or os.environ.get("SCAMSHIELD_HOST") or "0.0.0.0"
try:
    port = int(os.environ.get("PORT") or os.environ.get("SCAMSHIELD_PORT") or "5000")
except ValueError:
    port = 5000

bind = f"{host}:{port}"
workers = 1  # single worker: the app is stateless and disk-lean; avoids duplicate state
timeout = 90
graceful_timeout = 10
accesslog = "-"   # stream request logs to stdout so Render captures them
errorlog = "-"
loglevel = "debug" if _env_bool("DEBUG") else "info"