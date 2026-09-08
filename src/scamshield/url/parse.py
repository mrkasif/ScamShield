"""Safe, crash-proof URL parsing for the ScamShield URL engine.

Uses Python's standard library (`urllib.parse`) only. The parser must never
raise, regardless of how malformed the input is - every unusual condition is
handled defensively and reported through a structured dict.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from . import domains


def parse_url(url: str) -> dict:
    """Parse a raw URL string into structured parts (never raises).

    Returns a dict:
        raw        the trimmed input string (as given)
        ok         whether a usable URL structure was recovered
        scheme     lower-cased scheme, or "" (http is assumed when absent)
        netloc     the network location (host[:port][, userinfo])
        hostname   lower-cased host name *without* port/userinfo, trailing dot
                   stripped, or "" when not recoverable
        port       integer port (explicit in the URL) or None; None on error
        username   userinfo username or None
        password   userinfo password or None
        path       path component or ""
        query      query string (without "?") or ""
        fragment   fragment (without "#") or ""
        root_domain  registrable domain name (e.g. "sbi.co.in")
        subdomains   labels above the root domain (dot-joined, "" when none)
        tld          public suffix tail (e.g. "co.in", "com")
        with_scheme_url  the input with an assumed "http://" when it had none

    Missing schemes are tolerated: "example.com/login" is parsed as
    "http://example.com/login". No network access happens here.
    """
    raw = (url or "").strip()
    if not raw:
        return _empty(raw)

    # Recover a missing / ambiguous scheme so urlsplit can separate the host
    # from the path. Rules (deterministic, defensive):
    #   1. "http://x/..."            -> explicit web scheme, parse as-is.
    #   2. "http://..."             -> no scheme: assume http.
    #   3. "javascript:...", "data:" -> real non-web scheme: parse as-is so it
    #      can be reported as an unusual scheme.
    #   4. "example.com:8080/..."    -> looks like a scheme but contains ".":
    #      treat as host:port, assume http.
    #   5. "localhost:8080/..."      -> alpha-only "scheme" whose path starts
    #      with a port number: treat as host:port, assume http.
    work = raw
    if "://" not in work:
        probe = _probe_scheme(work)
        if probe == "assume":
            work = "http://" + work

    try:
        s = urlsplit(work)
    except ValueError:
        # Unparseable (e.g. a lone "<>" or an invalid bracket/percent run).
        return _empty(raw)

    scheme = (s.scheme or "").lower()

    hostname = ""
    if s.hostname is not None:
        hostname = s.hostname.rstrip(".")  # strip a single trailing root dot

    port = None
    if s.hostname is not None:
        try:
            port = s.port
        except ValueError:
            port = None

    username = s.username
    password = s.password

    ok = bool(hostname) or bool(scheme) or bool(s.path)

    dp = domains.domain_parts(hostname)

    return {
        "raw": raw,
        "ok": ok,
        "scheme": scheme,
        "netloc": s.netloc,
        "hostname": hostname,
        "port": port,
        "username": username,
        "password": password,
        "path": s.path,
        "query": s.query,
        "fragment": s.fragment,
        "root_domain": dp["root_domain"],
        "subdomains": dp["subdomains"],
        "tld": dp["tld"],
        "with_scheme_url": work,
        "parsed": s,
    }


def _probe_scheme(raw: str) -> str:
    """Decide whether a scheme-less URL needs 'http://' prepended.

    Returns 'as-is' (keep the string) or 'assume' (prepend http://).
    """
    try:
        s = urlsplit(raw)
    except ValueError:
        return "assume"
    scheme = s.scheme or ""
    if not scheme:
        return "assume"
    # urlsplit reads a scheme for "example.com:8080" (contains ".") and
    # "localhost:8080" (path begins like a port). Both are host:port typos.
    if "." in scheme:
        return "assume"
    if not s.netloc and (s.path or "").split("/", 1)[0].isdigit():
        return "assume"
    return "as-is"


def _empty(raw: str) -> dict:
    return {
        "raw": raw,
        "ok": False,
        "scheme": "",
        "netloc": "",
        "hostname": "",
        "port": None,
        "username": None,
        "password": None,
        "path": "",
        "query": "",
        "fragment": "",
        "root_domain": "",
        "subdomains": "",
        "tld": "",
        "with_scheme_url": "",
        "parsed": None,
    }