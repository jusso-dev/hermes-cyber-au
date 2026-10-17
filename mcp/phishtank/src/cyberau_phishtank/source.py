"""Read-only PhishTank verified-online phishing URL database.

Lookups compare the cached database only. The URL under test is never requested.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import idna
import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimited, RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector

PUBLIC_URL = "https://data.phishtank.com/data/online-valid.json"
HOST = "data.phishtank.com"
_USER_AGENT = f"phishtank/hermes-cyber-au ({USER_AGENT})"
_URL_QUERY = re.compile(r"(https?://\S*?)\?\S*")
ATTRIBUTION = (
    "PhishTank verified phishing URLs, operated by Cisco Talos. "
    "Licence not confirmed. This connector is not endorsed by PhishTank."
)
REQUIRED = ("phish_id", "url", "verified", "online")
_KEY = re.compile(r"[A-Za-z0-9_-]{4,128}")
_PACKAGE = Path(__file__).resolve().parents[2]
_HOUR = 3600
_MAX_BYTES = 80 * 1024 * 1024
_TRANSPORT = None
_SLEEP = None
_CLOCK = None
_PARSED: tuple[str, list] | None = None
_STORED: set[str] = set()


def phishtank_check_url(url: str) -> dict:
    """Whether a URL is in the cached verified-online set. The URL is not requested."""
    problem = _validate_url(url)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    rows, cache, warning = _feed(force_live=False)
    if rows is None:
        return _envelope([], cache, warnings=(warning or "PhishTank payload was not usable",))
    matched = _match(rows, url)
    warnings: list[str] = []
    if warning:
        warnings.append(warning)
    elif not matched and cache == "snapshot":
        warnings.append("no matching URL in the offline snapshot")
    return _envelope(matched, cache, warnings=tuple(warnings), as_of=_as_of(rows))


def connector() -> Connector:
    return _PhishtankConnector()


class _PhishtankConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="phishtank",
            server_name="phish",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "phishtank_check_url",
                    "Whether a URL is in the cached verified-online set. The URL is not requested.",
                    phishtank_check_url,
                )
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            text = _snapshot_text()
            problem = schema_drift(_loads(text) if text else None)
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        rows, _cache, warning = _feed(force_live=True)
        if warning or rows is None:
            return Probe(self.key, False, warning or "live fetch failed")
        if not rows:
            return Probe(self.key, False, "live probe returned no entries")
        problem = schema_drift(rows)
        if problem:
            return Probe(self.key, False, problem)
        mismatch = _response_problem(_normalise(rows[0]))
        if mismatch:
            return Probe(self.key, False, mismatch)
        return Probe(self.key, True, "live ok")


def schema_drift(payload) -> str | None:
    rows = _entries(payload)
    if rows is None:
        return "PhishTank payload has no entry list"
    if not rows:
        return None
    first = rows[0]
    if not isinstance(first, dict):
        return "PhishTank schema drift, entry is not an object"
    missing = [name for name in REQUIRED if name not in first]
    if missing:
        return "PhishTank schema drift, missing " + ", ".join(missing)
    return None


def _feed(*, force_live: bool) -> tuple[list | None, str, str]:
    pinned = bool(os.environ.get("CYBERAU_PHISHTANK_SNAPSHOT")) and not force_live
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if pinned:
        return _from_text(_snapshot_text(), "snapshot")
    data_dir = _data_dir()
    http_cache = HttpCache(data_dir / "http_cache.sqlite")
    target = _request_target()
    cached = None
    cache_key = ""
    if target is not None:
        url, scope = target
        cache_key = http_cache.key("GET", url, None, b"", scope)
        cached = http_cache.get(cache_key)
        if cached and not force_live and (offline or http_cache.fresh(cached)):
            state = "hit" if http_cache.fresh(cached) else "stale"
            return _from_body(cached.body, state)
    if offline:
        return _from_text(_snapshot_text(), "snapshot")
    if target is None:
        return None, "snapshot", _key_problem()
    url, scope = target
    try:
        _hourly_limit()
    except RateLimited:
        if cached is not None and not force_live:
            return _from_body(cached.body, "stale")
        return (
            None,
            "snapshot",
            "PhishTank download is limited to once an hour and no cached copy is available.",
        )
    httpx_log = logging.getLogger("httpx")
    httpcore_log = logging.getLogger("httpcore")
    previous_levels = (httpx_log.level, httpcore_log.level)
    httpx_log.setLevel(logging.WARNING)
    httpcore_log.setLevel(logging.WARNING)
    client = HttpClient(
        "phishtank",
        policy=EgressPolicy(_allowlist(), "phishtank"),
        cache=http_cache,
        limiter=_limiter(),
        user_agent=_USER_AGENT,
        rate=1,
        burst=4,
        window="rolling",
        timeout=60,
        retries=1,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
        auth_scope=scope,
        max_bytes=_MAX_BYTES,
    )
    try:
        response = client.get(_fresh_url(url), ttl=_HOUR, skip_cache=True)
    except (HttpError, EgressDenied, TimeoutError) as exc:
        if cached is not None and not force_live:
            return _from_body(cached.body, "stale")
        return None, "snapshot", _clean(exc)
    finally:
        client.close()
        httpx_log.setLevel(previous_levels[0])
        httpcore_log.setLevel(previous_levels[1])
    if response.status in (401, 403):
        return (
            None,
            response.cache,
            f"PhishTank refused the download ({response.status}). "
            "Set PHISHTANK_APP_KEY to an application key.",
        )
    if response.status == 429:
        if cached is not None and not force_live:
            return _from_body(cached.body, "stale")
        return (
            None,
            "miss",
            "PhishTank rate limited the download. The Retry-After wait was not enough.",
        )
    if response.status >= 400:
        return None, response.cache, f"PhishTank upstream status {response.status}"
    if response.cache == "stale" and cached is not None:
        return _from_body(response.body or cached.body, "stale")
    if cache_key and response.body:
        http_cache.put(
            cache_key,
            status=200,
            headers={"content-type": "application/json"},
            body=response.body,
            ttl=_HOUR,
        )
    return _from_body(response.body, "miss")


def _fresh_url(url: str) -> str:
    """Ask Cloudflare for a new redirect. A cached one carries an expired signature."""
    nonce = int(time.time())
    join = "&" if "?" in url else "?"
    return f"{url}{join}nc={nonce}"


def _request_target() -> tuple[str, str] | None:
    secret = lookup("PHISHTANK_APP_KEY")
    if secret is None:
        return PUBLIC_URL, "anonymous"
    if _key_problem():
        return None
    return f"https://{HOST}/data/{secret}/online-valid.json", "keyed"


def _key_problem() -> str:
    secret = lookup("PHISHTANK_APP_KEY")
    if secret is None or _KEY.fullmatch(secret):
        return ""
    return "PHISHTANK_APP_KEY is set but is not a usable application key."


def _hourly_limit() -> None:
    _limiter().acquire(
        "phishtank:database",
        rate=1 / _HOUR,
        burst=1,
        window="rolling",
        timeout=60,
    )


def _limiter() -> RateLimiter:
    kwargs = {}
    if _CLOCK is not None:
        kwargs["clock"] = _CLOCK
    if _SLEEP is not None:
        kwargs["sleeper"] = _SLEEP
    return RateLimiter(_data_dir() / "rate_limit.sqlite", **kwargs)


def _from_body(body: bytes, cache: str) -> tuple[list | None, str, str]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None, cache, "PhishTank payload was not UTF-8"
    return _from_text(text, cache)


def _from_text(text: str | None, cache: str) -> tuple[list | None, str, str]:
    global _PARSED
    if text is None:
        return (
            None,
            cache,
            "PhishTank is unavailable offline and no cache or snapshot is stored",
        )
    digest = hashlib.sha256(text.encode()).hexdigest()
    if _PARSED is not None and _PARSED[0] == digest:
        return _PARSED[1], cache, ""
    rows, warning = _parse(text)
    if warning:
        return None, cache, warning
    _PARSED = (digest, rows)
    _persist(rows, digest)
    return rows, cache, ""


def _parse(text: str) -> tuple[list, str]:
    payload = _loads(text)
    if payload is None and text.strip():
        return [], "PhishTank payload was not usable"
    problem = schema_drift(payload)
    if problem:
        return [], problem
    rows = [row for row in (_entries(payload) or []) if isinstance(row, dict)]
    return rows, ""


def _entries(payload) -> list | None:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for name in ("data", "entries"):
            rows = payload.get(name)
            if isinstance(rows, list):
                return rows
    return None


def _loads(text: str | None):
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _match(rows: list, url: str) -> list[dict]:
    wanted = _variants(url)
    found = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        if not _variants(str(row.get("url") or "")) & wanted:
            continue
        record = _normalise(row)
        if not record["phish_id"] or record["phish_id"] in seen:
            continue
        seen.add(record["phish_id"])
        found.append(record)
    found.sort(key=lambda item: item["phish_id"])
    return found


def _normalise(row: dict) -> dict:
    target = ""
    if row.get("target") is not None and "target" in row:
        target = untrusted_text(str(row.get("target")), "phishtank")
    return {
        "phish_id": _identifier(row.get("phish_id")),
        "url": str(row.get("url") or ""),
        "phish_detail_url": str(row.get("phish_detail_url") or ""),
        "submission_time": str(row.get("submission_time") or ""),
        "verified": str(row.get("verified") or ""),
        "verification_time": str(row.get("verification_time") or ""),
        "online": str(row.get("online") or ""),
        "target": target,
    }


def _identifier(value) -> str:
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value.strip()
    return ""


def _variants(url: str) -> set[str]:
    parsed = _split(url)
    if parsed is None:
        return set()
    scheme, netloc, path, query = parsed
    paths = {path}
    if path in {"", "/"}:
        paths.update({"", "/"})
    elif path.endswith("/"):
        paths.add(path.rstrip("/"))
    else:
        paths.add(path + "/")
    rendered = set()
    for item in paths:
        text = f"{scheme}://{netloc}{item}"
        if query:
            text += "?" + query
        rendered.add(text)
    return rendered


def _split(url: str) -> tuple[str, str, str, str] | None:
    if not isinstance(url, str):
        return None
    parts = urlsplit(url.strip())
    if parts.username or parts.password:
        return None
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not parts.hostname:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    host = _host(parts.hostname)
    netloc = host if port is None else f"{host}:{port}"
    return scheme, netloc, parts.path or "", parts.query


def _host(hostname: str) -> str:
    try:
        return idna.encode(hostname).decode("ascii")
    except idna.IDNAError:
        return hostname.lower()


def _validate_url(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        return "url is required"
    if _split(url) is None:
        return "url must be an http or https URL"
    return ""


def _as_of(rows: list) -> str | None:
    times = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        stamp = row.get("verification_time") or row.get("submission_time")
        if isinstance(stamp, str) and stamp:
            times.append(stamp)
    return max(times) if times else None


def _persist(rows: list, digest: str) -> None:
    if digest in _STORED:
        return
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    chosen: dict[str, tuple] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        phish_id = _identifier(row.get("phish_id"))
        url = str(row.get("url") or "")
        if not phish_id or not url:
            continue
        target = "" if row.get("target") is None else str(row.get("target"))
        chosen[phish_id] = (
            phish_id,
            url,
            target,
            str(row.get("verified") or ""),
            str(row.get("online") or ""),
            str(row.get("verification_time") or ""),
            str(row.get("submission_time") or ""),
            now,
            now,
        )
    if chosen:
        with sqlite3.connect(_data_dir() / "phishtank.sqlite") as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS phish (
                    phish_id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    target TEXT NOT NULL,
                    verified TEXT NOT NULL,
                    online TEXT NOT NULL,
                    verification_time TEXT NOT NULL,
                    submission_time TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
                """
            )
            conn.executemany(
                """
                INSERT INTO phish (
                    phish_id, url, target, verified, online,
                    verification_time, submission_time, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(phish_id) DO UPDATE SET
                    url=excluded.url,
                    target=excluded.target,
                    verified=excluded.verified,
                    online=excluded.online,
                    verification_time=excluded.verification_time,
                    submission_time=excluded.submission_time,
                    last_seen=excluded.last_seen
                """,
                list(chosen.values()),
            )
    _STORED.add(digest)


def _response_problem(record: dict) -> str | None:
    schema = json.loads(
        (_PACKAGE / "schema" / "phishtank_check_url.response.json").read_text(encoding="utf-8")
    )
    validator = jsonschema.Draft202012Validator(schema)
    if any(validator.iter_errors(record)):
        return "PhishTank response did not match the stored schema"
    return None


def _snapshot_text() -> str | None:
    override = os.environ.get("CYBERAU_PHISHTANK_SNAPSHOT")
    path = Path(override) if override else _PACKAGE / "data" / "online-valid.json"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _clean(exc: BaseException) -> str:
    return _clean_text(str(exc))


def _envelope(data, cache: str, warnings: tuple[str, ...] = (), as_of: str | None = None) -> dict:
    cleaned = tuple(_clean_text(item) for item in warnings)
    return envelope(
        "phishtank",
        data,
        urls=[PUBLIC_URL],
        cache=cache,
        data_as_of=as_of,
        warnings=cleaned,
        attribution=ATTRIBUTION,
    )


def _clean_text(message: str) -> str:
    text = redact(message)
    secret = lookup("PHISHTANK_APP_KEY")
    if secret:
        text = text.replace(secret, "[REDACTED]")
    return _URL_QUERY.sub(r"\1?[REDACTED]", text)


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-phishtank"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("phishtank", connector)
