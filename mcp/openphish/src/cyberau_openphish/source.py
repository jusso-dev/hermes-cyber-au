"""Read-only OpenPhish community feed. Never requests the URL under test."""

import hashlib
import json
import os
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimited, RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector

FEED_URL = "https://openphish.com/feed.txt"
GITHUB_FEED = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
GITHUB_HOST = "raw.githubusercontent.com"
GITHUB_PREFIX = "/openphish/public_feed/"
ATTRIBUTION = (
    "OpenPhish community feed (https://openphish.com/). "
    "Licence not confirmed. The community feed is a small sample. "
    "This connector is not affiliated with OpenPhish."
)
_SOURCES = ("openphish", "phishtank", "urlhaus")
_PACKAGE = Path(__file__).resolve().parents[2]
_TRANSPORT = None
_SLEEP = time.sleep
_TTL = 3600


def phish_check_url(url: str) -> dict:
    """Check one URL against OpenPhish and any local PhishTank or URLhaus cache."""
    problem = _query_problem(url)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    text, cache, warning = _fetch_feed(force_live=False)
    warnings = [warning] if warning else []
    feed_urls = _feed_urls(text) if text and not schema_drift(text) else []
    if feed_urls:
        _persist("openphish", feed_urls)
    wanted = _normalise(url)
    records = [_openphish_record(url, wanted, feed_urls, warning)]
    for name in ("phishtank", "urlhaus"):
        cached, status = _sibling_urls(name)
        if status and status != "cache not present":
            warnings.append(f"{_label(name)} cache {status}")
        if cached:
            _persist(name, [item for item in cached if item == wanted])
        records.append(_sibling_record(name, url, wanted, cached, status))
    return _envelope(records, cache, warnings=tuple(warnings))


def connector() -> Connector:
    return _OpenPhishConnector()


class _OpenPhishConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="openphish",
            server_name="phish",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "phish_check_url",
                    "Check a URL against the OpenPhish, PhishTank and URLhaus caches together.",
                    phish_check_url,
                )
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            text = _snapshot_text()
            if text is None:
                return Probe(self.key, False, "OpenPhish snapshot is missing")
            problem = schema_drift(text)
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        text, _cache, warning = _fetch_feed(force_live=True)
        if warning and not text:
            return Probe(self.key, False, warning)
        problem = schema_drift(text or "")
        if problem:
            return Probe(self.key, False, problem)
        urls = _feed_urls(text or "")
        if not urls:
            return Probe(self.key, False, "live probe returned no URLs")
        record = _record("openphish", urls[0], True, urls[0])
        drift = _response_problem(record)
        if drift:
            return Probe(self.key, False, drift)
        return Probe(self.key, True, "live ok")


def schema_drift(text: str) -> str | None:
    """Reject a feed whose lines are not bare URLs (including a renamed field)."""
    if text is None or "\x00" in text:
        return "OpenPhish payload was not usable"
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    for line in lines:
        if len(line) > 4000 or not _line_is_url(line):
            return "OpenPhish schema drift, missing url"
    return None


class _PublicFeedTransport(httpx.BaseTransport):
    """Allow the OpenPhish GitHub feed path and nothing else on that host."""

    def __init__(self, inner: httpx.BaseTransport) -> None:
        self._inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host or ""
        path = request.url.path or ""
        if host == GITHUB_HOST and not path.startswith(GITHUB_PREFIX):
            raise EgressDenied("redirect path is not the OpenPhish public feed")
        return self._inner.handle_request(request)

    def close(self) -> None:
        closer = getattr(self._inner, "close", None)
        if closer:
            closer()


def _fetch_feed(*, force_live: bool) -> tuple[str | None, str, str]:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    pinned = bool(os.environ.get("CYBERAU_OPENPHISH_SNAPSHOT")) and not force_live
    if pinned:
        return _from_snapshot()
    cache = HttpCache(_data_dir() / "http_cache.sqlite")
    key = cache.key("GET", FEED_URL, None, b"", "anonymous")
    previous = cache.get(key)
    if not force_live and not offline and previous and cache.fresh(previous):
        cached = _decode(previous.body)
        kind = _classify(cached) if cached is not None else "bad"
        if kind == "ok":
            return cached, "hit", ""
        if kind == "empty":
            return cached, "hit", "OpenPhish feed is empty"
    if offline:
        if previous and _classify(_decode(previous.body) or "") == "ok":
            return _decode(previous.body), "stale", ""
        return _from_snapshot()
    try:
        _limit_feed()
    except RateLimited:
        if previous and _classify(_decode(previous.body) or "") == "ok":
            return _decode(previous.body), "stale", ""
        return None, "snapshot", "OpenPhish feed is unavailable: hourly ceiling reached"
    try:
        response = _http(force_live=force_live)
    except (HttpError, EgressDenied, TimeoutError, RateLimited) as exc:
        if not force_live and previous and _classify(_decode(previous.body) or "") == "ok":
            return _decode(previous.body), "stale", ""
        return None, "snapshot", redact(str(exc))
    if response.status in {401, 403}:
        return None, response.cache, _auth_message(response.status)
    if response.status == 429:
        if not force_live and previous and _classify(_decode(previous.body) or "") == "ok":
            return _decode(previous.body), "stale", ""
        return None, response.cache, _rate_message(response.headers)
    if response.status >= 400:
        if not force_live and previous and _classify(_decode(previous.body) or "") == "ok":
            return _decode(previous.body), "stale", ""
        return None, response.cache, f"upstream status {response.status}"
    text = _decode(response.body)
    if text is None:
        return None, response.cache, "OpenPhish payload was not usable"
    kind = _classify(text)
    kept = "empty OpenPhish feed ignored; previous cache kept"
    if kind == "empty":
        if previous and _classify(_decode(previous.body) or "") == "ok":
            _restore(cache, key, previous)
            if not force_live:
                return _decode(previous.body), "stale", kept
        return text, response.cache, "OpenPhish feed is empty"
    if kind == "bad":
        problem = schema_drift(text) or "OpenPhish payload was not usable"
        if previous and _classify(_decode(previous.body) or "") == "ok":
            _restore(cache, key, previous)
            if not force_live:
                return _decode(previous.body), "stale", problem
        return None, response.cache, problem
    return text, response.cache, ""


def _http(*, force_live: bool):
    data_dir = _data_dir()
    client = HttpClient(
        "openphish",
        policy=EgressPolicy(_allowlist(), "openphish"),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", sleeper=_SLEEP),
        user_agent=USER_AGENT,
        rate=1 / 30,
        burst=4,
        window="rolling",
        timeout=30,
        retries=3,
        transport=_feed_transport(),
        sleeper=_SLEEP,
    )
    try:
        return client.get(FEED_URL, ttl=_TTL, stale_if_error=30 * 86400, skip_cache=force_live)
    finally:
        client.close()


def _limit_feed() -> None:
    """One logical feed fetch per hour. Hops inside that fetch use the HTTP client."""
    RateLimiter(_data_dir() / "rate_limit.sqlite", sleeper=_SLEEP).acquire(
        "openphish:feed",
        rate=1 / 3600,
        burst=1,
        window="rolling",
        timeout=60,
    )


def _feed_transport() -> httpx.BaseTransport:
    inner = _TRANSPORT if _TRANSPORT is not None else httpx.HTTPTransport()
    return _PublicFeedTransport(inner)


def _from_snapshot() -> tuple[str | None, str, str]:
    text = _snapshot_text()
    if text is None:
        return None, "snapshot", "OpenPhish feed is unavailable"
    problem = schema_drift(text)
    if problem:
        return None, "snapshot", problem
    if not _feed_urls(text):
        return text, "snapshot", "OpenPhish feed is empty"
    return text, "snapshot", ""


def _snapshot_text() -> str | None:
    override = os.environ.get("CYBERAU_OPENPHISH_SNAPSHOT")
    path = Path(override) if override else _PACKAGE / "data" / "feed.txt"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _restore(cache: HttpCache, key: str, previous) -> None:
    cache.put(
        key,
        status=previous.status,
        headers=previous.headers,
        body=previous.body,
        ttl=previous.ttl or _TTL,
    )


def _openphish_record(query: str, wanted: str, urls: list[str], warning: str) -> dict:
    listed = wanted in urls
    if listed:
        detail = wanted
    elif warning:
        detail = warning
    else:
        detail = "not listed in the OpenPhish community feed"
    return _record("openphish", query, listed, detail)


def _sibling_record(
    name: str,
    query: str,
    wanted: str,
    urls: list[str] | None,
    status: str,
) -> dict:
    if urls is None:
        detail = status or "cache was not usable"
        return _record(name, query, False, detail)
    listed = wanted in urls
    if listed:
        detail = wanted
    elif status:
        detail = status
    elif not urls and status == "":
        detail = "cache is empty"
    else:
        detail = f"not listed in the {_label(name)} cache"
    return _record(name, query, listed, detail)


def _record(name: str, query: str, listed: bool, detail: str) -> dict:
    return {
        "url": untrusted_text(query, name),
        "source": name,
        "listed": listed,
        "detail": untrusted_text(detail, name),
    }


def _sibling_urls(name: str) -> tuple[list[str] | None, str]:
    path = _sibling_path(name)
    if path is None or not path.is_file():
        return [], "cache not present"
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None, "was not usable"
    urls, status = _urls_from_document(text)
    return urls, status


def _sibling_path(name: str) -> Path | None:
    if name == "phishtank":
        override = os.environ.get("CYBERAU_PHISHTANK_CACHE")
        relative = "phishtank/online-valid.json"
    elif name == "urlhaus":
        override = os.environ.get("CYBERAU_URLHAUS_CACHE")
        relative = "urlhaus/recent.json"
    else:
        return None
    if override:
        return Path(override)
    return _data_dir() / relative


def _urls_from_document(text: str) -> tuple[list[str] | None, str]:
    stripped = text.strip()
    if not stripped:
        return [], ""
    if stripped[0] in "[{":
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return None, "was not usable"
        urls = _urls_from_json(payload)
        if urls is None:
            return None, "is missing url"
        return urls, ""
    found = []
    for line in text.splitlines():
        item = line.strip()
        if not item:
            continue
        if not _line_is_url(item):
            return None, "is missing url"
        found.append(_normalise(item))
    return found, ""


def _urls_from_json(payload) -> list[str] | None:
    if isinstance(payload, list):
        if not payload:
            return []
        if all(isinstance(item, str) for item in payload):
            if any(not _line_is_url(item) for item in payload):
                return None
            return [_normalise(item) for item in payload]
        if all(isinstance(item, dict) for item in payload):
            if not any("url" in item or "URL" in item for item in payload):
                return None
            found = []
            for item in payload:
                raw = item.get("url") or item.get("URL")
                if isinstance(raw, str) and _line_is_url(raw):
                    found.append(_normalise(raw))
            return found
        return None
    if isinstance(payload, dict):
        for key in ("urls", "data"):
            if key in payload:
                return _urls_from_json(payload[key])
        if "url" in payload or "URL" in payload:
            return _urls_from_json([payload])
        return None
    return None


def _persist(source: str, urls: list[str]) -> None:
    if not urls:
        return
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    with sqlite3.connect(_data_dir() / "openphish.sqlite") as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS indicators (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                url TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        for url in urls:
            digest = hashlib.sha256(url.encode()).hexdigest()
            conn.execute(
                """
                INSERT INTO indicators (id, source, url, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (f"{source}:{digest}", source, url, now, now),
            )


def _response_problem(record: dict) -> str | None:
    schema = json.loads((_PACKAGE / "schema" / "phish_check_url.response.json").read_text())
    try:
        jsonschema.validate(record, schema)
    except jsonschema.ValidationError as exc:
        return f"OpenPhish response schema: {exc.message}"
    return None


def _query_problem(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        return "url is required"
    parts = urlsplit(url.strip())
    if parts.username or parts.password:
        return "url must not contain userinfo"
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return "url must be an http or https URL"
    return ""


def _classify(text: str) -> str:
    if schema_drift(text):
        return "bad"
    if not _feed_urls(text):
        return "empty"
    return "ok"


def _feed_urls(text: str) -> list[str]:
    if schema_drift(text):
        return []
    found = []
    seen = set()
    for line in text.splitlines():
        item = line.strip()
        if not item:
            continue
        normalised = _normalise(item)
        if normalised in seen:
            continue
        seen.add(normalised)
        found.append(normalised)
    return found


def _line_is_url(value: str) -> bool:
    if any(char.isspace() for char in value):
        return False
    parts = urlsplit(value)
    if parts.username or parts.password:
        return False
    return parts.scheme in {"http", "https"} and bool(parts.hostname)


def _normalise(url: str) -> str:
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    port = parts.port
    default = (parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443)
    netloc = host if port is None or default else f"{host}:{port}"
    path = parts.path or ""
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    rebuilt = f"{parts.scheme.lower()}://{netloc}{path}"
    if parts.query:
        rebuilt += f"?{parts.query}"
    return rebuilt


def _decode(body: bytes) -> str | None:
    try:
        return body.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def _auth_message(status: int) -> str:
    return (
        f"OpenPhish returned {status}. The community feed does not use a key, "
        "so no env var is read."
    )


def _rate_message(headers: dict) -> str:
    retry = headers.get("retry-after") or headers.get("Retry-After") or ""
    if retry:
        return f"OpenPhish rate limited (429); Retry-After {retry}"
    return "OpenPhish rate limited (429)"


def _label(name: str) -> str:
    return {"openphish": "OpenPhish", "phishtank": "PhishTank", "urlhaus": "URLhaus"}[name]


def _envelope(data, cache: str, warnings: tuple[str, ...] = ()) -> dict:
    return envelope(
        "openphish",
        data,
        urls=[FEED_URL, GITHUB_FEED],
        cache=cache,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-openphish"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("openphish", connector)
