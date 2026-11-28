"""Read-only AusCERT member malicious URL feed: check a URL or domain against it.

The member supplies the feed URL (``AUSCERT_URL_FEED``) and, when the feed needs one, a
credential (``AUSCERT_FEED_TOKEN``, sent as a bearer token). The feed format is not public.
This connector assumes the common shape of a malicious URL feed: a plain text list with one
URL per line and ``#`` comments, or CSV with a ``url`` column. See SOURCE.md to adjust it.
The one host in ``AUSCERT_URL_FEED`` is the only host the connector may call. AusMISP is
reached through the MISP connector, not here.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import jsonschema
import yaml
from cyberau_common import USER_AGENT, runtime
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpError
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable

KEY = "auscert-member"
SERVER = "auscertm"
LABEL = "AusCERT member URL feed"
FEED_ENV = "AUSCERT_URL_FEED"
TOKEN_ENV = "AUSCERT_FEED_TOKEN"
TERMS = (
    "AusCERT member data, used under your AusCERT membership terms. Keep it inside your "
    "organisation and do not republish it."
)
ATTRIBUTION = (
    "Source: AusCERT member URL feed. AusCERT member data, used under your AusCERT "
    "membership terms. Keep it inside your organisation and do not republish it. "
    "Not affiliated with AusCERT."
)
DOCTOR_NOTE = "off by default: licence terms. See docs/connectors/auscert-member.md."
DOCS_URL = "https://auscert.org.au/services/threat-intelligence/"
SNAPSHOT_ENV = "CYBERAU_AUSCERT_MEMBER_SNAPSHOT"
OPERATOR_NOTE = (
    f"served the operator-supplied feed file ({SNAPSHOT_ENV}), not a live fetch of the member feed"
)
TTL = 3600
MAX_ENTRIES = 200_000
MAX_MATCHES = 50
_PACKAGE = Path(__file__).resolve().parents[2]
_SCHEMA = _PACKAGE / "schema"
# Read only by the offline schema-drift probe. Never served to a tool caller.
_SCHEMA_FIXTURE = _PACKAGE / "tests" / "fixtures" / "url_feed_synthetic.txt"
_HOST = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{1,63})+")
_URL_COLUMNS = ("url", "uri", "link")
_TRANSPORT = None
_RESOLVER = None
_SLEEP = time.sleep
_LIMIT_SLEEP = time.sleep
_CLOCK = time.monotonic
_RETRIES = 1


def auscert_url_feed_lookup(value: str) -> dict:
    """Check a URL or domain against the cached member URL feed."""
    wanted, problem = _query(value)
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,))
    entries, cache, warnings = _feed()
    if entries is None:
        return _envelope(None, cache, warnings=warnings)
    matches = [item for item in entries if _matches(item, wanted)]
    listed = bool(matches)
    data = {
        "query": untrusted_text(str(value), KEY, 500),
        "kind": wanted["kind"],
        "listed": listed,
        "match_count": len(matches),
        "matches": [_present(item, wanted) for item in matches[:MAX_MATCHES]],
        "entries_checked": len(entries),
    }
    if listed and cache != "snapshot":
        _persist(matches)
    notes = list(warnings)
    if not listed:
        notes.append("not listed in the member URL feed")
    if len(matches) > MAX_MATCHES:
        notes.append(f"showing the first {MAX_MATCHES} of {len(matches)} matching entries")
    return _envelope(data, cache, warnings=tuple(notes))


def auscert_url_feed_status() -> dict:
    """Last fetch time and entry count."""
    entries, cache, warnings = _feed()
    fetched_at = _fetched_at()
    if entries is None:
        data = {
            "configured": _configured_problem() == "",
            "entries": 0,
            "fetched_at": fetched_at,
            "cache": cache,
            "format": None,
        }
        return _envelope(data, cache, warnings=warnings)
    data = {
        "configured": _configured_problem() == ""
        or bool(os.environ.get("CYBERAU_AUSCERT_MEMBER_SNAPSHOT")),
        "entries": len(entries),
        "fetched_at": fetched_at,
        "cache": cache,
        "format": _LAST_FORMAT.get("format"),
    }
    notes = list(warnings)
    if not entries:
        notes.append("the member URL feed has no entries")
    return _envelope(data, cache, warnings=tuple(notes))


def parse_feed(text: str) -> tuple[list[dict] | None, str, str]:
    """Parse a feed body. Returns the entries, the format name and a problem."""
    if not isinstance(text, str) or "\x00" in text:
        return None, "", "the member URL feed was not usable"
    lines = [line for line in text.splitlines() if line.strip()]
    content = [line for line in lines if not line.lstrip().startswith("#")]
    if not content:
        return [], "text", ""
    header = next(csv.reader([content[0]]))
    columns = [cell.strip().lower() for cell in header]
    # CSV when the first row names a url column, or is a multi-column row that is not
    # itself a URL (a header whose url column was renamed). A URL with a comma in its
    # query stays a text line.
    named = any(name in _URL_COLUMNS for name in columns)
    if named or (len(columns) > 1 and _normalise_url(content[0].strip()) is None):
        return _parse_csv(content)
    return _parse_text(content)


def schema_drift(text: str) -> str | None:
    """A body with no URL column or a line that is not a URL is drift."""
    entries, _format, problem = parse_feed(text)
    if entries is None:
        return problem or "the member URL feed was not usable"
    return None


def connector() -> Connector:
    return _AuscertMemberConnector()


class _AuscertMemberConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key=KEY,
            server_name=SERVER,
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "auscert_url_feed_lookup",
                    "Check a URL or domain against the cached member URL feed.",
                    auscert_url_feed_lookup,
                ),
                ToolSpec(
                    "auscert_url_feed_status",
                    "Last fetch time and entry count.",
                    auscert_url_feed_status,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            text = _snapshot_text()
            if text is None:
                text = _SCHEMA_FIXTURE.read_text(encoding="utf-8")
            problem = schema_drift(text)
            if problem:
                return Probe(self.key, False, problem)
            entries, _format, _problem = parse_feed(text)
            problem = _response_problem("auscert_url_feed_status", _status_record(entries or []))
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        problem = _configured_problem()
        if problem:
            return Probe(self.key, False, problem)
        text, cache, warning = _fetch(force_live=True)
        if text is None:
            return Probe(self.key, False, warning)
        if cache != "miss":
            return Probe(self.key, False, f"feed was served from cache ({cache}), not live")
        entries, _format, problem = parse_feed(text)
        if entries is None:
            return Probe(self.key, False, problem)
        record = _status_record(entries)
        problem = _response_problem("auscert_url_feed_status", record)
        if problem:
            return Probe(self.key, False, problem)
        if entries:
            sample = _present(entries[0], {"kind": "domain", "host": entries[0]["host"]})
            lookup_record = {
                "query": "probe",
                "kind": "domain",
                "listed": True,
                "match_count": 1,
                "matches": [sample],
                "entries_checked": len(entries),
            }
            problem = _response_problem("auscert_url_feed_lookup", lookup_record)
            if problem:
                return Probe(self.key, False, problem)
        return Probe(self.key, True, f"live ok, {len(entries)} entries")


# Parsing.


def _parse_text(lines: list[str]) -> tuple[list[dict] | None, str, str]:
    entries: list[dict] = []
    seen: set[str] = set()
    for line in lines:
        item = line.split(" #", 1)[0].strip()
        entry = _entry(item, None)
        if entry is None:
            return None, "text", "AusCERT member feed schema drift, a line is not a URL"
        if entry["url"] in seen:
            continue
        seen.add(entry["url"])
        entries.append(entry)
        if len(entries) >= MAX_ENTRIES:
            break
    return entries, "text", ""


def _parse_csv(lines: list[str]) -> tuple[list[dict] | None, str, str]:
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    fields = {(name or "").strip().lower(): name for name in reader.fieldnames or []}
    column = next((fields[name] for name in _URL_COLUMNS if name in fields), None)
    if column is None:
        return None, "csv", "AusCERT member feed schema drift, missing url column"
    extra = {
        key: fields[key]
        for key in ("first_seen", "date", "date_added", "added", "category", "type", "threat")
        if key in fields
    }
    entries: list[dict] = []
    seen: set[str] = set()
    for row in reader:
        raw = (row.get(column) or "").strip()
        if not raw:
            continue
        entry = _entry(raw, row, extra)
        if entry is None:
            continue
        if entry["url"] in seen:
            continue
        seen.add(entry["url"])
        entries.append(entry)
        if len(entries) >= MAX_ENTRIES:
            break
    return entries, "csv", ""


def _entry(raw: str, row: dict | None, extra: dict | None = None) -> dict | None:
    url = _normalise_url(raw)
    if url is None:
        return None
    entry = {"url": url, "host": urlsplit(url).hostname or "", "first_seen": None, "category": None}
    if row and extra:
        for name in ("first_seen", "date", "date_added", "added"):
            if name in extra and (row.get(extra[name]) or "").strip():
                entry["first_seen"] = (row[extra[name]] or "").strip()[:40]
                break
        for name in ("category", "type", "threat"):
            if name in extra and (row.get(extra[name]) or "").strip():
                entry["category"] = (row[extra[name]] or "").strip()[:200]
                break
    return entry


def _normalise_url(value: str) -> str | None:
    text = value.strip().strip('"')
    if not text or len(text) > 4000 or any(char.isspace() for char in text):
        return None
    text = text.replace("hxxps://", "https://").replace("hxxp://", "http://")
    text = text.replace("[.]", ".").replace("[:]", ":")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return None
    host = parts.hostname.lower().rstrip(".")
    default = port is None or (parts.scheme.lower(), port) in {("http", 80), ("https", 443)}
    netloc = host if default else f"{host}:{port}"
    if ":" in host:
        netloc = f"[{host}]" if default else f"[{host}]:{port}"
    path = parts.path or ""
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    rebuilt = f"{parts.scheme.lower()}://{netloc}{path}"
    if parts.query:
        rebuilt += f"?{parts.query}"
    return rebuilt


def _query(value) -> tuple[dict, str]:
    if not isinstance(value, str) or len(value.strip()) < 3:
        return {}, "value must be a URL or a domain of at least 3 characters"
    text = value.strip()
    if "://" in text or text.lower().startswith(("hxxp", "http")):
        url = _normalise_url(text)
        if url is None:
            return {}, "value must be an http or https URL, or a domain"
        return {"kind": "url", "url": url, "host": urlsplit(url).hostname or ""}, ""
    host = text.replace("[.]", ".").lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOST.fullmatch(host):
            return {}, "value must be an http or https URL, or a domain"
    return {"kind": "domain", "host": host}, ""


def _matches(entry: dict, wanted: dict) -> bool:
    if wanted["kind"] == "url":
        return entry["url"] == wanted["url"]
    host = entry["host"]
    return host == wanted["host"] or host.endswith("." + wanted["host"])


def _present(entry: dict, wanted: dict) -> dict:
    match = "exact" if wanted["kind"] == "url" or entry["host"] == wanted["host"] else "subdomain"
    return {
        "url": untrusted_text(entry["url"], KEY, 4000),
        "host": entry["host"],
        "match": match,
        "first_seen": untrusted_text(entry["first_seen"], KEY, 40) if entry["first_seen"] else None,
        "category": untrusted_text(entry["category"], KEY, 200) if entry["category"] else None,
    }


def _status_record(entries: list[dict]) -> dict:
    return {
        "configured": True,
        "entries": len(entries),
        "fetched_at": None,
        "cache": "miss",
        "format": "text",
    }


# Fetching.

_LAST_FORMAT: dict[str, str] = {}


def _feed() -> tuple[list[dict] | None, str, tuple[str, ...]]:
    text, cache, warning = _fetch(force_live=False)
    warnings: list[str] = []
    if (
        cache == "snapshot"
        and os.environ.get("CYBERAU_AUSCERT_MEMBER_SNAPSHOT")
        and text is not None
    ):
        warnings.append(OPERATOR_NOTE)
    if text is None:
        return None, cache, (warning,)
    if warning:
        warnings.append(warning)
    entries, fmt, problem = parse_feed(text)
    if entries is None:
        return None, cache, (problem,)
    _LAST_FORMAT["format"] = fmt
    return entries, cache, tuple(warnings)


def _fetch(*, force_live: bool) -> tuple[str | None, str, str]:
    if os.environ.get("CYBERAU_AUSCERT_MEMBER_SNAPSHOT") and not force_live:
        text = _snapshot_text()
        if text is None:
            return None, "snapshot", unavailable(LABEL, f"the {SNAPSHOT_ENV} file is missing")
        return text, "snapshot", ""
    problem = _configured_problem()
    offline = runtime.offline() and not force_live
    if problem and not offline:
        return None, "snapshot", problem
    url = _feed_url()
    token = lookup("AUSCERT_FEED_TOKEN")
    data_dir = runtime.data_dir(KEY, mode=0o700)
    cache = HttpCache(data_dir / "http_cache.sqlite")
    scope = _scope(token)
    cached = cache.get(cache.key("GET", url, None, b"", scope)) if url else None
    if offline:
        if cached is None:
            return None, "snapshot", unavailable(LABEL, "offline mode and no cached copy")
        state = "hit" if cache.fresh(cached) else "stale"
        return _decode(cached.body), state, ""
    client = runtime.http_client(
        KEY,
        directory=data_dir,
        policy=_policy(url),
        cache=cache,
        limiter_clock=_CLOCK,
        limiter_sleeper=_LIMIT_SLEEP,
        user_agent=USER_AGENT,
        # The feed is cached for an hour; this ceiling stays well under any member terms.
        rate=1 / 60,
        burst=4,
        window="rolling",
        timeout=60,
        retries=_RETRIES,
        auth_scope=scope,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
    )
    headers = {"Accept": "text/plain, text/csv, */*"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = client.get(url, headers=headers, ttl=TTL, skip_cache=force_live)
    except (HttpError, EgressDenied, TimeoutError, OSError) as exc:
        if not force_live and cached is not None:
            return _decode(cached.body), "stale", ""
        return None, "snapshot", _clean(exc, token)
    finally:
        client.close()
    if response.status in (401, 403):
        return None, response.cache, _auth_message(response.status)
    if response.status == 429:
        wait = str(response.headers.get("retry-after", "")).strip()
        hint = f" Retry after {wait} seconds." if wait.isdigit() else ""
        if not force_live and cached is not None:
            return _decode(cached.body), "stale", f"the feed returned 429.{hint}"
        return None, response.cache, unavailable(LABEL, f"the feed returned 429.{hint}".strip())
    if response.status >= 400:
        if not force_live and cached is not None:
            return _decode(cached.body), "stale", f"upstream status {response.status}"
        return None, response.cache, unavailable(LABEL, f"upstream status {response.status}")
    text = _decode(response.body)
    if text is None:
        return None, response.cache, "the member URL feed was not usable"
    return text, response.cache, ""


def _configured_problem() -> str:
    raw = lookup("AUSCERT_URL_FEED")
    if raw is None:
        return unavailable(LABEL, f"{FEED_ENV} is not set")
    _url, problem = _parse_feed_url(raw)
    return problem


def _feed_url() -> str:
    url, _problem = _parse_feed_url(lookup("AUSCERT_URL_FEED") or "")
    return url or ""


def _parse_feed_url(raw: str) -> tuple[str | None, str]:
    try:
        parts = urlsplit(raw.strip())
        port = parts.port
    except ValueError:
        return None, f"{FEED_ENV} is not a valid URL."
    if parts.username or parts.password:
        return None, f"{FEED_ENV} must not contain userinfo. Put a credential in {TOKEN_ENV}."
    if parts.scheme.lower() != "https" or not parts.hostname:
        return None, f"{FEED_ENV} must be an https URL with a host."
    host = parts.hostname.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        literal = False
    else:
        literal = True
    if literal or not _HOST.fullmatch(host):
        return None, f"{FEED_ENV} must name a host. IP literals are not allowed."
    netloc = host if port is None else f"{host}:{port}"
    rebuilt = f"https://{netloc}{parts.path or '/'}"
    if parts.query:
        rebuilt += f"?{parts.query}"
    return rebuilt, ""


def _policy(url: str) -> EgressPolicy:
    """The allowlist entry for this connector, plus the one host in AUSCERT_URL_FEED."""
    host = (urlsplit(url).hostname or "").lower()
    directory = runtime.data_dir(KEY, mode=0o700)
    path = directory / "auscert-member-egress.yaml"
    hosts: list[str] = []
    for item in [*_static_hosts(), host]:
        if item and item not in hosts:
            hosts.append(item)
    lines = ["connectors:", f"  {KEY}:", "    hosts:", *[f"      - {item}" for item in hosts]]
    lines.extend(["    allow_ip_literals: false", "    allow_http_loopback: false", ""])
    path.write_text("\n".join(lines), encoding="utf-8")
    return EgressPolicy(path, KEY, resolver=_RESOLVER)


def _static_hosts() -> list[str]:
    path = runtime.allowlist_path()
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    spec = (data.get("connectors") or {}).get(KEY) or {}
    found = []
    for item in spec.get("hosts") or []:
        text = str(item).strip().lower().rstrip(".")
        if _HOST.fullmatch(text) and text not in found:
            found.append(text)
    return found


def _scope(token: str | None) -> str:
    """Cache scope per credential, so a different token never reads another one's copy."""
    if not token:
        return "anonymous"
    return "key:" + hashlib.sha256(token.encode()).hexdigest()


def _fetched_at() -> str | None:
    """When the cached copy of the feed was fetched, as ISO 8601 UTC."""
    if os.environ.get("CYBERAU_AUSCERT_MEMBER_SNAPSHOT"):
        path = Path(os.environ[SNAPSHOT_ENV])
        if path.is_file():
            return runtime.iso(datetime.fromtimestamp(path.stat().st_mtime, UTC))
        return None
    url = _feed_url()
    if not url or runtime.configured_data_dir() is None:
        return None
    cache = HttpCache(runtime.data_dir(KEY, mode=0o700) / "http_cache.sqlite")
    cached = cache.get(cache.key("GET", url, None, b"", _scope(lookup("AUSCERT_FEED_TOKEN"))))
    if cached is None:
        return None
    return runtime.iso(datetime.fromtimestamp(cached.fetched_at, UTC))


def _persist(entries: list[dict]) -> None:
    """Keep matched entries as local history. Member data stays in the profile data dir."""
    if runtime.configured_data_dir() is None:
        return
    directory = runtime.data_dir(KEY, mode=0o700)
    now = runtime.utc_now_iso()
    path = directory / "auscert-member.sqlite"
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS matches (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        for entry in entries:
            digest = hashlib.sha256(entry["url"].encode()).hexdigest()
            conn.execute(
                """
                INSERT INTO matches (id, url, first_seen, last_seen) VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (digest, entry["url"], now, now),
            )
    os.chmod(path, 0o600)


def _snapshot_text() -> str | None:
    raw = os.environ.get("CYBERAU_AUSCERT_MEMBER_SNAPSHOT")
    if not raw:
        return None
    path = Path(raw)
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _decode(body: bytes) -> str | None:
    try:
        return body.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def _auth_message(status: int) -> str:
    return (
        f"The member feed returned {status}. Check {TOKEN_ENV} (and {FEED_ENV}) against "
        "the feed details from AusCERT."
    )


def _clean(exc: BaseException, token: str | None) -> str:
    message = redact(str(exc))
    if token and token in message:
        message = message.replace(token, "[REDACTED]")
    lowered = message.lower()
    kept = ("not allowlisted", "only https", "ip literal", "blocked address", "userinfo")
    if any(part in lowered for part in kept):
        return message
    return unavailable(LABEL, "the feed could not be reached and no cached copy exists")


def _response_problem(tool: str, record: dict) -> str | None:
    schema = json.loads((_SCHEMA / f"{tool}.response.json").read_text(encoding="utf-8"))
    try:
        jsonschema.validate(record, schema)
    except jsonschema.ValidationError as exc:
        return f"{LABEL} {tool} response schema: {exc.message}"
    return None


def _envelope(data, cache: str, *, warnings: tuple[str, ...] = ()) -> dict:
    return envelope(
        KEY,
        data,
        urls=[DOCS_URL],
        cache=cache,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


register_connector(KEY, connector)
