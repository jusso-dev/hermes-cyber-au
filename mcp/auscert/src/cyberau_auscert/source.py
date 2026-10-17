"""Read-only AusCERT public security bulletins."""

import email.utils
import json
import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimited, RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

FEED_URL = "https://portal.auscert.org.au/rss/bulletins/"
ATTRIBUTION = (
    "AusCERT public security bulletins (portal.auscert.org.au). Title, link, date and feed "
    "summary only. Not endorsed by AusCERT."
)
TTL = 30 * 60
_HOST = "portal.auscert.org.au"
_SYDNEY = ZoneInfo("Australia/Sydney")
_CONTENT = "{http://purl.org/rss/1.0/modules/content/}encoded"
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CVE_EXACT = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_BULLETIN = re.compile(r"/bulletins/([A-Z]{3}-\d{4}\.\d+(?:\.\d+)?)", re.IGNORECASE)
_CVSS = re.compile(r"CVSS \(Max\):\s*(\d{1,2}(?:\.\d)?)")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_PUBLIC_CVES = 50
_PACKAGE = Path(__file__).resolve().parents[2]
_TRANSPORT = None

_Since = Annotated[
    str,
    Field(
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="YYYY-MM-DD, interpreted in Australia/Sydney",
    ),
]
_Limit = Annotated[int, Field(ge=1, le=100)]


@dataclass
class _Feed:
    text: str | None
    cache: str
    warnings: tuple[str, ...] = ()
    persist: bool = False


def auscert_bulletins(
    since: _Since | None = None,
    query: str | None = None,
    limit: _Limit = 20,
) -> dict:
    problem = _validate(since, limit)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    return _collect(since, query, limit)


def connector() -> Connector:
    return _AuscertConnector()


class _AuscertConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="auscert",
            server_name="auscert",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "auscert_bulletins",
                    "Recent AusCERT public security bulletins, optionally filtered by keyword "
                    "or CVE.",
                    auscert_bulletins,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            problem = schema_drift(_read(_snapshot_path()))
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        result = _collect(None, None, 1, force_live=True)
        if result["warnings"]:
            return Probe(self.key, False, result["warnings"][0])
        if not result["data"]:
            return Probe(self.key, False, "live probe returned no bulletins")
        schema = json.loads(
            (_PACKAGE / "schema" / "auscert_bulletins.response.json").read_text(encoding="utf-8")
        )
        try:
            jsonschema.validate(result, schema)
        except jsonschema.ValidationError as exc:
            return Probe(self.key, False, f"response schema mismatch: {exc.message}")
        return Probe(self.key, True, "live ok")


def schema_drift(text: str | None) -> str | None:
    return _root(text)[1]


def _collect(
    since: str | None,
    query: str | None,
    limit: int,
    *,
    force_live: bool = False,
) -> dict:
    feed = _fetch(force_live=force_live)
    warnings = list(feed.warnings)
    if feed.text is None:
        return _envelope([], feed.cache, warnings=warnings)
    root, problem = _root(feed.text)
    if root is None:
        return _envelope([], feed.cache, warnings=[*warnings, problem or "AusCERT feed unusable"])
    records, skipped = _records(root)
    if skipped:
        warnings.append(f"{skipped} feed items were skipped because they were incomplete")
    if not records and not skipped:
        warnings.append("AusCERT feed contained no bulletins")
    if feed.persist:
        try:
            _persist(records)
        except (OSError, sqlite3.Error) as exc:
            warnings.append(f"could not record bulletins locally: {redact(str(exc))}")
    chosen = _select(records, since, query)[:limit]
    return _envelope(
        [_public(row) for row in chosen],
        feed.cache,
        as_of=_as_of(root, records),
        warnings=warnings,
    )


def _fetch(*, force_live: bool = False) -> _Feed:
    snapshot = os.environ.get("CYBERAU_AUSCERT_SNAPSHOT")
    if snapshot and not force_live:
        return _Feed(_read(Path(snapshot)), "snapshot")
    data_dir = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-auscert"))
    cache = HttpCache(data_dir / "http_cache.sqlite")
    key = cache.key("GET", FEED_URL, None, b"", "anonymous")
    cached = cache.get(key)
    if os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live:
        if cached:
            if cache.fresh(cached):
                return _Feed(_decode(cached.body), "hit", persist=True)
            note = "offline, served the cached feed past its 30 minute lifetime"
            return _Feed(_decode(cached.body), "stale", (note,), persist=True)
        note = "offline and nothing cached, served the shipped snapshot"
        return _Feed(_read(_snapshot_path()), "snapshot", (note,))
    if cached and cache.fresh(cached) and not force_live:
        return _Feed(_decode(cached.body), "hit", persist=True)
    wait = _backoff_remaining(data_dir)
    if wait > 0:
        return _fallback(cached, f"AusCERT asked for a pause, retry in {int(wait)} seconds")
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    client = HttpClient(
        "auscert",
        policy=EgressPolicy(allowlist, "auscert"),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        timeout=60,
        retries=0,
        user_agent=USER_AGENT,
        rate=1 / TTL,
        burst=1,
        window="rolling",
        transport=_TRANSPORT,
    )
    try:
        response = client.get(
            FEED_URL,
            ttl=TTL,
            skip_cache=force_live,
            headers={"accept": "application/rss+xml, application/xml;q=0.9, text/xml;q=0.8"},
        )
    except (HttpError, EgressDenied, RateLimited, TimeoutError, OSError) as exc:
        return _fallback(cached, redact(str(exc)) or "AusCERT could not be reached")
    finally:
        client.close()
    if response.status in (401, 403):
        # The public RSS needs no credential, so there is no env var to set.
        note = (
            f"AusCERT answered HTTP {response.status}. The public bulletin feed needs no "
            "credential and this connector has no env var for one. Member content is out of scope"
        )
        return _fallback(cached, note)
    if response.status == 429:
        seconds = _retry_after(response.headers.get("retry-after"))
        _set_backoff(data_dir, seconds)
        return _fallback(cached, f"AusCERT rate limited this client, retry in {seconds} seconds")
    if response.status >= 400:
        return _fallback(cached, f"AusCERT answered HTTP {response.status}")
    warnings = ()
    if response.cache == "stale":
        warnings = ("AusCERT could not be reached, served the stale cached feed",)
    return _Feed(_decode(response.body), response.cache, warnings, persist=True)


def _fallback(cached, reason: str) -> _Feed:
    if cached:
        return _Feed(
            _decode(cached.body),
            "stale",
            (f"{reason}; served the stale cached feed",),
            persist=True,
        )
    return _Feed(None, "snapshot", (f"{reason}; AusCERT bulletins are unavailable",))


def _root(text: str | None) -> tuple[ET.Element | None, str | None]:
    if not text or not text.strip():
        return None, "AusCERT feed is empty"
    if re.search(r"<!(DOCTYPE|ENTITY)", text, re.IGNORECASE):
        return None, "AusCERT feed carries a DTD, refused"
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None, "AusCERT feed is not XML"
    if root.tag != "rss":
        return None, "AusCERT schema drift, missing rss"
    if root.find("channel") is None:
        return None, "AusCERT schema drift, missing channel"
    first = root.find("channel/item")
    if first is not None:
        missing = [name for name in ("title", "link", "pubDate") if first.find(name) is None]
        if missing:
            return None, "AusCERT schema drift, missing " + ", ".join(missing)
    return root, None


def _records(root: ET.Element) -> tuple[list[dict], int]:
    rows: dict[str, dict] = {}
    skipped = 0
    for node in root.findall("channel/item"):
        title = _clean(node.findtext("title"))
        link = (node.findtext("link") or "").strip()
        guid = (node.findtext("guid") or "").strip()
        match = _BULLETIN.search(link) or _BULLETIN.search(guid)
        stamp = _stamp(node.findtext("pubDate"))
        if not title or match is None or stamp is None:
            skipped += 1
            continue
        bulletin_id = match.group(1).upper()
        summary = _clean(node.findtext("description"))
        body = node.findtext(_CONTENT) or ""
        cves = sorted({item.upper() for item in _CVE.findall(f"{title} {summary} {body}")})
        cvss = _CVSS.search(title)
        rows.setdefault(
            bulletin_id,
            {
                "bulletin_id": bulletin_id,
                "kind": bulletin_id[:3],
                "title": title,
                "link": _link(link, bulletin_id),
                "stamp": stamp,
                "summary": summary,
                "cvss_max": min(float(cvss.group(1)), 10.0) if cvss else None,
                "cves": cves,
            },
        )
    ordered = sorted(
        rows.values(),
        key=lambda row: (row["stamp"], row["bulletin_id"]),
        reverse=True,
    )
    return ordered, skipped


def _select(records: list[dict], since: str | None, query: str | None) -> list[dict]:
    needle = (query or "").strip()
    chosen = []
    for row in records:
        if since and row["stamp"].astimezone(_SYDNEY).date().isoformat() < since:
            continue
        if needle and not _matches(row, needle):
            continue
        chosen.append(row)
    return chosen


def _matches(row: dict, needle: str) -> bool:
    if _CVE_EXACT.match(needle):
        return needle.upper() in row["cves"]
    lowered = needle.lower()
    haystack = f"{row['bulletin_id']} {row['title']} {row['summary']}".lower()
    return lowered in haystack


def _public(row: dict) -> dict:
    return {
        "bulletin_id": row["bulletin_id"],
        "kind": row["kind"],
        "title": untrusted_text(row["title"], "auscert"),
        "link": row["link"],
        "published": row["stamp"].astimezone(_SYDNEY).isoformat(timespec="seconds"),
        "summary": untrusted_text(row["summary"], "auscert") if row["summary"] else "",
        "cvss_max": row["cvss_max"],
        "cves": row["cves"][:_PUBLIC_CVES],
        "cve_count": len(row["cves"]),
    }


def _link(raw: str, bulletin_id: str) -> str:
    parts = urlsplit(raw)
    if (parts.hostname or "").lower() == _HOST and parts.scheme in ("http", "https"):
        return f"https://{_HOST}{parts.path}"
    return f"https://{_HOST}/bulletins/{bulletin_id}/"


def _stamp(raw: str | None) -> datetime | None:
    if not raw or not raw.strip():
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(raw.strip())
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _as_of(root: ET.Element, records: list[dict]) -> str | None:
    built = _stamp(root.findtext("channel/lastBuildDate"))
    if built is None and records:
        built = records[0]["stamp"]
    return built.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if built else None


def _clean(value: str | None) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _validate(since: str | None, limit: int) -> str:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        return "limit must be between 1 and 100"
    if since:
        if not _DATE.match(since):
            return "since must be YYYY-MM-DD"
        try:
            date.fromisoformat(since)
        except ValueError:
            return "since must be a real calendar date"
    return ""


def _persist(records: list[dict]) -> None:
    if not records:
        return
    directory = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-auscert"))
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    with closing(sqlite3.connect(directory / "auscert_bulletins.sqlite", timeout=5)) as conn:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bulletins (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    title TEXT NOT NULL,
                    link TEXT NOT NULL,
                    published TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    cves TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
                """
            )
            conn.executemany(
                """
                INSERT INTO bulletins
                    (id, kind, title, link, published, summary, cves, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title,
                    link=excluded.link,
                    published=excluded.published,
                    summary=excluded.summary,
                    cves=excluded.cves,
                    last_seen=excluded.last_seen
                """,
                [
                    (
                        row["bulletin_id"],
                        row["kind"],
                        row["title"],
                        row["link"],
                        row["stamp"].astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        row["summary"],
                        json.dumps(row["cves"]),
                        now,
                        now,
                    )
                    for row in records
                ],
            )


def _retry_after(header: str | None) -> int:
    try:
        seconds = int(float(header or ""))
    except ValueError:
        seconds = TTL
    return max(60, min(seconds, 3600))


def _backoff_path(data_dir: Path) -> Path:
    return data_dir / "auscert_backoff.json"


def _set_backoff(data_dir: Path, seconds: int) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    _backoff_path(data_dir).write_text(json.dumps({"until": time.time() + seconds}))


def _backoff_remaining(data_dir: Path) -> float:
    try:
        until = float(json.loads(_backoff_path(data_dir).read_text())["until"])
    except (OSError, ValueError, KeyError, TypeError):
        return 0.0
    return max(0.0, until - time.time())


def _snapshot_path() -> Path:
    snapshot = os.environ.get("CYBERAU_AUSCERT_SNAPSHOT")
    return Path(snapshot) if snapshot else _PACKAGE / "data" / "bulletins.xml"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _decode(body: bytes) -> str:
    return body.decode("utf-8", "replace")


def _envelope(
    data,
    cache: str,
    *,
    as_of: str | None = None,
    warnings: tuple[str, ...] | list[str] = (),
) -> dict:
    return envelope(
        "auscert",
        data,
        urls=[FEED_URL],
        cache=cache,
        data_as_of=as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("auscert", connector)
