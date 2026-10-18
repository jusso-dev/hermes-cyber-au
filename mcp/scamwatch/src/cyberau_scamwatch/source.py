"""Read-only Scamwatch homepage alerts.

A 403 or an access-denied page is reported as blocked. It is never returned as
an empty alert list.
"""

import hashlib
import json
import os
import re
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Annotated
from urllib.parse import urljoin, urlsplit

from cyberau_common import GOV_AU_USER_AGENT as USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimited, RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

HOME = "https://www.scamwatch.gov.au/"
TTL = 6 * 3600
ATTRIBUTION = (
    "Scamwatch alerts from scamwatch.gov.au (ACCC). Licence not confirmed. "
    "This connector is not endorsed by the ACCC or Scamwatch."
)
_URL = re.compile(r"^https://www\.scamwatch\.gov\.au/")
_WS = re.compile(r"\s+")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u200b-\u200f]")
_DATE_ONLY = re.compile(r"(?:\d{4}-\d{2}-\d{2}|\d{1,2}\s+[A-Za-z]+\s+\d{4})")
_MONTHS = {
    "jan": 1,
    "january": 1,
    "feb": 2,
    "february": 2,
    "mar": 3,
    "march": 3,
    "apr": 4,
    "april": 4,
    "may": 5,
    "jun": 6,
    "june": 6,
    "jul": 7,
    "july": 7,
    "aug": 8,
    "august": 8,
    "sep": 9,
    "sept": 9,
    "september": 9,
    "oct": 10,
    "october": 10,
    "nov": 11,
    "november": 11,
    "dec": 12,
    "december": 12,
}
_ALERT_PREFIX = "/about-us/news-and-alerts/"
_Limit = Annotated[int, Field(ge=1, le=50)]
_Url = Annotated[str, Field(pattern=r"^https://www\.scamwatch\.gov\.au/")]
_PACKAGE = Path(__file__).resolve().parents[2]
_TRANSPORT = None
_SLEEP = time.sleep


def _rng() -> float:
    return 0.0


@dataclass
class _ParsedHome:
    saw_section: bool = False
    alerts: list[dict] = field(default_factory=list)


def scamwatch_list_alerts(limit: _Limit = 10) -> dict:
    problem = _check_limit(limit)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    text, cache, warning = _fetch_home(force_live=False)
    if text is None:
        return _envelope([], cache, warnings=(_unavailable(warning),))
    drift = schema_drift(text)
    if drift:
        return _envelope([], cache, warnings=(_join(warning, drift),))
    try:
        alerts = _parse_home(text).alerts
    except Exception as exc:
        return _envelope([], cache, warnings=(redact(f"Scamwatch page could not be read: {exc}"),))
    _persist(alerts, body="")
    public = [_public_alert(item) for item in alerts[:limit]]
    warnings: list[str] = []
    if warning:
        warnings.append(warning)
    if not public and not warnings:
        warnings.append("Scamwatch listed no alerts")
    return _envelope(public, cache, warnings=tuple(warnings), as_of=_newest(alerts))


def scamwatch_get_alert(url: _Url) -> dict:
    problem = _check_url(url)
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,), urls=())
    text, cache, warning = _fetch_url(url, force_live=False)
    if text is None:
        return _envelope(None, cache, warnings=(_unavailable(warning),), urls=(url,))
    if _looks_blocked(text):
        return _envelope(
            None,
            cache,
            warnings=(_join(warning, _blocked_page()),),
            urls=(url,),
        )
    try:
        page = _parse_page(text, url)
    except Exception as exc:
        return _envelope(
            None,
            cache,
            warnings=(redact(f"Scamwatch alert could not be read: {exc}"),),
            urls=(url,),
        )
    if not page["title"] and not page["body"]:
        return _envelope(
            None,
            cache,
            warnings=(_join(warning, "Scamwatch alert page had no text"),),
            urls=(url,),
        )
    if _alert_slug(url):
        _persist([{**page, "url": _canonical(url)}], body=page["body"])
    warnings = (warning,) if warning else ()
    return _envelope(
        _public_page(page),
        cache,
        warnings=warnings,
        urls=(url,),
        as_of=page["date"] or None,
    )


def connector() -> Connector:
    return _ScamwatchConnector()


class _ScamwatchConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="scamwatch",
            server_name="scamwatch",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "scamwatch_list_alerts",
                    "Current scam alerts with title, date and link.",
                    scamwatch_list_alerts,
                ),
                ToolSpec(
                    "scamwatch_get_alert",
                    "One alert as cleaned text.",
                    scamwatch_get_alert,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            problem = schema_drift(_snapshot_text() or "")
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        text, _cache, warning = _fetch_home(force_live=True)
        if warning:
            return Probe(self.key, False, warning)
        problem = schema_drift(text or "")
        if problem:
            return Probe(self.key, False, problem)
        if not text:
            return Probe(self.key, False, "live probe returned no page")
        return Probe(self.key, True, "live ok")


def schema_drift(html: str) -> str | None:
    if not html or not html.strip():
        return "Scamwatch page is empty"
    if _looks_blocked(html):
        return _blocked_page()
    try:
        parsed = _parse_home(html)
    except Exception:
        return "Scamwatch page could not be read"
    if not parsed.saw_section:
        return "Scamwatch schema drift, missing news and alerts"
    return None


def _fetch_home(*, force_live: bool) -> tuple[str | None, str, str]:
    if not force_live and os.environ.get("CYBERAU_SCAMWATCH_SNAPSHOT"):
        return _snapshot_text(), "snapshot", ""
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if offline:
        return _offline_home()
    cached, state = _cached(HOME)
    if cached is not None and state == "hit" and not force_live:
        return cached, "hit", ""
    return _live(HOME, force_live=force_live, fallback=not force_live)


def _fetch_url(url: str, *, force_live: bool) -> tuple[str | None, str, str]:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    mapped = _mapped_page(url)
    pages = os.environ.get("CYBERAU_SCAMWATCH_PAGES")
    if mapped is not None and not force_live and (offline or pages):
        return mapped, "snapshot", ""
    if offline:
        cached, state = _cached(url)
        if cached is not None:
            return cached, state, ""
        stored = _stored_body(_canonical(url))
        if stored:
            return stored, "stale", ""
        return None, "snapshot", "unavailable: Scamwatch has no cached or snapshot copy"
    cached, state = _cached(url)
    if cached is not None and state == "hit" and not force_live:
        return cached, "hit", ""
    return _live(url, force_live=force_live, fallback=not force_live)


def _offline_home() -> tuple[str | None, str, str]:
    cached, state = _cached(HOME)
    if cached is not None:
        return cached, state, ""
    shipped = _shipped_home()
    if shipped:
        return shipped, "snapshot", ""
    return None, "snapshot", "unavailable: Scamwatch has no cached or snapshot copy"


def _live(url: str, *, force_live: bool, fallback: bool) -> tuple[str | None, str, str]:
    budget = _take_budget()
    if budget:
        budget = _recent_block() or budget
        if force_live or not fallback:
            return None, "snapshot", budget
        cached, _state = _cached(url)
        if cached is not None:
            return cached, "stale", budget
        stored = _stored_body(_canonical(url)) if url != HOME else ""
        if stored:
            return stored, "stale", budget
        return None, "snapshot", budget
    return _http(url, skip_cache=force_live, fallback=fallback)


def _http(url: str, *, skip_cache: bool, fallback: bool) -> tuple[str | None, str, str]:
    client = _client()
    try:
        try:
            response = client.get(url, ttl=TTL, skip_cache=skip_cache, stale_if_error=7 * 86400)
        except (HttpError, EgressDenied, TimeoutError, RateLimited) as exc:
            if fallback:
                cached, _state = _cached(url)
                if cached is not None:
                    return cached, "stale", "served from cache after the live fetch failed"
            return None, "snapshot", redact(str(exc))
    finally:
        client.close()
    if response.status in (401, 403):
        warning = _blocked(response.status)
        _note_block(warning)
        if fallback:
            cached, _state = _cached(url)
            if cached is not None:
                return cached, "stale", warning
        return None, "snapshot", warning
    if response.status == 429:
        retry = response.headers.get("retry-after", "")
        message = "upstream status 429"
        if retry:
            message = f"upstream status 429, retry after {retry}"
        if fallback:
            cached, _state = _cached(url)
            if cached is not None:
                return cached, "stale", message
        return None, "snapshot", message
    if response.status >= 400:
        return None, "snapshot", f"upstream status {response.status}"
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return None, response.cache, "Scamwatch page was not UTF-8"
    _note_block("")
    warning = ""
    if response.cache == "stale":
        warning = "served from cache after the live fetch failed"
    return text, response.cache, warning


def _block_path() -> Path:
    return _data_dir() / "blocked.json"


def _note_block(warning: str) -> None:
    """Remember a 401 or 403 so a repeat call inside the poll budget still says blocked.

    The block is per host: a refusal for one page means the next page is refused too.
    """
    path = _block_path()
    if warning:
        mark = {"at": time.time(), "warning": warning}
        path.write_text(json.dumps(mark), encoding="utf-8")
    else:
        path.unlink(missing_ok=True)


def _recent_block() -> str:
    try:
        mark = json.loads(_block_path().read_text(encoding="utf-8"))
        if time.time() - float(mark["at"]) < TTL:
            return str(mark["warning"])
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return ""


def _client() -> HttpClient:
    data_dir = _data_dir()
    return HttpClient(
        "scamwatch",
        policy=EgressPolicy(_allowlist(), "scamwatch"),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", sleeper=_SLEEP),
        user_agent=USER_AGENT,
        rate=1.0,
        burst=4,
        window="rolling",
        timeout=30,
        retries=1,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
        rng=_rng,
    )


def _take_budget() -> str:
    limiter = RateLimiter(_data_dir() / "rate_limit.sqlite", sleeper=_SLEEP)
    try:
        limiter.acquire(
            "scamwatch:budget",
            rate=1 / TTL,
            burst=1,
            window="rolling",
            timeout=0,
        )
    except RateLimited:
        return "rate limit: one Scamwatch request every 6 hours"
    return ""


class _HomeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.saw_section = False
        self.alerts: list[dict] = []
        self._skip = 0
        self._section = False
        self._done = False
        self._heading = ""
        self._buf: list[str] = []
        self._in_a = False
        self._href = ""
        self._a_buf: list[str] = []
        self._in_time = False
        self._time_dt = ""
        self._time_buf: list[str] = []
        self._in_p = False
        self._p_buf: list[str] = []
        self._current: dict | None = None
        self._pending_date = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {key.lower(): value or "" for key, value in attrs}
        if tag in {"script", "style", "noscript"}:
            self._skip += 1
            return
        if self._skip or self._done:
            return
        if tag in {"h1", "h2", "h3"}:
            self._heading = tag
            self._buf = []
        if tag == "a":
            self._in_a = True
            self._href = attr.get("href", "")
            self._a_buf = []
        if tag == "time":
            self._in_time = True
            self._time_dt = attr.get("datetime", "")
            self._time_buf = []
        if tag == "p":
            self._in_p = True
            self._p_buf = []

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._skip:
            self._skip -= 1
            return
        if self._skip:
            return
        if tag == self._heading:
            text = _plain("".join(self._buf))
            if tag == "h2" and text.casefold().startswith("news and alerts"):
                self._section = True
                self.saw_section = True
            elif tag == "h2" and self._section:
                self._finish()
                self._section = False
                self._done = True
            self._heading = ""
        if tag == "a" and self._in_a:
            href = self._href
            label = _plain("".join(self._a_buf))
            self._in_a = False
            self._take_link(href, label)
        if tag == "time" and self._in_time:
            shown = _plain("".join(self._time_buf))
            self._note_date(self._time_dt or shown)
            self._in_time = False
        if tag == "p" and self._in_p:
            text = _plain("".join(self._p_buf))
            current = self._current
            if self._section and current is not None and text and not current["summary"]:
                current["summary"] = text
            self._in_p = False

    def handle_data(self, data: str) -> None:
        if self._skip or self._done:
            return
        if self._heading:
            self._buf.append(data)
        if self._in_a:
            self._a_buf.append(data)
        if self._in_time:
            self._time_buf.append(data)
        if self._in_p:
            self._p_buf.append(data)
        stripped = data.strip()
        if stripped and not self._in_time and _DATE_ONLY.fullmatch(stripped):
            self._note_date(stripped)

    def close(self) -> None:
        super().close()
        self._finish()

    def _take_link(self, href: str, label: str) -> None:
        if not self._section or self._done:
            return
        if _is_index(href) or label.casefold().startswith("view all"):
            self._finish()
            self._section = False
            self._done = True
            return
        slug = _alert_slug(href)
        if not slug:
            return
        self._finish()
        self._current = {
            "title": label,
            "url": _canonical(href),
            "date": self._pending_date,
            "summary": "",
            "body": "",
        }
        self._pending_date = ""

    def _note_date(self, raw: str) -> None:
        if not self._section or self._done:
            return
        parsed = _normalise_date(raw)
        if not parsed:
            return
        if self._current is None or (self._current["title"] and self._current["date"]):
            self._pending_date = parsed
        elif not self._current["date"]:
            self._current["date"] = parsed

    def _finish(self) -> None:
        current = self._current
        self._current = None
        if not current:
            return
        title = _plain(str(current.get("title") or ""))
        url = str(current.get("url") or "")
        if not title or not url:
            return
        current["title"] = title
        current["summary"] = _plain(str(current.get("summary") or ""))
        current["date"] = _plain(str(current.get("date") or ""))
        self.alerts.append(current)


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.date = ""
        self.headings: list[str] = []
        self.parts: list[str] = []
        self._skip = 0
        self._heading = ""
        self._buf: list[str] = []
        self._in_time = False
        self._time_dt = ""
        self._time_buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {key.lower(): value or "" for key, value in attrs}
        if tag in {"script", "style", "noscript", "nav", "footer", "form"}:
            self._skip += 1
            return
        if self._skip:
            return
        if tag in {"h1", "h2", "h3"}:
            self._heading = tag
            self._buf = []
        if tag == "time":
            self._in_time = True
            self._time_dt = attr.get("datetime", "")
            self._time_buf = []

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "nav", "footer", "form"} and self._skip:
            self._skip -= 1
            return
        if self._skip:
            return
        if tag == self._heading:
            text = _plain("".join(self._buf))
            if tag == "h1" and text and not self.title:
                self.title = text
            elif tag in {"h2", "h3"} and text:
                self.headings.append(text)
            self._heading = ""
        if tag == "time" and self._in_time:
            shown = _plain("".join(self._time_buf))
            parsed = _normalise_date(self._time_dt or shown)
            if parsed and not self.date:
                self.date = parsed
            self._in_time = False

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._heading:
            self._buf.append(data)
        if self._in_time:
            self._time_buf.append(data)
        text = data.strip()
        if not text:
            return
        self.parts.append(text)
        if not self.date and _DATE_ONLY.fullmatch(text):
            parsed = _normalise_date(text)
            if parsed:
                self.date = parsed


def _parse_home(html: str) -> _ParsedHome:
    parser = _HomeParser()
    parser.feed(html)
    parser.close()
    return _ParsedHome(parser.saw_section, parser.alerts)


def _parse_page(html: str, url: str) -> dict:
    parser = _PageParser()
    parser.feed(html)
    parser.close()
    return {
        "title": parser.title,
        "url": url,
        "date": parser.date,
        "summary": "",
        "body": _plain(" ".join(parser.parts)),
        "headings": parser.headings,
    }


def _persist(rows: list[dict], *, body: str) -> None:
    if not rows:
        return
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path = _data_dir() / "scamwatch-alerts.jsonl"
    with _db() as conn:
        for row in rows:
            url = str(row.get("url") or "")
            if not url:
                continue
            existing = conn.execute(
                "SELECT content_hash, title, published, summary, body FROM alerts WHERE id = ?",
                (_alert_id(url),),
            ).fetchone()
            # The homepage has no body and an alert page has no summary. Keep what the
            # other source stored so each read does not blank the other's fields.
            old = existing or {"title": "", "published": "", "summary": "", "body": ""}
            title = _plain(str(row.get("title") or "")) or old["title"]
            published = _plain(str(row.get("date") or "")) or old["published"]
            summary = _plain(str(row.get("summary") or "")) or old["summary"]
            kept_body = _plain(body or str(row.get("body") or "")) or old["body"]
            digest = hashlib.sha256(
                "\n".join((title, published, summary, kept_body)).encode()
            ).hexdigest()
            changed = existing is None or existing["content_hash"] != digest
            conn.execute(
                """
                INSERT INTO alerts (
                    id, url, title, published, summary, body, content_hash, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title,
                    published=excluded.published,
                    summary=excluded.summary,
                    body=excluded.body,
                    content_hash=excluded.content_hash,
                    last_seen=excluded.last_seen
                """,
                (
                    _alert_id(url),
                    url,
                    title,
                    published,
                    summary,
                    kept_body,
                    digest,
                    now,
                    now,
                ),
            )
            if changed:
                record = {
                    "id": _alert_id(url),
                    "url": url,
                    "title": title,
                    "date": published,
                    "summary": summary,
                    "body": kept_body,
                    "seen": now,
                }
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")


def _stored_body(url: str) -> str:
    if not (_data_dir() / "scamwatch.sqlite").exists():
        return ""
    with _db() as conn:
        row = conn.execute(
            "SELECT body FROM alerts WHERE url = ?",
            (url,),
        ).fetchone()
    if row is None:
        return ""
    return str(row["body"] or "")


@contextmanager
def _db() -> Iterator[sqlite3.Connection]:
    path = _data_dir() / "scamwatch.sqlite"
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                title TEXT NOT NULL,
                published TEXT NOT NULL,
                summary TEXT NOT NULL,
                body TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        yield conn
        conn.commit()
    finally:
        conn.close()


def _public_alert(item: dict) -> dict:
    return {
        "title": untrusted_text(str(item.get("title") or ""), "scamwatch"),
        "date": str(item.get("date") or ""),
        "url": str(item.get("url") or ""),
        "summary": untrusted_text(str(item.get("summary") or ""), "scamwatch"),
    }


def _public_page(page: dict) -> dict:
    return {
        "url": page["url"],
        "title": untrusted_text(page["title"], "scamwatch"),
        "date": page["date"],
        "body": untrusted_text(page["body"], "scamwatch"),
        "headings": [untrusted_text(item, "scamwatch") for item in page["headings"]],
    }


def _envelope(
    data,
    cache: str,
    *,
    warnings: tuple[str, ...] = (),
    urls: tuple[str, ...] | None = None,
    as_of: str | None = None,
) -> dict:
    return envelope(
        "scamwatch",
        data,
        urls=[HOME] if urls is None else list(urls),
        cache=cache,
        data_as_of=as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _cached(url: str) -> tuple[str | None, str]:
    cache = HttpCache(_data_dir() / "http_cache.sqlite")
    item = cache.get(cache.key("GET", url, None, b"", "anonymous"))
    if item is None or item.status >= 400:
        return None, "snapshot"
    try:
        text = item.body.decode("utf-8")
    except UnicodeDecodeError:
        return None, "snapshot"
    return text, "hit" if cache.fresh(item) else "stale"


def _snapshot_text() -> str:
    override = os.environ.get("CYBERAU_SCAMWATCH_SNAPSHOT")
    path = Path(override) if override else _PACKAGE / "data" / "homepage.html"
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _shipped_home() -> str:
    path = _PACKAGE / "data" / "homepage.html"
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _mapped_page(url: str) -> str | None:
    root = os.environ.get("CYBERAU_SCAMWATCH_PAGES")
    if not root:
        return None
    slug = urlsplit(url).path.rstrip("/").split("/")[-1]
    if not slug:
        return None
    path = Path(root) / f"{slug}.html"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _check_limit(limit: int) -> str:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        return "limit must be an integer from 1 to 50"
    return ""


def _check_url(url: str) -> str:
    if not url or _URL.match(url) is None:
        return "url must be an https://www.scamwatch.gov.au/ address"
    parts = urlsplit(url)
    if parts.username or parts.password:
        return "url must not contain userinfo"
    return ""


def _blocked(status: int) -> str:
    return (
        f"blocked: www.scamwatch.gov.au returned {status}. "
        "This is not an empty alert list. "
        "Scamwatch does not use an access key from the environment."
    )


def _blocked_page() -> str:
    return "blocked: Scamwatch returned an access denied page. This is not an empty alert list."


def _looks_blocked(html: str) -> bool:
    lowered = html.casefold()
    if "news and alerts" in lowered:
        return False
    return "access denied" in lowered


def _unavailable(warning: str) -> str:
    if warning:
        return warning
    return "unavailable: Scamwatch could not be fetched"


def _join(left: str, right: str) -> str:
    if left and right:
        return f"{left} {right}"
    return left or right


def _newest(rows: list[dict]) -> str | None:
    dates = [str(row.get("date") or "") for row in rows if row.get("date")]
    return max(dates) if dates else None


def _plain(value: str) -> str:
    cleaned = _BIDI.sub("", _CONTROL.sub("", value))
    return _WS.sub(" ", cleaned).strip()


def _normalise_date(value: str) -> str:
    text = _plain(value)
    iso = re.match(r"(\d{4})-(\d{2})-(\d{2})", text)
    if iso:
        year, month, day = (int(iso.group(index)) for index in (1, 2, 3))
        if 1 <= month <= 12 and 1 <= day <= 31:
            return f"{year:04d}-{month:02d}-{day:02d}"
        return ""
    named = re.match(r"(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})", text)
    if not named:
        return ""
    month = _MONTHS.get(named.group(2).casefold())
    if not month:
        return ""
    day = int(named.group(1))
    year = int(named.group(3))
    if not 1 <= day <= 31:
        return ""
    return f"{year:04d}-{month:02d}-{day:02d}"


def _alert_slug(href: str) -> str:
    if not href or href.startswith(("#", "mailto:", "javascript:")):
        return ""
    parts = urlsplit(urljoin(HOME, href))
    if parts.netloc and parts.netloc != "www.scamwatch.gov.au":
        return ""
    path = parts.path.rstrip("/")
    if not path.startswith(_ALERT_PREFIX):
        return ""
    slug = path[len(_ALERT_PREFIX) :]
    if not slug or "/" in slug or slug == "browse-news-and-alerts":
        return ""
    return slug


def _is_index(href: str) -> bool:
    if not href:
        return False
    parts = urlsplit(urljoin(HOME, href))
    return parts.path.rstrip("/") == "/about-us/news-and-alerts"


def _canonical(href: str) -> str:
    parts = urlsplit(urljoin(HOME, href))
    return parts._replace(scheme="https", fragment="").geturl()


def _alert_id(url: str) -> str:
    digest = hashlib.sha1(url.encode()).hexdigest()
    return f"scamwatch:{digest}"


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-scamwatch"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _allowlist() -> Path:
    override = os.environ.get("CYBERAU_EGRESS_ALLOWLIST")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("scamwatch", connector)
