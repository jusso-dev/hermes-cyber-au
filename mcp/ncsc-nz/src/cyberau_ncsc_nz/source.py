"""Read-only NCSC NZ alerts (formerly CERT NZ)."""

import hashlib
import json
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Annotated
from urllib.parse import urljoin, urlsplit
from zoneinfo import ZoneInfo

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

LIST_URL = "https://www.ncsc.govt.nz/alerts/"
ATTRIBUTION = (
    "NCSC NZ alerts (formerly CERT NZ). Licence not confirmed. "
    "Quote short passages only. This connector is not endorsed by the NCSC."
)
_PACKAGE = Path(__file__).resolve().parents[2]
_SYDNEY = ZoneInfo("Australia/Sydney")
_AUCKLAND = ZoneInfo("Pacific/Auckland")
_LIST_TTL = 3600
_ITEM_TTL = 7 * 86400
_STALE_IF_ERROR = 7 * 86400
_PASSAGE_LIMIT = 500
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ALERT_PATH = re.compile(r"^/alerts/[^/]+/?$")
_WHEN = re.compile(
    r"(?:(\d{1,2}):(\d{2})\s*(am|pm)\s*,\s*)?(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})",
    re.IGNORECASE,
)
_MONTHS = {
    name: index
    for index, name in enumerate(
        (
            "january",
            "february",
            "march",
            "april",
            "may",
            "june",
            "july",
            "august",
            "september",
            "october",
            "november",
            "december",
        ),
        start=1,
    )
}
_VOID = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "source",
    "track",
    "wbr",
}
_HTML = {
    "user-agent": USER_AGENT,
    "accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "accept-language": "en-AU,en;q=0.9",
}
_Date = Annotated[
    str,
    Field(
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="YYYY-MM-DD, interpreted in Australia/Sydney",
    ),
]
_Limit = Annotated[int, Field(ge=1, le=100)]
_Url = Annotated[str, Field(pattern=r"^https://www\.ncsc\.govt\.nz/")]
_TRANSPORT = None
_RESOLVER = None
_SLEEP = time.sleep


def ncscnz_list_alerts(since: _Date | None = None, limit: _Limit = 20) -> dict:
    problem = _validate_list(since, limit)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    text, cache, warning = _fetch_list(force_live=False)
    if text is None:
        return _envelope(
            [],
            cache,
            [LIST_URL],
            warnings=_warnings(warning or "NCSC NZ alerts are unavailable"),
        )
    items = _dedupe(_parse_list(text))
    _persist_alerts(items)
    rows = []
    for item in items:
        if since and (not item["published"] or item["published"] < since):
            continue
        rows.append(item)
    rows.sort(key=lambda row: row["published"] or "", reverse=True)
    warnings = list(_warnings(warning))
    if not rows and not warnings:
        warnings.append("no NCSC NZ alerts matched")
    newest = rows[0]["published"] if rows and rows[0]["published"] else None
    public = [_public_alert(row) for row in rows[:limit]]
    return _envelope(public, cache, [LIST_URL], newest, tuple(warnings))


def ncscnz_get_alert(url: _Url) -> dict:
    page_url = _allowed_page(url) if isinstance(url, str) else ""
    if not page_url:
        return _envelope(
            None,
            "snapshot",
            warnings=("url must be an https://www.ncsc.govt.nz/ page",),
        )
    parsed, cache, warning = _fetch_item(page_url)
    if parsed is None:
        return _envelope(
            None,
            cache,
            [page_url],
            warnings=_warnings(warning or "NCSC NZ alert page was not usable"),
        )
    published = parsed["published"] or None
    return _envelope(
        _public_page(parsed),
        cache,
        [page_url],
        published,
        _warnings(warning),
    )


def connector() -> Connector:
    return _NcscConnector()


class _NcscConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="ncsc-nz",
            server_name="ncscnz",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "ncscnz_list_alerts",
                    "Recent NCSC NZ alerts with title, date and link.",
                    ncscnz_list_alerts,
                ),
                ToolSpec(
                    "ncscnz_get_alert",
                    "One NCSC NZ alert as cleaned text with extracted CVEs.",
                    ncscnz_get_alert,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            text = _read_list_snapshot()
            problem = schema_drift(text or "")
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        text, _cache, warning = _fetch_list(force_live=True)
        if warning or not text:
            return Probe(self.key, False, warning or "NCSC NZ alerts are unavailable")
        problem = schema_drift(text)
        if problem:
            return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def schema_drift(text: str) -> str | None:
    """Return a drift message when the alerts list selectors are missing."""
    if not text or not text.strip():
        return "NCSC NZ alert list is empty"
    has_card = "card--alert" in text
    if "explore--alert" not in text and not has_card:
        return "NCSC NZ schema drift, missing alert list"
    if not has_card:
        return None
    if "card__title" not in text:
        return "NCSC NZ schema drift, missing card__title"
    if "card__link" not in text:
        return "NCSC NZ schema drift, missing card__link"
    if "card__date" not in text:
        return "NCSC NZ schema drift, missing card__date"
    return None


def _validate_list(since: str | None, limit: int) -> str:
    if since and not _DATE.fullmatch(since):
        return "since must be YYYY-MM-DD"
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        return "limit must be between 1 and 100"
    return ""


def _fetch_list(*, force_live: bool) -> tuple[str | None, str, str]:
    pinned = bool(os.environ.get("CYBERAU_NCSC_SNAPSHOT")) and not force_live
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if pinned:
        return _pinned_list()
    cached = None if force_live else _cached_body(LIST_URL)
    if offline:
        if cached is not None:
            return cached[0], "stale", "served from the HTTP cache"
        return _pinned_list()
    if cached is not None and cached[1]:
        return cached[0], "hit", ""
    try:
        _limit("ncscnz:list", rate=1 / 3600, burst=1)
    except Exception as exc:
        return _fallback_list(redact(str(exc)) or "list rate limit not available")
    text, warning, cache = _http(LIST_URL, ttl=_LIST_TTL, skip_cache=force_live)
    if text is None:
        if _is_auth(warning):
            return None, "snapshot", warning
        return _fallback_list(warning or "list fetch failed")
    problem = schema_drift(text)
    if problem:
        if force_live:
            return None, "snapshot", problem
        return _fallback_list(problem)
    if warning and cache != "stale":
        cache = "stale"
    return text, cache, warning


def _pinned_list() -> tuple[str | None, str, str]:
    text = _read_list_snapshot()
    if text is None:
        return None, "snapshot", "NCSC NZ alerts are unavailable"
    problem = schema_drift(text)
    if problem:
        return None, "snapshot", problem
    return text, "snapshot", ""


def _fallback_list(warning: str) -> tuple[str | None, str, str]:
    cached = _cached_body(LIST_URL)
    if cached is not None:
        note = warning or "served from the HTTP cache"
        return cached[0], "stale", note
    text = _read_list_snapshot()
    if text and not schema_drift(text):
        note = f"{warning}; served shipped snapshot" if warning else ""
        return text, "snapshot", note
    if not warning:
        warning = "NCSC NZ alerts are unavailable"
    return None, "snapshot", warning


def _fetch_item(url: str) -> tuple[dict | None, str, str]:
    pinned = bool(os.environ.get("CYBERAU_NCSC_SNAPSHOT"))
    offline = os.environ.get("CYBERAU_OFFLINE") == "1"
    if pinned or offline:
        mapped = _mapped_html(url)
        if mapped is not None:
            return _parse_item(mapped, url), "snapshot", ""
        if not pinned:
            cached = _cached_body(url)
            if cached is not None:
                return _parse_item(cached[0], url), "stale", "served from the HTTP cache"
        stored = _stored(url)
        if stored is not None:
            return stored, "stale", "served from the stored alert"
        return None, "snapshot", "NCSC NZ alert page is unavailable"
    try:
        _limit("ncscnz:item", rate=1 / 5, burst=1)
    except Exception as exc:
        stored = _stored(url)
        if stored is not None:
            return stored, "stale", redact(str(exc))
        return None, "snapshot", redact(str(exc))
    text, warning, cache = _http(url, ttl=_ITEM_TTL, skip_cache=False)
    if text is None:
        if _is_auth(warning):
            return None, "snapshot", warning
        stored = _stored(url)
        if stored is not None:
            return stored, "stale", warning or "item fetch failed"
        mapped = _mapped_html(url)
        if mapped is not None:
            note = warning or ""
            return _parse_item(mapped, url), "snapshot", note
        return None, "snapshot", warning or "NCSC NZ alert page is unavailable"
    parsed = _parse_item(text, url)
    if not parsed["title"] and not parsed["passage"]:
        return None, cache if cache == "stale" else "snapshot", "NCSC NZ alert page was not usable"
    _save_item(parsed)
    if warning and cache != "stale":
        cache = "stale"
    return parsed, cache, warning


def _http(url: str, *, ttl: int, skip_cache: bool) -> tuple[str | None, str, str]:
    data_dir = _data_dir()
    kwargs = {}
    if _RESOLVER is not None:
        kwargs["resolver"] = _RESOLVER
    client = HttpClient(
        "ncsc-nz",
        policy=EgressPolicy(_allowlist(), "ncsc-nz", **kwargs),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", sleeper=_SLEEP),
        user_agent=USER_AGENT,
        rate=4,
        burst=20,
        window="rolling",
        timeout=30,
        retries=3,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
    )
    try:
        response = client.get(
            url,
            headers=_HTML,
            ttl=ttl,
            stale_if_error=_STALE_IF_ERROR,
            skip_cache=skip_cache,
        )
    except Exception as exc:
        return None, redact(str(exc)), "snapshot"
    finally:
        client.close()
    if response.status in (401, 403):
        return None, _auth_message(response.status), "snapshot"
    if response.status >= 400:
        return None, f"upstream status {response.status}", "snapshot"
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return None, "NCSC NZ page was not UTF-8", response.cache
    warning = ""
    if response.cache == "stale":
        warning = "served from cache after the live fetch failed"
    return text, warning, response.cache


def _auth_message(status: int) -> str:
    return (
        f"upstream status {status}; NCSC NZ alerts are public and this connector "
        "reads no credential env var"
    )


def _is_auth(warning: str) -> bool:
    return warning.startswith("upstream status 401") or warning.startswith("upstream status 403")


def _parse_list(text: str) -> list[dict]:
    parser = _ListParser()
    parser.feed(text)
    parser.close()
    return parser.items


def _parse_item(text: str, url: str) -> dict:
    parser = _ItemParser()
    parser.feed(text)
    parser.close()
    title = _collapse(" ".join(parser.title_parts)) or _collapse(" ".join(parser.alt_parts))
    intro = _collapse(" ".join(parser.intro_parts))
    summary = _collapse(" ".join(parser.summary_parts))
    passage = intro or summary
    if len(passage) > _PASSAGE_LIMIT:
        passage = passage[:_PASSAGE_LIMIT]
    published = _parse_when(_collapse(" ".join(parser.date_parts)))
    haystack = " ".join(part for part in (title, intro, summary) if part)
    return {
        "url": url,
        "title": title,
        "published": published,
        "passage": passage,
        "cves": _ids(haystack),
    }


class _ListParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.items: list[dict] = []
        self._href = ""
        self._card_href = ""
        self._in_card = 0
        self._title = 0
        self._date = 0
        self._title_parts: list[str] = []
        self._date_parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if self._skip:
            if tag in {"script", "style"}:
                self._skip += 1
            return
        if tag in {"script", "style"}:
            self._skip += 1
            return
        classes = _class_set(attrs)
        if tag == "a" and "card__link" in classes:
            self._href = _attr(attrs, "href")
            if self._in_card:
                self._card_href = self._href
        if tag in _VOID:
            return
        if tag == "article" and "card--alert" in classes and self._in_card == 0:
            self._in_card = 1
            self._card_href = self._href
            self._title_parts = []
            self._date_parts = []
        elif self._in_card:
            self._in_card += 1
        if tag == "h3" and "card__title" in classes:
            self._title = 1 if self._title == 0 else self._title + 1
        elif self._title:
            self._title += 1
        if tag == "p" and "card__date" in classes:
            self._date = 1 if self._date == 0 else self._date + 1
        elif self._date:
            self._date += 1

    def handle_endtag(self, tag):
        if self._skip:
            if tag in {"script", "style"}:
                self._skip -= 1
            return
        if tag in _VOID:
            return
        if self._title:
            self._title -= 1
        if self._date:
            self._date -= 1
        if self._in_card:
            self._in_card -= 1
            if self._in_card == 0:
                self._finish()

    def handle_data(self, data):
        if self._skip or not data.strip():
            return
        text = data.strip()
        if self._title:
            self._title_parts.append(text)
        if self._date:
            self._date_parts.append(text)

    def _finish(self) -> None:
        link = _canonical(self._card_href)
        self._href = ""
        self._card_href = ""
        title = _collapse(" ".join(self._title_parts))
        if not link or not title:
            return
        published = _parse_when(_collapse(" ".join(self._date_parts)))
        self.items.append(
            {
                "link": link,
                "title": title,
                "published": published,
                "cves": _ids(title),
            }
        )


class _ItemParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title_parts: list[str] = []
        self.alt_parts: list[str] = []
        self.date_parts: list[str] = []
        self.intro_parts: list[str] = []
        self.summary_parts: list[str] = []
        self._skip = 0
        self._title = 0
        self._alt = 0
        self._date = 0
        self._intro = 0
        self._summary = 0

    def handle_starttag(self, tag, attrs):
        if self._skip:
            if tag in {"script", "style"}:
                self._skip += 1
            return
        if tag in {"script", "style"}:
            self._skip += 1
            return
        if tag in _VOID:
            return
        classes = _class_set(attrs)
        if "content-intro__title--eng" in classes or (
            tag == "h1" and "content-intro__title" in classes
        ):
            self._title = 1 if self._title == 0 else self._title + 1
        elif self._title:
            self._title += 1
        if tag == "h2" and "advisory-page-title" in classes:
            self._alt = 1 if self._alt == 0 else self._alt + 1
        elif self._alt:
            self._alt += 1
        if "content__detail--date" in classes:
            self._date = 1 if self._date == 0 else self._date + 1
        elif self._date:
            self._date += 1
        if "advisory-page-intro" in classes:
            self._intro = 1 if self._intro == 0 else self._intro + 1
        elif self._intro:
            self._intro += 1
        if "advisory-summary" in classes:
            self._summary = 1 if self._summary == 0 else self._summary + 1
        elif self._summary:
            self._summary += 1

    def handle_endtag(self, tag):
        if self._skip:
            if tag in {"script", "style"}:
                self._skip -= 1
            return
        if tag in _VOID:
            return
        if self._title:
            self._title -= 1
        if self._alt:
            self._alt -= 1
        if self._date:
            self._date -= 1
        if self._intro:
            self._intro -= 1
        if self._summary:
            self._summary -= 1

    def handle_data(self, data):
        if self._skip or not data.strip():
            return
        text = data.strip()
        if self._title:
            self.title_parts.append(text)
        if self._alt:
            self.alt_parts.append(text)
        if self._date:
            self.date_parts.append(text)
        if self._intro:
            self.intro_parts.append(text)
        if self._summary:
            self.summary_parts.append(text)


def _dedupe(items: list[dict]) -> list[dict]:
    chosen: dict[str, dict] = {}
    order: list[str] = []
    for item in items:
        link = item["link"]
        current = chosen.get(link)
        if current is None:
            chosen[link] = item
            order.append(link)
            continue
        if _prefer_new(item, current):
            chosen[link] = item
    return [chosen[link] for link in order]


def _prefer_new(new: dict, old: dict) -> bool:
    if new["published"] and old["published"] and new["published"] != old["published"]:
        return new["published"] > old["published"]
    return _is_updated(new["title"]) and not _is_updated(old["title"])


def _is_updated(title: str) -> bool:
    return title.lstrip().upper().startswith("UPDATED:")


def _persist_alerts(items: list[dict]) -> None:
    now = datetime.now(_SYDNEY).strftime("%Y-%m-%dT%H:%M:%S%z")
    with _db() as conn:
        for item in items:
            known = conn.execute(
                "SELECT cves FROM alerts WHERE link = ?", (item["link"],)
            ).fetchone()
            cves = set(item["cves"])
            if known is not None:
                cves |= set(json.loads(known["cves"] or "[]"))
            conn.execute(
                """
                INSERT INTO alerts (id, link, title, published, cves, passage, fetched_at)
                VALUES (?, ?, ?, ?, ?, '', ?)
                ON CONFLICT(link) DO UPDATE SET
                    title=excluded.title,
                    published=CASE WHEN excluded.published = '' THEN alerts.published
                         ELSE excluded.published END,
                    cves=excluded.cves,
                    fetched_at=excluded.fetched_at
                """,
                (
                    _item_id(item["link"]),
                    item["link"],
                    item["title"],
                    item["published"],
                    json.dumps(sorted(cves)),
                    now,
                ),
            )


def _save_item(page: dict) -> None:
    now = datetime.now(_SYDNEY).strftime("%Y-%m-%dT%H:%M:%S%z")
    with _db() as conn:
        conn.execute(
            """
            INSERT INTO alerts (id, link, title, published, cves, passage, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(link) DO UPDATE SET
                title=CASE WHEN excluded.title = '' THEN alerts.title ELSE excluded.title END,
                published=CASE WHEN excluded.published = '' THEN alerts.published
                     ELSE excluded.published END,
                cves=excluded.cves,
                passage=CASE WHEN excluded.passage = '' THEN alerts.passage
                     ELSE excluded.passage END,
                fetched_at=excluded.fetched_at
            """,
            (
                _item_id(page["url"]),
                page["url"],
                page["title"],
                page["published"],
                json.dumps(page["cves"]),
                page["passage"],
                now,
            ),
        )


def _stored(url: str) -> dict | None:
    with _db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE link = ?", (url,)).fetchone()
    if row is None:
        return None
    return {
        "url": row["link"],
        "title": row["title"],
        "published": row["published"] or "",
        "passage": row["passage"] or "",
        "cves": json.loads(row["cves"] or "[]"),
    }


def _public_alert(item: dict) -> dict:
    return {
        "title": untrusted_text(item["title"], "ncscnz", max_len=300),
        "published": item["published"],
        "link": item["link"],
        "cves": item["cves"],
    }


def _public_page(page: dict) -> dict:
    return {
        "url": page["url"],
        "title": untrusted_text(page["title"], "ncscnz", max_len=300),
        "published": page["published"],
        "passage": untrusted_text(page["passage"], "ncscnz", max_len=_PASSAGE_LIMIT),
        "cves": page["cves"],
    }


def _read_list_snapshot() -> str | None:
    override = os.environ.get("CYBERAU_NCSC_SNAPSHOT")
    root = Path(override) if override else _PACKAGE / "data"
    path = root / "alerts_page.html"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _mapped_html(url: str) -> str | None:
    wanted = _allowed_page(url)
    if not wanted:
        return None
    override = os.environ.get("CYBERAU_NCSC_SNAPSHOT")
    roots = [Path(override)] if override else []
    roots.append(_PACKAGE / "data")
    for root in roots:
        index = root / "items.json"
        if not index.is_file():
            continue
        mapping = json.loads(index.read_text(encoding="utf-8"))
        for key, name in mapping.items():
            if _allowed_page(str(key)) != wanted:
                continue
            page = root / str(name)
            if page.is_file():
                return page.read_text(encoding="utf-8")
    return None


def _cached_body(url: str) -> tuple[str, bool] | None:
    cache = HttpCache(_data_dir() / "http_cache.sqlite")
    key = cache.key("GET", url, None, b"", "anonymous")
    item = cache.get(key)
    if item is None:
        return None
    try:
        text = item.body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text, cache.fresh(item)


def _canonical(url: str) -> str:
    absolute = urljoin("https://www.ncsc.govt.nz/", url.strip())
    parts = urlsplit(absolute)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or host != "www.ncsc.govt.nz":
        return ""
    path = parts.path or "/"
    if not _ALERT_PATH.match(path):
        return ""
    if not path.endswith("/"):
        path += "/"
    return f"https://www.ncsc.govt.nz{path}"


def _allowed_page(url: str) -> str:
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or host != "www.ncsc.govt.nz":
        return ""
    path = parts.path or "/"
    if not path.startswith("/"):
        return ""
    if _ALERT_PATH.match(path) and not path.endswith("/"):
        path += "/"
    return f"https://www.ncsc.govt.nz{path}"


def _parse_when(value: str) -> str:
    if not value:
        return ""
    match = _WHEN.search(value)
    if match is None:
        return ""
    month = _MONTHS.get(match.group(5).lower())
    if month is None:
        return ""
    day = int(match.group(4))
    year = int(match.group(6))
    try:
        if match.group(1) is None:
            return datetime(year, month, day).date().isoformat()
        hour = int(match.group(1))
        minute = int(match.group(2))
        if not 1 <= hour <= 12 or not 0 <= minute <= 59:
            return ""
        marker = match.group(3).lower()
        if marker == "pm" and hour != 12:
            hour += 12
        if marker == "am" and hour == 12:
            hour = 0
        when = datetime(year, month, day, hour, minute, tzinfo=_AUCKLAND)
    except ValueError:
        return ""
    return when.astimezone(_SYDNEY).date().isoformat()


def _ids(text: str) -> list[str]:
    return sorted(set(_CVE.findall(text)))


def _collapse(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("\xa0", " ")).strip()


def _class_set(attrs) -> set[str]:
    for key, value in attrs:
        if key.lower() == "class" and value:
            return set(value.split())
    return set()


def _attr(attrs, name: str) -> str:
    for key, value in attrs:
        if key.lower() == name:
            return value or ""
    return ""


def _item_id(link: str) -> str:
    return "ncscnz:" + hashlib.sha1(link.encode()).hexdigest()


def _limit(key: str, *, rate: float, burst: int) -> None:
    RateLimiter(_data_dir() / "rate_limit.sqlite", sleeper=_SLEEP).acquire(
        key,
        rate=rate,
        burst=burst,
        window="rolling",
        timeout=60,
    )


def _warnings(*items: str) -> tuple[str, ...]:
    return tuple(item for item in items if item)


def _envelope(
    data,
    cache: str,
    urls: list[str] | None = None,
    data_as_of: str | None = None,
    warnings=(),
):
    return envelope(
        "ncsc-nz",
        data,
        urls=urls or [],
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-ncsc-nz"))
    path.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def _db():
    conn = sqlite3.connect(_data_dir() / "ncsc_alerts.sqlite")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            link TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            published TEXT NOT NULL DEFAULT '',
            cves TEXT NOT NULL,
            passage TEXT NOT NULL DEFAULT '',
            fetched_at TEXT NOT NULL
        )
        """
    )
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _allowlist() -> Path:
    override = os.environ.get("CYBERAU_EGRESS_ALLOWLIST")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("ncsc-nz", connector)
