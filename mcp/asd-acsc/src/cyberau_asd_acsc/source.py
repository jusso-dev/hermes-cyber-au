"""Read-only ASD ACSC alerts, advisories and publications."""

import email.utils
import hashlib
import json
import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urljoin
from zoneinfo import ZoneInfo

from cyberau_common import GOV_AU_USER_AGENT as USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, safe_url, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable
from pydantic import Field

FEEDS = ("alerts", "advisories", "publications", "threats", "news")
_Feed = Literal["alerts", "advisories", "publications", "threats", "news"]
_Date = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]
_ListLimit = Annotated[int, Field(ge=1, le=100)]
_SearchLimit = Annotated[int, Field(ge=1, le=50)]
_Query = Annotated[str, Field(min_length=2)]
_Url = Annotated[str, Field(pattern=r"^https://www\.cyber\.gov\.au/")]
ATTRIBUTION = (
    "© Commonwealth of Australia 2026. Material from ASD's ACSC (cyber.gov.au), "
    "Creative Commons Attribution 4.0 International. "
    "Confirm the current licence at https://www.cyber.gov.au/about-us/copyright. "
    "This connector is not endorsed by ASD."
)
_OVERRIDE = "CYBERAU_ASD_SNAPSHOT"
_OVERRIDE_NOTE = (
    "served from the operator-supplied ASD snapshot files in CYBERAU_ASD_SNAPSHOT, not a live fetch"
)
_SYDNEY = ZoneInfo("Australia/Sydney")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_ATTACK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TRANSPORT = None
_SLEEP = time.sleep
_DIRECT = {
    "user-agent": USER_AGENT,
    "accept": "application/rss+xml, application/xml, text/xml, */*",
}
_BROWSER = {
    "user-agent": f"{USER_AGENT} (compatible; HTTP/1.1 fallback)",
    "accept": "application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.8",
    "accept-language": "en-AU,en;q=0.9",
    "connection": "close",
}


def asd_list_items(
    feeds: list[_Feed] | None = None,
    since: _Date | None = None,
    limit: _ListLimit = 20,
) -> dict:
    chosen, problem = _feeds(feeds)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    if since and not _DATE.fullmatch(since):
        return _envelope([], "snapshot", warnings=("since must be YYYY-MM-DD",))
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        return _envelope([], "snapshot", warnings=("limit must be between 1 and 100",))
    rows: list[dict] = []
    warnings: list[str] = []
    caches: list[str] = []
    urls: list[str] = []
    newest = ""
    for feed in chosen:
        items, cache, warning, _method = _items_for_feed(feed)
        urls.append(_feed_url(feed))
        caches.append(cache)
        if warning:
            warnings.append(warning)
        for item in items:
            if since and (not item["published"] or item["published"] < since):
                continue
            rows.append(_public(item))
            if item["published"] and item["published"] > newest:
                newest = item["published"]
    rows.sort(key=lambda row: row["published"] or "", reverse=True)
    if not rows and not warnings:
        warnings.append("no ASD items matched")
    if rows and os.environ.get(_OVERRIDE):
        warnings.append(_OVERRIDE_NOTE)
    return _envelope(rows[:limit], _merge_cache(caches), urls, newest or None, tuple(warnings))


def asd_get_item(url: _Url) -> dict:
    if not isinstance(url, str) or not url.startswith("https://www.cyber.gov.au/"):
        return _envelope(
            None,
            "snapshot",
            warnings=("url must be an https://www.cyber.gov.au/ page",),
        )
    page, cache, warning = _page(url)
    if page is None:
        return _envelope(
            None,
            cache,
            [url],
            warnings=(unavailable("ASD item page", warning or "the page was not usable"),),
        )
    warnings = (warning,) if warning else ()
    return _envelope(_public_page(url, page), cache, [url], warnings=warnings)


def asd_search(
    query: _Query,
    since: _Date | None = None,
    limit: _SearchLimit = 10,
) -> dict:
    if not isinstance(query, str) or len(query.strip()) < 2:
        return _envelope([], "snapshot", warnings=("query must be at least 2 characters",))
    if since and not _DATE.fullmatch(since):
        return _envelope([], "snapshot", warnings=("since must be YYYY-MM-DD",))
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        return _envelope([], "snapshot", warnings=("limit must be between 1 and 50",))
    _hydrate_override()
    needle = f"%{query.strip().lower()}%"
    with _db() as conn:
        found = conn.execute(
            """
            SELECT * FROM advisories
            WHERE (lower(title) LIKE ? OR lower(summary) LIKE ? OR lower(body) LIKE ?
                   OR lower(cves) LIKE ? OR lower(link) LIKE ?)
              AND (? IS NULL OR coalesce(published, '') >= ?)
            ORDER BY coalesce(published, '') DESC
            LIMIT ?
            """,
            (needle, needle, needle, needle, needle, since, since or "", limit),
        ).fetchall()
    if not found:
        if not _has_items():
            reason = "no ASD items have been stored from a live poll yet"
            return _envelope([], "snapshot", warnings=(unavailable("ASD search", reason),))
        return _envelope([], "snapshot", warnings=(f"no stored ASD items match {query!r}",))
    newest = ""
    rows = []
    for row in found:
        item = dict(row)
        rows.append(_public(item))
        if item["published"] and item["published"] > newest:
            newest = item["published"]
    warnings = (_OVERRIDE_NOTE,) if os.environ.get(_OVERRIDE) else ()
    return _envelope(rows, "snapshot", [_feed_url("alerts")], newest or None, warnings)


def asd_feed_status(feeds: list[_Feed] | None = None) -> dict:
    chosen, problem = _feeds(feeds if feeds is not None else list(FEEDS))
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    rows = []
    with _db() as conn:
        for feed in chosen:
            stored = conn.execute(
                "SELECT * FROM feed_status WHERE feed = ?",
                (feed,),
            ).fetchone()
            if stored is None:
                rows.append(
                    {
                        "feed": feed,
                        "last_success": None,
                        "method": "never",
                        "item_count": 0,
                        "stale": True,
                        "warning": f"{feed} has not been fetched",
                    }
                )
                continue
            rows.append(
                {
                    "feed": feed,
                    "last_success": stored["last_success"],
                    "method": stored["method"],
                    "item_count": stored["item_count"],
                    "stale": stored["method"] == "stale",
                    "warning": stored["warning"],
                }
            )
    return _envelope(rows, "snapshot")


def import_feed(path: str, feed: str = "alerts") -> str:
    chosen, problem = _feeds([feed])
    if problem:
        raise ValueError(problem)
    text = Path(path).read_text(encoding="utf-8")
    drift = schema_drift(text)
    if drift:
        raise ValueError(drift)
    items = _parse_feed(text, chosen[0])
    _persist(chosen[0], items, method="manual", warning="", cache="snapshot")
    return f"imported {len(items)} {chosen[0]} items"


def connector() -> Connector:
    return _AsdConnector()


class _AsdConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="asd-acsc",
            server_name="asd",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "asd_list_items",
                    "List ASD ACSC feed items, newest first.",
                    asd_list_items,
                ),
                ToolSpec("asd_get_item", "Fetch one ASD item page as cleaned text.", asd_get_item),
                ToolSpec("asd_search", "Search ASD items kept from earlier polls.", asd_search),
                ToolSpec(
                    "asd_feed_status",
                    "Last fetch method and staleness for ASD feeds.",
                    asd_feed_status,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            # Offline schema check: read the operator override or the HTTP cache,
            # never a file shipped in the package.
            text = _read_snapshot("alerts") or _cached_body(_feed_url("alerts"))
            if text is None:
                return Probe(self.key, True, "no local copy to check")
            problem = schema_drift(text)
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        _text, _cache, warning, _method = _fetch_xml("alerts", force_live=True)
        if warning:
            return Probe(self.key, False, warning)
        problem = schema_drift(_text or "")
        if problem:
            return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def _feed_problem(text: str) -> str | None:
    drift = schema_drift(text)
    if drift:
        return drift
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return "ASD feed is not XML"
    for node in root.iter():
        if _local(node.tag) != "item":
            continue
        for child in list(node):
            if _local(child.tag) not in {"pubDate", "date"}:
                continue
            raw = (child.text or "").strip()
            if raw and _parse_pubdate(raw) is None:
                return f"unusable pubDate {raw!r}"
    return None


def schema_drift(text: str) -> str | None:
    if not text or not text.strip():
        return "ASD feed is empty"
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return "ASD feed is not XML"
    if _local(root.tag) != "rss":
        return "ASD schema drift, missing rss"
    if not any(_local(child.tag) == "channel" for child in root):
        return "ASD schema drift, missing channel"
    return None


def _items_for_feed(feed: str) -> tuple[list[dict], str, str, str]:
    text, cache, warning, method = _fetch_xml(feed, force_live=False)
    if text is None and method in {"stored", "stale"} and _has_poll(feed):
        items = _latest_poll(feed)
        note = warning or f"{feed} served from the last stored poll"
        _persist(feed, items, method="stale", warning=note, cache="stale", replace=False)
        return items, "stale", note, "stale"
    if text is None:
        return [], cache, warning or f"{feed} is unavailable", method
    problem = _feed_problem(text)
    if problem:
        stored = _latest_poll(feed) if _has_poll(feed) else []
        if _has_poll(feed):
            note = f"{feed} fetch failed: {problem}"
            _persist(feed, stored, method="stale", warning=note, cache="stale", replace=False)
            return stored, "stale", note, "stale"
        return [], "snapshot", _unavailable(feed, problem), method
    items = _parse_feed(text, feed)
    note = warning
    if not items and not note:
        note = f"{feed} feed contained no items"
    _persist(
        feed,
        items,
        method=method,
        warning=note,
        cache=cache,
        replace=method in {"direct", "http11"},
    )
    return items, cache, note, method


def _fetch_xml(feed: str, *, force_live: bool) -> tuple[str | None, str, str, str]:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    pinned = bool(os.environ.get(_OVERRIDE)) and not force_live
    if pinned:
        return _pinned_snapshot(feed)
    if offline:
        return _offline_feed(feed)
    try:
        _limit(f"asd:feed:{feed}", rate=2 / 600, burst=2)
    except Exception as exc:
        if _has_poll(feed):
            return None, "stale", f"{feed} fetch skipped: {redact(str(exc))}", "stale"
        return None, "snapshot", _unavailable(feed, redact(str(exc))), "direct"
    direct = _http(_feed_url(feed), _DIRECT, ttl=15 * 60, skip_cache=force_live)
    accepted = _accept_feed(direct)
    if accepted is not None:
        return accepted[0], accepted[1], accepted[2], "direct"
    if force_live:
        message = _feed_failure(direct) or f"{feed} live fetch failed"
        return None, "snapshot", message, "direct"
    fallback = _http(_feed_url(feed), _BROWSER, ttl=15 * 60, skip_cache=True)
    accepted = _accept_feed(fallback)
    if accepted is not None:
        return accepted[0], accepted[1], accepted[2], "http11"
    message = _feed_failure(fallback) or _feed_failure(direct) or "fetch failed"
    if _has_poll(feed):
        return None, "stale", f"{feed} fetch failed: {message}", "stale"
    return None, "snapshot", _unavailable(feed, f"fetch failed: {message}"), "direct"


def _pinned_snapshot(feed: str) -> tuple[str | None, str, str, str]:
    text = _read_snapshot(feed)
    if text is None:
        return None, "snapshot", f"{feed} snapshot is missing", "snapshot"
    problem = _feed_problem(text)
    if problem:
        return None, "snapshot", problem, "snapshot"
    return text, "snapshot", "", "snapshot"


def _offline_feed(feed: str) -> tuple[str | None, str, str, str]:
    if _has_poll(feed):
        return None, "stale", f"{feed} served from the last stored poll", "stored"
    cached = _cached_feed(feed)
    if cached is not None and not _feed_problem(cached[0]):
        return cached[0], cached[1], f"{feed} served from the HTTP cache", "stale"
    reason = "offline mode, and there is no stored poll or cached copy"
    return None, "snapshot", _unavailable(feed, reason), "snapshot"


def _unavailable(feed: str, reason: str) -> str:
    return unavailable(f"ASD {feed}", reason)


def _accept_feed(result: tuple[str | None, str, str]) -> tuple[str, str, str] | None:
    text, warning, cache = result
    if not text or _feed_problem(text):
        return None
    if warning:
        return text, "stale", warning
    return text, cache, ""


def _feed_failure(result: tuple[str | None, str, str]) -> str:
    text, warning, _cache = result
    if text:
        return _feed_problem(text) or warning
    return warning


def _http(url: str, headers: dict, *, ttl: int, skip_cache: bool) -> tuple[str | None, str, str]:
    data_dir = _data_dir()
    client = HttpClient(
        "asd-acsc",
        policy=EgressPolicy(_allowlist(), "asd-acsc"),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", sleeper=_SLEEP),
        user_agent=USER_AGENT,
        rate=4,
        burst=20,
        window="rolling",
        timeout=60,
        retries=3,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
    )
    try:
        response = client.get(
            url,
            headers=headers,
            ttl=ttl,
            stale_if_error=0,
            skip_cache=skip_cache,
        )
    except Exception as exc:
        return None, redact(str(exc)), "snapshot"
    finally:
        client.close()
    if response.status >= 400:
        return None, f"upstream status {response.status}", response.cache
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return None, "ASD feed was not UTF-8", response.cache
    warning = ""
    if response.cache == "stale":
        warning = "served from cache after the live fetch failed"
    return text, warning, response.cache


def _page(url: str) -> tuple[dict | None, str, str]:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1"
    if offline or os.environ.get(_OVERRIDE):
        cached = _cached_page(url)
        if cached:
            return _parse_html(cached, url), "stale", "served from the HTTP cache"
        saved = _stored_by_link(url)
        if saved and saved.get("body"):
            return _page_from_row(saved), "stale", "served from the stored page"
        mapped = _mapped_html(url)
        if mapped is None:
            return None, "snapshot", "no stored page for this URL"
        return _parse_html(mapped, url), "snapshot", _OVERRIDE_NOTE
    try:
        _limit("asd:item", rate=1 / 5, burst=1)
    except Exception as exc:
        return None, "snapshot", redact(str(exc))
    text, warning, cache = _http(url, _DIRECT, ttl=7 * 86400, skip_cache=False)
    if text is None:
        note = warning or "item fetch failed"
        saved = _stored_by_link(url)
        if saved and saved.get("body"):
            return _page_from_row(saved), "stale", note
        return None, "snapshot", note
    parsed = _parse_html(text, url)
    _save_page(url, parsed)
    if warning and cache != "stale":
        cache = "stale"
    return parsed, cache, warning


def _parse_feed(text: str, feed: str) -> list[dict]:
    root = ET.fromstring(text)
    by_id: dict[str, dict] = {}
    for node in root.iter():
        if _local(node.tag) != "item":
            continue
        fields = {_local(child.tag): (child.text or "").strip() for child in list(node)}
        link = fields.get("link") or fields.get("guid") or ""
        if not link:
            continue
        title = fields.get("title") or ""
        summary = fields.get("description") or ""
        published = _published(fields.get("pubDate") or fields.get("date") or "")
        plain = f"{title}\n{summary}"
        item_id = _item_id(feed, link)
        by_id[item_id] = {
            "id": item_id,
            "feed": feed,
            "link": link,
            "title": title,
            "summary": summary,
            "published": published,
            "body": "",
            "cves": _ids(_CVE, plain),
            "attack_ids": _ids(_ATTACK, plain),
        }
    return list(by_id.values())


def _parse_html(text: str, url: str) -> dict:
    parser = _PageParser()
    parser.feed(text)
    plain = " ".join(parser.parts)
    headings = [part.strip() for part in parser.headings if part.strip()]
    links = []
    for href in parser.links:
        absolute = urljoin(url, href)
        if absolute.startswith("https://"):
            links.append(absolute)
    return {
        "title": headings[0] if headings else "",
        "summary": plain[:500],
        "body": plain,
        "headings": headings,
        "links": links,
        "cves": _ids(_CVE, plain),
        "attack_ids": _ids(_ATTACK, plain),
        "published": "",
    }


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.headings: list[str] = []
        self.links: list[str] = []
        self.parts: list[str] = []
        self._heading: str | None = None
        self._buf: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        attr = {key.lower(): value for key, value in attrs}
        if tag in {"script", "style"}:
            self._skip += 1
        if tag in {"h1", "h2", "h3"}:
            self._heading = tag
            self._buf = []
        if tag == "a" and attr.get("href"):
            self.links.append(attr["href"])

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self._skip:
            self._skip -= 1
        if tag == self._heading:
            self.headings.append("".join(self._buf))
            self._heading = None

    def handle_data(self, data):
        if self._skip:
            return
        if self._heading is not None:
            self._buf.append(data)
        if data.strip():
            self.parts.append(data.strip())


def _persist(
    feed: str,
    items: list[dict],
    *,
    method: str,
    warning: str,
    cache: str,
    replace: bool = True,
    touch_status: bool = True,
) -> None:
    now = datetime.now(_SYDNEY).strftime("%Y-%m-%dT%H:%M:%S%z")
    newest = ""
    for item in items:
        if item.get("published") and item["published"] > newest:
            newest = item["published"]
    succeeded = method in {"direct", "http11", "snapshot", "manual"} and cache != "stale"
    success = now if succeeded else None
    with _db() as conn:
        for item in items:
            if replace:
                conn.execute(
                    """
                    INSERT INTO advisories (
                        id, feed, link, title, summary, published, body, cves,
                        attack_ids, fetched_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        title=excluded.title,
                        summary=excluded.summary,
                        published=CASE WHEN excluded.published = '' THEN advisories.published
                             ELSE excluded.published END,
                        body=CASE WHEN excluded.body = '' THEN advisories.body
                             ELSE excluded.body END,
                        cves=excluded.cves,
                        attack_ids=excluded.attack_ids,
                        fetched_at=excluded.fetched_at
                    """,
                    (
                        item["id"],
                        item["feed"],
                        item["link"],
                        item.get("title") or "",
                        item.get("summary") or "",
                        item.get("published") or "",
                        item.get("body") or "",
                        json.dumps(item.get("cves") or []),
                        json.dumps(item.get("attack_ids") or []),
                        now,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO advisories (
                        id, feed, link, title, summary, published, body, cves,
                        attack_ids, fetched_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item["id"],
                        item["feed"],
                        item["link"],
                        item.get("title") or "",
                        item.get("summary") or "",
                        item.get("published") or "",
                        item.get("body") or "",
                        json.dumps(item.get("cves") or []),
                        json.dumps(item.get("attack_ids") or []),
                        now,
                    ),
                )
        if not touch_status:
            return
        conn.execute("DELETE FROM feed_poll WHERE feed = ?", (feed,))
        seen: set[str] = set()
        for item in items:
            if item["id"] in seen:
                continue
            seen.add(item["id"])
            conn.execute(
                "INSERT OR IGNORE INTO feed_poll (feed, item_id) VALUES (?, ?)",
                (feed, item["id"]),
            )
        conn.execute(
            """
            INSERT INTO feed_status (feed, last_success, method, item_count, warning, data_as_of)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(feed) DO UPDATE SET
                last_success=COALESCE(excluded.last_success, feed_status.last_success),
                method=excluded.method,
                item_count=excluded.item_count,
                warning=excluded.warning,
                data_as_of=COALESCE(excluded.data_as_of, feed_status.data_as_of)
            """,
            (feed, success, method, len(seen), warning, newest or None),
        )


def _save_page(url: str, page: dict) -> None:
    existing = _stored_by_link(url)
    if existing:
        item = dict(existing)
        if page.get("body"):
            item["body"] = page["body"]
        if page.get("cves"):
            item["cves"] = page["cves"]
        if page.get("attack_ids"):
            item["attack_ids"] = page["attack_ids"]
        if not item.get("title"):
            item["title"] = page.get("title") or ""
        if not item.get("summary"):
            item["summary"] = page.get("summary") or ""
        _persist(
            existing["feed"],
            [item],
            method="direct",
            warning="",
            cache="miss",
            touch_status=False,
        )
        return
    _persist(
        "pages",
        [
            {
                "id": _item_id("pages", url),
                "feed": "pages",
                "link": url,
                "title": page.get("title") or "",
                "summary": page.get("summary") or "",
                "published": page.get("published") or "",
                "body": page.get("body") or "",
                "cves": page.get("cves") or [],
                "attack_ids": page.get("attack_ids") or [],
            }
        ],
        method="direct",
        warning="",
        cache="miss",
        touch_status=False,
    )


def _stored_by_link(url: str) -> dict | None:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM advisories WHERE link = ? ORDER BY coalesce(published, '') DESC",
            (url,),
        ).fetchone()
    if row is None:
        return None
    return _row_item(row)


def _page_from_row(item: dict) -> dict:
    return {
        "title": item.get("title") or "",
        "summary": item.get("summary") or "",
        "body": item.get("body") or "",
        "headings": [],
        "links": [],
        "cves": item.get("cves") or [],
        "attack_ids": item.get("attack_ids") or [],
        "published": item.get("published") or "",
    }


def _has_poll(feed: str) -> bool:
    with _db() as conn:
        row = conn.execute("SELECT 1 FROM feed_status WHERE feed = ?", (feed,)).fetchone()
    return row is not None


def _latest_poll(feed: str) -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            """
            SELECT advisories.* FROM advisories
            JOIN feed_poll ON feed_poll.item_id = advisories.id
             AND feed_poll.feed = advisories.feed
            WHERE advisories.feed = ?
            ORDER BY coalesce(advisories.published, '') DESC
            """,
            (feed,),
        ).fetchall()
    return [_row_item(row) for row in rows]


def _has_items() -> bool:
    with _db() as conn:
        return conn.execute("SELECT 1 FROM advisories LIMIT 1").fetchone() is not None


def _hydrate_override() -> None:
    # Only the operator-supplied CYBERAU_ASD_SNAPSHOT files may seed an empty store.
    if not os.environ.get(_OVERRIDE) or _has_items():
        return
    for feed in FEEDS:
        text = _read_snapshot(feed)
        if not text or schema_drift(text):
            continue
        _persist(feed, _parse_feed(text, feed), method="snapshot", warning="", cache="snapshot")


def _row_item(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "feed": row["feed"],
        "link": row["link"],
        "title": row["title"],
        "summary": row["summary"],
        "published": row["published"],
        "body": row["body"],
        "cves": json.loads(row["cves"] or "[]"),
        "attack_ids": json.loads(row["attack_ids"] or "[]"),
    }


def _public(item: dict) -> dict:
    cves = item.get("cves") or []
    attack_ids = item.get("attack_ids") or []
    if isinstance(cves, str):
        cves = json.loads(cves)
    if isinstance(attack_ids, str):
        attack_ids = json.loads(attack_ids)
    return {
        "id": item["id"],
        "feed": item["feed"],
        "title": untrusted_text(str(item.get("title") or ""), "asd"),
        "link": safe_url(item["link"]),
        "published": item.get("published") or "",
        "summary": untrusted_text(str(item.get("summary") or ""), "asd"),
        "cves": cves,
        "attack_ids": attack_ids,
    }


def _public_page(url: str, page: dict) -> dict:
    return {
        "id": _item_id("advisories", url),
        "url": url,
        "title": untrusted_text(page["title"], "asd"),
        "headings": [untrusted_text(item, "asd") for item in page["headings"]],
        "body": untrusted_text(page["body"], "asd"),
        "cves": page["cves"],
        "attack_ids": page["attack_ids"],
        "links": [link for link in map(safe_url, page["links"]) if link],
    }


def _read_snapshot(feed: str) -> str | None:
    # Only the operator override is read. Nothing shipped in the package is served.
    override = os.environ.get(_OVERRIDE)
    if not override:
        return None
    path = Path(override) / f"{feed}.xml"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _mapped_html(url: str) -> str | None:
    override = os.environ.get(_OVERRIDE)
    if not override:
        return None
    root = Path(override)
    index = root / "items.json"
    if not index.is_file():
        return None
    mapping = json.loads(index.read_text(encoding="utf-8"))
    name = mapping.get(url)
    if not name:
        return None
    page = root / name
    if page.is_file():
        return page.read_text(encoding="utf-8")
    return None


def _feed_url(feed: str) -> str:
    return f"https://www.cyber.gov.au/rss/{feed}"


def _item_id(feed: str, link: str) -> str:
    digest = hashlib.sha1(link.encode()).hexdigest()
    return f"asd:{feed}:{digest}"


def _parse_pubdate(value: str):
    if not value or not value.strip():
        return None
    try:
        return email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError, IndexError):
        return None


def _published(value: str) -> str:
    parsed = _parse_pubdate(value)
    if parsed is None:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_SYDNEY)
    return parsed.astimezone(_SYDNEY).date().isoformat()


def _cached_body(url: str) -> str | None:
    cache = HttpCache(_data_dir() / "http_cache.sqlite")
    key = cache.key("GET", url, None, b"", "anonymous")
    item = cache.get(key)
    if item is None:
        return None
    try:
        return item.body.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _cached_feed(feed: str) -> tuple[str, str] | None:
    text = _cached_body(_feed_url(feed))
    if text is None:
        return None
    cache = HttpCache(_data_dir() / "http_cache.sqlite")
    key = cache.key("GET", _feed_url(feed), None, b"", "anonymous")
    item = cache.get(key)
    if item is None:
        return None
    state = "hit" if cache.fresh(item) else "stale"
    return text, state


def _cached_page(url: str) -> str | None:
    return _cached_body(url)


def _ids(pattern: re.Pattern[str], text: str) -> list[str]:
    return sorted(set(pattern.findall(text)))


def _feeds(feeds: list[str] | None) -> tuple[list[str], str]:
    chosen = list(feeds) if feeds else ["alerts", "advisories"]
    if not chosen:
        return [], "feeds must not be empty"
    for item in chosen:
        if item not in FEEDS:
            return [], f"unknown feed: {item}"
    return chosen, ""


def _limit(key: str, *, rate: float, burst: int) -> None:
    RateLimiter(_data_dir() / "rate_limit.sqlite", sleeper=_SLEEP).acquire(
        key,
        rate=rate,
        burst=burst,
        window="rolling",
        timeout=60,
    )


def _merge_cache(caches: list[str]) -> str:
    if not caches:
        return "snapshot"
    if "stale" in caches:
        return "stale"
    if "miss" in caches:
        return "miss"
    if "hit" in caches:
        return "hit"
    return "snapshot"


def _envelope(
    data,
    cache: str,
    urls: list[str] | None = None,
    data_as_of: str | None = None,
    warnings=(),
):
    return envelope(
        "asd-acsc",
        data,
        urls=urls or [],
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-asd"))
    path.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def _db():
    conn = sqlite3.connect(_data_dir() / "asd_advisories.sqlite")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS advisories (
            id TEXT PRIMARY KEY,
            feed TEXT NOT NULL,
            link TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            published TEXT,
            body TEXT NOT NULL DEFAULT '',
            cves TEXT NOT NULL,
            attack_ids TEXT NOT NULL,
            fetched_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS feed_poll (
            feed TEXT NOT NULL,
            item_id TEXT NOT NULL,
            PRIMARY KEY (feed, item_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS feed_status (
            feed TEXT PRIMARY KEY,
            last_success TEXT,
            method TEXT NOT NULL,
            item_count INTEGER NOT NULL,
            warning TEXT NOT NULL,
            data_as_of TEXT
        )
        """
    )
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("asd-acsc", connector)
