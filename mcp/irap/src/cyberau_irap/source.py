"""Read-only IRAP guidance from cyber.gov.au.

Quotations only. This module does not perform an IRAP assessment and it is not endorsed by ASD.
"""

import hashlib
import json
import os
import random
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Annotated
from zoneinfo import ZoneInfo

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

OVERVIEW_URL = "https://www.cyber.gov.au/irap"
CONSUMER_URL = (
    "https://www.cyber.gov.au/business-government/protecting-devices-systems/"
    "assessment-evaluation-programs/irap/irap-consumer-guide"
)
PAGES = (
    ("overview", OVERVIEW_URL, "irap_overview.html"),
    ("consumer-guide", CONSUMER_URL, "irap_consumer_guide.html"),
)
ATTRIBUTION = (
    "Commonwealth of Australia IRAP guidance from cyber.gov.au "
    "(July 2025 consumer guide, CC BY 4.0 except the Coat of Arms). "
    "Short quotations only. This is not an IRAP assessment and it is not endorsed by ASD."
)
SNAPSHOT_NOTE = (
    "Shipped snapshot: short passages seen through a search index on 16 October 2026. "
    "It is not a full fetch of the cyber.gov.au page. Read the current page before relying on it."
)
_STOP = frozenset(
    "about all and any are can does for from has have how its may not should that the their "
    "them then there these they this was what when where which who why will with would you "
    "your".split()
)
_CHROME = {"nav", "header", "footer", "aside", "form", "noscript"}
_PACKAGE = Path(__file__).resolve().parents[2]
_SYDNEY = ZoneInfo("Australia/Sydney")
_QUERY = Annotated[str, Field(min_length=2)]
_TOKEN = re.compile(r"[a-z0-9]+")
_TRANSPORT = None
_NOW: float | None = None
_RNG = random.random
_DIRECT = {
    "user-agent": USER_AGENT,
    "accept": "text/html, application/xhtml+xml, */*",
}
_BROWSER = {
    "user-agent": f"{USER_AGENT} (compatible; HTTP/1.1 fallback)",
    "accept": "text/html, application/xhtml+xml;q=0.9, */*;q=0.8",
    "accept-language": "en-AU,en;q=0.9",
    "connection": "close",
}


def irap_search_guidance(query: _QUERY) -> dict:
    if not isinstance(query, str) or len(query.strip()) < 2:
        return _envelope(
            _not_covered(),
            "snapshot",
            warnings=("query must be at least 2 characters",),
        )
    pages = _pages(None)
    warnings = _page_warnings(pages)
    records = [row for page in pages for row in page["records"]]
    matched = [row for row in records if _matches(query, row["sentence"])]
    cache = _merge_cache([page["cache"] for page in pages])
    urls = [page["url"] for page in pages]
    if not matched:
        warnings.append("not covered")
        return _envelope(_not_covered(), cache, urls, _as_of(records), tuple(warnings))
    public = [_public(row) for row in matched[:20]]
    if len(matched) > 20:
        warnings.append("results truncated to 20 passages")
    return _envelope(_quoted(public), cache, urls, _as_of(matched), tuple(warnings))


def irap_consumer_checklist() -> dict:
    pages = _pages(("consumer-guide",))
    page = pages[0]
    checks = [_public(row) for row in page["records"] if row["kind"] == "check"]
    warnings = _page_warnings(pages)
    if not checks and not page["warning"]:
        warnings.append("consumer guide checklist is empty")
    return _envelope(checks, page["cache"], [page["url"]], _as_of(page["records"]), tuple(warnings))


def _page_warnings(pages: list[dict]) -> list[str]:
    warnings = [page["warning"] for page in pages if page["warning"]]
    if any(page["snapshot"] for page in pages):
        warnings.append(SNAPSHOT_NOTE)
    return warnings


def connector() -> Connector:
    return _IrapConnector()


class _IrapConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="irap",
            server_name="irap",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "irap_search_guidance",
                    "Search quoted IRAP guidance. Unanswered questions are not covered. "
                    "This is not an assessment.",
                    irap_search_guidance,
                ),
                ToolSpec(
                    "irap_consumer_checklist",
                    "List consumer guide checks, each linked to its source paragraph. "
                    "This is not an assessment.",
                    irap_consumer_checklist,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            return _schema_probe(self.key)
        if not live:
            return Probe(self.key, True, "offline ok")
        records: list[dict] = []
        for page_id, url, filename in PAGES:
            page = _fetch_page(page_id, url, filename, force_live=True)
            if page["warning"] or not page["records"]:
                detail = page["warning"] or f"live probe returned no guidance for {page_id}"
                return Probe(self.key, False, detail)
            records.extend(page["records"])
        problem = _validate_responses(records)
        if problem:
            return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def schema_drift(text: str) -> str | None:
    if not text or not text.strip():
        return "IRAP page is empty"
    if "data-url=" not in text:
        return "IRAP schema drift, missing data-url"
    if "data-retrieved=" not in text:
        return "IRAP schema drift, missing data-retrieved"
    if "data-sentence=" not in text:
        return "IRAP schema drift, missing data-sentence"
    return None


def _schema_probe(name: str) -> Probe:
    problems = []
    records: list[dict] = []
    for page_id, url, filename in PAGES:
        text = _read_snapshot(filename)
        if text is None:
            problems.append(f"{page_id} snapshot is missing")
            continue
        drift = schema_drift(text)
        if drift:
            problems.append(f"{page_id}: {drift}")
            continue
        parsed, warning = _interpret(page_id, url, text, snapshot_rules=True)
        if warning:
            problems.append(warning)
        records.extend(parsed)
    if problems:
        return Probe(name, False, "; ".join(problems))
    problem = _validate_responses(records)
    if problem:
        return Probe(name, False, problem)
    return Probe(name, True, "schema ok")


def _validate_responses(records: list[dict]) -> str | None:
    public = [_public(row) for row in records]
    search = _quoted(public[:20]) if public else _not_covered()
    checks = [row for row in public if row["kind"] == "check"]
    try:
        jsonschema.validate(search, _response_schema("irap_search_guidance.response.json"))
        jsonschema.validate(checks, _response_schema("irap_consumer_checklist.response.json"))
    except jsonschema.ValidationError as exc:
        return "IRAP response schema: " + exc.message[:200]
    return None


def _pages(only: tuple[str, ...] | None, *, force_live: bool = False) -> list[dict]:
    found = []
    blocked = False
    for page_id, url, filename in PAGES:
        if only is not None and page_id not in only:
            continue
        if blocked and not force_live:
            found.append(_snapshot_page(page_id, url, filename, after_block=True))
            continue
        result = _fetch_page(page_id, url, filename, force_live=force_live)
        found.append(result)
        if result["blocked"]:
            blocked = True
    return found


def _fetch_page(page_id: str, url: str, filename: str, *, force_live: bool) -> dict:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    pinned = bool(os.environ.get("CYBERAU_IRAP_SNAPSHOT")) and not force_live
    if pinned or (offline and not _stored_html(page_id)):
        return _snapshot_page(page_id, url, filename, after_block=False)
    if offline:
        stored = _stored_html(page_id) or ""
        records, warning = _interpret(page_id, url, stored, snapshot_rules=_structured(stored))
        if records and not warning:
            return _done(
                page_id,
                url,
                records,
                "stale",
                f"{page_id} served from the last stored copy",
                blocked=False,
            )
        return _snapshot_page(page_id, url, filename, after_block=False)
    try:
        _limit()
    except Exception as exc:
        page = _snapshot_page(page_id, url, filename, after_block=False)
        page["warning"] = f"{page_id} rate limited: {redact(str(exc))}"
        return page
    direct = _http(url, _DIRECT, skip_cache=force_live)
    accepted = _accept(page_id, url, direct, "direct")
    if accepted is not None:
        return accepted
    if force_live:
        return _done(page_id, url, [], "snapshot", direct["warning"] or "live fetch failed", False)
    fallback_warning = direct["warning"]
    blocked = direct["blocked"]
    if _try_http11(direct["warning"]):
        fallback = _http(url, _BROWSER, skip_cache=True)
        accepted = _accept(page_id, url, fallback, "http11")
        if accepted is not None:
            return accepted
        fallback_warning = fallback["warning"] or fallback_warning
        blocked = blocked or fallback["blocked"]
    stored = _stored_html(page_id)
    if stored:
        records, warning = _interpret(page_id, url, stored, snapshot_rules=_structured(stored))
        if records and not warning:
            note = f"{page_id} fetch failed: {fallback_warning}"
            return _done(page_id, url, records, "stale", note, blocked)
    page = _snapshot_page(page_id, url, filename, after_block=False)
    if page["records"] and not page["warning"]:
        page["warning"] = f"{page_id} fetch failed: {fallback_warning}; served shipped snapshot"
    elif not page["warning"]:
        page["warning"] = fallback_warning or f"{page_id} is unavailable"
    page["blocked"] = blocked
    return page


def _snapshot_page(page_id: str, url: str, filename: str, *, after_block: bool) -> dict:
    text = _read_snapshot(filename)
    records, warning = _interpret(page_id, url, text, snapshot_rules=True)
    if after_block and not warning:
        warning = f"{page_id} served shipped snapshot after cyber.gov.au could not be reached"
    if records and text and not warning:
        _persist(page_id, url, text, records, method="snapshot")
    return _done(page_id, url, records, "snapshot", warning, blocked=after_block)


def _accept(page_id: str, url: str, fetched: dict, method: str) -> dict | None:
    text = fetched["text"]
    if not text:
        return None
    if fetched["warning"] and fetched["cache"] != "stale":
        return None
    records, warning = _interpret(page_id, url, text, snapshot_rules=_structured(text))
    if warning or not records:
        return None
    _persist(page_id, url, text, records, method=method)
    return _done(page_id, url, records, fetched["cache"], fetched["warning"], blocked=False)


def _try_http11(warning: str) -> bool:
    text = warning.lower()
    if "returned 401" in text or "returned 403" in text or "returned 429" in text:
        return False
    if "not allowlisted" in text or "egress" in text:
        return False
    return True


def _http(url: str, headers: dict, *, skip_cache: bool) -> dict:
    data_dir = _data_dir()
    client = HttpClient(
        "irap",
        policy=EgressPolicy(_allowlist(), "irap"),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", clock=_clock, sleeper=_sleep),
        user_agent=USER_AGENT,
        rate=4,
        burst=8,
        window="rolling",
        timeout=60,
        retries=1,
        transport=_TRANSPORT,
        sleeper=_sleep,
        rng=_RNG,
    )
    try:
        response = client.get(
            url,
            headers=headers,
            ttl=7 * 24 * 3600,
            stale_if_error=7 * 24 * 3600,
            skip_cache=skip_cache,
        )
    except EgressDenied as exc:
        return _http_fail(redact(str(exc)), blocked=False)
    except Exception as exc:
        message = redact(str(exc))
        return _http_fail(message, blocked=_blocked(message))
    finally:
        client.close()
    if response.status in (401, 403):
        return _http_fail(_auth_warning(response.status), blocked=False)
    if response.status == 429:
        return _http_fail("cyber.gov.au returned 429", blocked=False)
    if response.status >= 400:
        return _http_fail(f"upstream status {response.status}", blocked=False)
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return _http_fail("IRAP page was not UTF-8", blocked=False)
    warning = ""
    if response.cache == "stale":
        warning = "served from cache after the live fetch failed"
    return {
        "text": text,
        "warning": warning,
        "cache": response.cache,
        "blocked": False,
    }


def _http_fail(warning: str, *, blocked: bool) -> dict:
    return {"text": None, "warning": warning, "cache": "snapshot", "blocked": blocked}


def _blocked(message: str) -> bool:
    text = message.lower()
    return "connecterror" in text or "timed out" in text or "name or service not known" in text


def _auth_warning(status: int) -> str:
    return (
        f"cyber.gov.au returned {status}. "
        "IRAP guidance is public and this connector reads no API key. "
        "Set CYBERAU_OFFLINE=1 to answer from the shipped snapshot."
    )


def _interpret(
    page_id: str,
    url: str,
    text: str | None,
    *,
    snapshot_rules: bool,
) -> tuple[list[dict], str]:
    if text is None:
        return [], f"{page_id} snapshot is missing"
    if snapshot_rules or _structured(text):
        drift = schema_drift(text)
        if drift:
            return [], drift
    try:
        records = _parse(text, page_id, url)
    except Exception as exc:
        return [], f"{page_id} page was not usable: {redact(str(exc))}"
    if not records:
        return [], f"{page_id} page had no guidance sentences"
    return records, ""


def _structured(text: str) -> bool:
    return "data-url=" in text or "data-sentence=" in text or "data-wording=" in text


def _parse(text: str, page_id: str, url: str) -> list[dict]:
    parser = _GuideParser(page_id, url)
    parser.feed(text)
    parser.close()
    return parser.items


class _GuideParser(HTMLParser):
    def __init__(self, page_id: str, fallback_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_id = page_id
        self.url = fallback_url
        self.retrieved = ""
        self.items: list[dict] = []
        self._skip = 0
        self._chrome = 0
        self._capture: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        attr = {key.lower(): value or "" for key, value in attrs}
        if tag in {"script", "style"}:
            self._skip += 1
        if tag in _CHROME:
            self._chrome += 1
        if tag == "article":
            if attr.get("data-url"):
                self.url = attr["data-url"]
            if attr.get("data-retrieved"):
                self.retrieved = attr["data-retrieved"]
        sentence = attr.get("data-sentence", "").strip()
        if sentence and not self._skip:
            kind = attr.get("data-kind") or ("check" if tag == "li" else "paragraph")
            self.items.append(self._item(attr.get("data-id", ""), kind, sentence))
            return
        if tag in {"p", "li"} and not self._skip and not self._chrome:
            self._capture = tag
            self._buf = []

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self._skip:
            self._skip -= 1
        if tag in _CHROME and self._chrome:
            self._chrome -= 1
        if self._capture == tag:
            text = " ".join("".join(self._buf).split())
            self._capture = None
            self._buf = []
            if len(text) >= 40:
                kind = "check" if tag == "li" else "paragraph"
                self.items.append(self._item("", kind, text))

    def handle_data(self, data):
        if self._skip or self._capture is None:
            return
        self._buf.append(data)

    def _item(self, paragraph_id: str, kind: str, sentence: str) -> dict:
        retrieved = self.retrieved or _today()
        if not paragraph_id:
            paragraph_id = hashlib.sha256(sentence.encode()).hexdigest()[:12]
        return {
            "id": f"irap:{self.page_id}:{paragraph_id}",
            "page": self.page_id,
            "kind": kind,
            "paragraph_id": paragraph_id,
            "url": self.url,
            "sentence": sentence,
            "retrieved": retrieved,
            "sha256": hashlib.sha256(sentence.encode()).hexdigest(),
        }


def _matches(query: str, sentence: str) -> bool:
    hay = sentence.casefold()
    needle = " ".join(query.casefold().split())
    tokens = [token for token in _TOKEN.findall(needle) if len(token) >= 3 and token not in _STOP]
    if not tokens:
        return False
    if needle in hay:
        return True
    return all(re.search(rf"\b{re.escape(token)}", hay) for token in tokens)


def _public(row: dict) -> dict:
    return {
        "id": row["id"],
        "page": row["page"],
        "kind": row["kind"],
        "sentence": untrusted_text(row["sentence"], "irap"),
        "url": row["url"],
        "retrieved": row["retrieved"],
        "sha256": row["sha256"],
        "paragraph_id": row["paragraph_id"],
        "assessment": False,
        "endorsed_by_asd": False,
    }


def _quoted(matches: list[dict]) -> dict:
    return {
        "coverage": "quoted",
        "assessment": False,
        "endorsed_by_asd": False,
        "matches": matches,
    }


def _not_covered() -> dict:
    return {
        "coverage": "not covered",
        "assessment": False,
        "endorsed_by_asd": False,
        "matches": [],
    }


def _persist(page_id: str, url: str, html: str, records: list[dict], *, method: str) -> None:
    now = datetime.now(_SYDNEY).strftime("%Y-%m-%dT%H:%M:%S%z")
    with _db() as conn:
        if method in {"direct", "http11"}:
            conn.execute(
                """
                INSERT INTO pages (page, url, html, method, fetched_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(page) DO UPDATE SET
                    url=excluded.url,
                    html=excluded.html,
                    method=excluded.method,
                    fetched_at=excluded.fetched_at
                """,
                (page_id, url, html, method, now),
            )
        for record in records:
            if method in {"direct", "http11"}:
                conn.execute(
                    """
                    INSERT INTO guidance (
                        id, page, kind, paragraph_id, url, sentence, sha256, retrieved, fetched_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        sentence=excluded.sentence,
                        sha256=excluded.sha256,
                        retrieved=excluded.retrieved,
                        fetched_at=excluded.fetched_at
                    """,
                    (
                        record["id"],
                        record["page"],
                        record["kind"],
                        record["paragraph_id"],
                        record["url"],
                        record["sentence"],
                        record["sha256"],
                        record["retrieved"],
                        now,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO guidance (
                        id, page, kind, paragraph_id, url, sentence, sha256, retrieved, fetched_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["id"],
                        record["page"],
                        record["kind"],
                        record["paragraph_id"],
                        record["url"],
                        record["sentence"],
                        record["sha256"],
                        record["retrieved"],
                        now,
                    ),
                )


def _stored_html(page_id: str) -> str | None:
    with _db() as conn:
        row = conn.execute("SELECT html FROM pages WHERE page = ?", (page_id,)).fetchone()
    if row is None:
        return None
    return row["html"]


def _read_snapshot(filename: str) -> str | None:
    path = _snapshot_root() / filename
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _snapshot_root() -> Path:
    override = os.environ.get("CYBERAU_IRAP_SNAPSHOT")
    if override:
        return Path(override)
    return _PACKAGE / "data"


def _response_schema(name: str) -> dict:
    path = _PACKAGE / "schema" / name
    return json.loads(path.read_text(encoding="utf-8"))


def _limit() -> None:
    RateLimiter(_data_dir() / "rate_limit.sqlite", clock=_clock, sleeper=_sleep).acquire(
        "irap:page",
        rate=1 / 6,
        burst=1,
        window="rolling",
        timeout=60,
    )


def _done(
    page_id: str,
    url: str,
    records: list[dict],
    cache: str,
    warning: str,
    blocked: bool,
) -> dict:
    return {
        "snapshot": cache == "snapshot",
        "page": page_id,
        "url": url,
        "records": records,
        "cache": cache,
        "warning": warning,
        "blocked": blocked,
    }


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


def _as_of(records: list[dict]) -> str | None:
    dates = [row["retrieved"] for row in records if row.get("retrieved")]
    if not dates:
        return None
    return max(dates)


def _envelope(
    data,
    cache: str,
    urls: list[str] | None = None,
    data_as_of: str | None = None,
    warnings=(),
):
    return envelope(
        "irap",
        data,
        urls=urls or [],
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _today() -> str:
    return datetime.now(_SYDNEY).date().isoformat()


def _clock() -> float:
    if _NOW is None:
        return time.monotonic()
    return _NOW


def _sleep(seconds: float) -> None:
    global _NOW
    if _NOW is None:
        time.sleep(seconds)
        return
    _NOW += seconds


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-irap"))
    path.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def _db():
    conn = sqlite3.connect(_data_dir() / "irap_guidance.sqlite")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pages (
            page TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            html TEXT NOT NULL,
            method TEXT NOT NULL,
            fetched_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS guidance (
            id TEXT PRIMARY KEY,
            page TEXT NOT NULL,
            kind TEXT NOT NULL,
            paragraph_id TEXT NOT NULL,
            url TEXT NOT NULL,
            sentence TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            retrieved TEXT NOT NULL,
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
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("irap", connector)
