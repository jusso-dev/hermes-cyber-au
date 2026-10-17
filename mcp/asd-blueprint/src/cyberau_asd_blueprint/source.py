"""Read-only ASD Blueprint for Secure Cloud lookup.

Search answers from a shipped snapshot. A refresh may fetch HTML, at most one
page every five seconds. Results are published guidance, not an ASD assessment,
and this connector is not endorsed by ASD.
"""

import json
import os
import re
import time
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

ORIGIN = "https://blueprint.asd.gov.au/"
HOST = "blueprint.asd.gov.au"
ATTRIBUTION = (
    "ASD Blueprint for Secure Cloud, published by the Australian Signals Directorate. "
    "This lookup is not an ASD assessment and is not endorsed by ASD. Licence not confirmed."
)
WEEK = 7 * 24 * 3600
PAGE_RATE = 1 / 5
_LIMIT = 20
_SKIPPED = frozenset({"script", "style", "nav", "header", "footer", "aside", "form", "noscript"})
_PAGE_FIELDS = ("url", "title", "settings")
_SETTING_FIELDS = ("item", "value")
_LABELS = {
    "entra-id": "Entra ID",
    "mfa": "MFA",
}
_PACKAGE = Path(__file__).resolve().parents[2]
_TRANSPORT = None
_SLEEP = time.sleep
_CLOCK = time.monotonic
_RESOLVER = None

_Query = Annotated[str, Field(min_length=2)]


def blueprint_search(query: _Query) -> dict:
    """Find the relevant Blueprint setting and return it with its link."""
    text = (query or "").strip()
    if len(text) < 2:
        return _envelope([], "snapshot", warnings=("query must be at least 2 characters",))
    document, cache, problem = _load_document()
    if problem or document is None:
        return _envelope([], cache, warnings=(problem or "Blueprint snapshot was not usable",))
    provenance = _provenance(document, cache)
    drift = schema_drift(document)
    if drift:
        return _envelope([], cache, warnings=(drift, *provenance), as_of=_as_of(document))
    rows = _match(document, text)
    if not rows:
        return _envelope(
            [],
            cache,
            warnings=("no matching Blueprint setting", *provenance),
            as_of=_as_of(document),
        )
    _persist(rows, _as_of(document))
    return _envelope(
        [_present(row) for row in rows],
        cache,
        urls=_urls(rows),
        warnings=provenance,
        as_of=_as_of(document),
    )


def refresh_index() -> dict:
    """Fetch the snapshot page URLs and store a fresh index. Weekly, one page every 5 seconds."""
    if os.environ.get("CYBERAU_OFFLINE") == "1":
        return _envelope([], "snapshot", warnings=("offline, Blueprint refresh skipped",))
    document, problem = _pinned_or_shipped()
    if problem or document is None:
        return _envelope([], "snapshot", warnings=(problem or "Blueprint snapshot was not usable",))
    drift = schema_drift(document)
    if drift:
        return _envelope([], "snapshot", warnings=(drift,))
    pages = []
    warnings: list[str] = []
    for page in document["pages"]:
        url = str(page.get("url") or "")
        if not _allowed_page(url):
            warnings.append("skipped a page outside blueprint.asd.gov.au")
            continue
        body, state, note = _fetch(url, force_live=True)
        if not body or state != "miss":
            warnings.append(f"{url}: {note or 'Blueprint page was not a live fetch'}")
            continue
        parsed = parse_html(body, url)
        if not parsed["title"] or not parsed["settings"]:
            warnings.append(f"{url}: Blueprint page had no title or settings")
            continue
        pages.append(parsed)
    if warnings or not pages:
        # A partial index would drop the failed pages from search, so keep the previous one.
        return _envelope([], "snapshot", warnings=tuple(warnings or ("Blueprint refresh failed",)))
    refreshed = {"retrieved_at": _now(), "pages": pages}
    _write_index(refreshed)
    rows = [
        {
            "url": page["url"],
            "title": page["title"],
            "section": page["section"],
            "group": "",
            "item": page["title"],
            "value": f"{len(page['settings'])} settings",
        }
        for page in pages
    ]
    return _envelope(
        [_present(row) for row in rows],
        "miss",
        urls=_urls(rows),
        as_of=refreshed["retrieved_at"],
    )


def connector() -> Connector:
    return _BlueprintConnector()


class _BlueprintConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="asd-blueprint",
            server_name="blueprint",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "blueprint_search",
                    "Find the relevant Blueprint setting and return it with its link.",
                    blueprint_search,
                )
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            document, problem = _pinned_or_shipped()
            if problem or document is None:
                return Probe(self.key, False, problem or "Blueprint snapshot was not usable")
            drift = schema_drift(document)
            if drift:
                return Probe(self.key, False, drift)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        document, problem = _pinned_or_shipped()
        if problem or document is None:
            return Probe(self.key, False, problem or "Blueprint snapshot was not usable")
        urls = [
            str(page.get("url") or "")
            for page in document.get("pages") or []
            if isinstance(page, dict)
        ]
        if not urls:
            return Probe(self.key, False, "no Blueprint pages to probe")
        failures = []
        for url in urls:
            body, state, note = _fetch(url, force_live=True)
            if not body or state != "miss":
                failures.append(f"{url}: {note or 'not a live fetch'}")
                continue
            parsed = parse_html(body, url)
            if not parsed["title"] or not parsed["settings"]:
                failures.append(f"{url}: no title or settings parsed")
        if failures:
            return Probe(self.key, False, "; ".join(failures))
        return Probe(self.key, True, f"live ok, {len(urls)} pages")


def schema_drift(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return "Blueprint payload is not an object"
    pages = payload.get("pages")
    if not isinstance(pages, list):
        return "Blueprint schema drift, missing pages"
    for page in pages:
        if not isinstance(page, dict):
            return "Blueprint schema drift, page is not an object"
        missing = [name for name in _PAGE_FIELDS if name not in page]
        if missing:
            return "Blueprint schema drift, missing " + ", ".join(missing)
        settings = page.get("settings")
        if not isinstance(settings, list):
            return "Blueprint schema drift, settings is not a list"
        for setting in settings:
            if not isinstance(setting, dict):
                return "Blueprint schema drift, setting is not an object"
            missing = [name for name in _SETTING_FIELDS if name not in setting]
            if missing:
                return "Blueprint schema drift, missing " + ", ".join(missing)
    return None


def parse_html(html: str, url: str) -> dict:
    parser = _ArticleParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return _page(url, "", "", [])
    title = parser.title or _title_tag(html)
    summary = parser.paragraphs[0] if parser.paragraphs else ""
    return _page(url, title, summary, parser.settings)


class _ArticleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skipping: list[str] = []
        self._article = 0
        self._capture: str | None = None
        self._buf: list[str] = []
        self._cell = False
        self._table = 0
        self._row: list[str] | None = None
        self._group = ""
        self.title = ""
        self.paragraphs: list[str] = []
        self.settings: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        if tag in _SKIPPED:
            self._skipping.append(tag)
            return
        if self._skipping:
            return
        if tag == "article":
            self._article += 1
            return
        if self._article == 0:
            return
        if self._cell:
            return
        if tag in {"h2", "h3", "h4"}:
            self._capture = tag
            self._buf = []
        elif tag == "p" and self._table == 0:
            self._capture = "p"
            self._buf = []
        elif tag == "table":
            self._table += 1
        elif tag == "tr" and self._table:
            self._row = []
        elif tag in {"td", "th"} and self._row is not None:
            self._cell = True
            self._buf = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in _SKIPPED:
            if tag in self._skipping:
                while self._skipping.pop() != tag:
                    pass
            return
        if self._skipping:
            return
        if tag == "article" and self._article:
            self._article -= 1
            self._capture = None
            self._cell = False
            return
        if self._article == 0:
            return
        if tag in {"td", "th"} and self._cell:
            if self._row is not None:
                self._row.append(_squash(self._buf))
            self._cell = False
            self._buf = []
            return
        if self._cell:
            return
        if tag == "h2" and self._capture == "h2":
            self.title = _squash(self._buf)
            self._capture = None
        elif tag in {"h3", "h4"} and self._capture == tag:
            self._group = _squash(self._buf)
            self._capture = None
        elif tag == "p" and self._capture == "p":
            text = _squash(self._buf)
            if text:
                self.paragraphs.append(text)
            self._capture = None
        elif tag == "tr" and self._row is not None:
            self._take_row(self._row)
            self._row = None
        elif tag == "table" and self._table:
            self._table -= 1

    def handle_data(self, data: str) -> None:
        if self._skipping:
            return
        if self._cell or self._capture:
            self._buf.append(data)

    def _take_row(self, row: list[str]) -> None:
        if len(row) < 2:
            return
        item, value = row[0], row[1]
        if item.lower() == "item" and value.lower() == "value":
            return
        self.settings.append({"group": self._group, "item": item, "value": value})


def _fetch(url: str, *, force_live: bool = False) -> tuple[str | None, str, str]:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if offline:
        cached = _cached_body(url)
        if cached is not None:
            return cached, "stale", ""
        return None, "snapshot", "offline and no cached Blueprint page"
    if not _allowed_page(url):
        return None, "snapshot", "skipped a page outside blueprint.asd.gov.au"
    client = HttpClient(
        "asd-blueprint",
        policy=_policy(),
        cache=HttpCache(_data_dir() / "http_cache.sqlite"),
        limiter=RateLimiter(_data_dir() / "rate_limit.sqlite", clock=_CLOCK, sleeper=_SLEEP),
        user_agent=USER_AGENT,
        rate=PAGE_RATE,
        burst=1,
        window="rolling",
        timeout=30,
        retries=3,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
    )
    try:
        response = client.get(
            url,
            headers={"accept": "text/html"},
            ttl=WEEK,
            stale_if_error=WEEK,
            skip_cache=force_live,
        )
    except EgressDenied as exc:
        return None, "snapshot", redact(str(exc))
    except Exception as exc:
        if not force_live:
            cached = _cached_body(url)
            if cached is not None:
                return cached, "stale", ""
        return None, "snapshot", redact(str(exc))
    finally:
        client.close()
    if response.status in (401, 403):
        return None, response.cache, _denied(response.status)
    if response.status >= 400:
        if not force_live:
            cached = _cached_body(url)
            if cached is not None:
                return cached, "stale", f"upstream status {response.status}"
        return None, response.cache, f"upstream status {response.status}"
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return None, response.cache, "Blueprint page was not UTF-8"
    warning = ""
    if response.cache == "stale":
        warning = "served from cache after the live fetch failed"
    return text, response.cache, warning


def _denied(status: int) -> str:
    return (
        f"blueprint.asd.gov.au returned {status}. "
        "This connector does not use a credential, so no environment variable is set or sent."
    )


def _policy() -> EgressPolicy:
    if _RESOLVER is None:
        return EgressPolicy(_allowlist(), "asd-blueprint")
    return EgressPolicy(_allowlist(), "asd-blueprint", resolver=_RESOLVER)


def _load_document() -> tuple[dict | None, str, str]:
    pinned = os.environ.get("CYBERAU_BLUEPRINT_SNAPSHOT")
    if pinned:
        document, problem = _read_json(Path(pinned))
        return document, "snapshot", problem
    offline = os.environ.get("CYBERAU_OFFLINE") == "1"
    stored, _index_problem = _read_stored_index()
    if stored is not None and schema_drift(stored) is None:
        state = "stale" if offline or not _fresh(stored) else "hit"
        return stored, state, ""
    document, problem = _read_json(_snapshot_path())
    return document, "snapshot", problem


def _pinned_or_shipped() -> tuple[dict | None, str]:
    pinned = os.environ.get("CYBERAU_BLUEPRINT_SNAPSHOT")
    path = Path(pinned) if pinned else _snapshot_path()
    return _read_json(path)


def _read_stored_index() -> tuple[dict | None, str]:
    path = _data_dir() / "blueprint-index.json"
    if not path.is_file():
        return None, ""
    return _read_json(path)


def _write_index(document: dict) -> None:
    directory = _data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "blueprint-index.json"
    staged = path.with_suffix(".json.tmp")
    staged.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    staged.replace(path)


def _read_json(path: Path) -> tuple[dict | None, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None, "Blueprint snapshot could not be read"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None, "Blueprint snapshot was not valid JSON"
    if not isinstance(payload, dict):
        return None, "Blueprint snapshot was not a JSON object"
    return payload, ""


def _match(document: dict, query: str) -> list[dict]:
    tokens = _tokens(query)
    if not tokens:
        return []
    ranked: list[tuple[int, dict]] = []
    page_hits: list[dict] = []
    for page in document.get("pages") or []:
        if not isinstance(page, dict) or not _allowed_page(str(page.get("url") or "")):
            continue
        title = str(page.get("title") or "")
        section = str(page.get("section") or "")
        summary = str(page.get("summary") or "")
        page_hay = _hay(title, section, summary)
        matched_setting = False
        for setting in page.get("settings") or []:
            if not isinstance(setting, dict):
                continue
            item = str(setting.get("item") or "")
            value = str(setting.get("value") or "")
            group = str(setting.get("group") or "")
            row = {
                "url": str(page["url"]),
                "title": title,
                "section": section,
                "group": group,
                "item": item,
                "value": value,
            }
            specific = _hay(item, value, group)
            broad = _hay(item, value, group, title, section)
            if _contains(specific, tokens):
                ranked.append((2, row))
                matched_setting = True
            elif _contains(broad, tokens):
                ranked.append((1, row))
                matched_setting = True
        if not matched_setting and _contains(page_hay, tokens):
            page_hits.append(
                {
                    "url": str(page["url"]),
                    "title": title,
                    "section": section,
                    "group": "",
                    "item": title,
                    "value": summary,
                }
            )
    ranked.sort(key=lambda pair: (-pair[0], pair[1]["url"], pair[1]["item"]))
    rows = [row for _score, row in ranked]
    if not rows:
        rows = page_hits
    return rows[:_LIMIT]


def _tokens(query: str) -> list[str]:
    spaced = re.sub(r"[^a-z0-9]+", " ", query.lower())
    return [token for token in spaced.split() if len(token) >= 2]


def _hay(*parts: str) -> str:
    text = " ".join(parts).lower()
    spaced = re.sub(r"[^a-z0-9]+", " ", text)
    collapsed = re.sub(r"[^a-z0-9]+", "", text)
    return f"{spaced} {collapsed}"


def _contains(hay: str, tokens: list[str]) -> bool:
    return all(token in hay for token in tokens)


def _envelope(
    data,
    cache: str,
    *,
    urls: list[str] | None = None,
    warnings: tuple[str, ...] | list[str] = (),
    as_of: str | None = None,
) -> dict:
    return envelope(
        "asd-blueprint",
        data,
        urls=list(urls or [ORIGIN]),
        cache=cache,
        data_as_of=as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _present(row: dict) -> dict:
    return {
        "url": row["url"],
        "title": untrusted_text(row.get("title") or "", "asd-blueprint"),
        "section": untrusted_text(row.get("section") or "", "asd-blueprint"),
        "group": untrusted_text(row.get("group") or "", "asd-blueprint"),
        "item": untrusted_text(row.get("item") or "", "asd-blueprint"),
        "value": untrusted_text(row.get("value") or "", "asd-blueprint"),
    }


def _persist(rows: list[dict], data_as_of: str | None) -> None:
    if not rows:
        return
    directory = _data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "blueprint-observations.jsonl"
    stamp = _now()
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            record = {
                "url": row["url"],
                "title": row.get("title") or "",
                "section": row.get("section") or "",
                "group": row.get("group") or "",
                "item": row.get("item") or "",
                "value": row.get("value") or "",
                "data_as_of": data_as_of,
                "observed_at": stamp,
            }
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _urls(rows: list[dict]) -> list[str]:
    found = [ORIGIN]
    for row in rows:
        url = row["url"]
        if url not in found:
            found.append(url)
    return found


def _page(url: str, title: str, summary: str, settings: list[dict]) -> dict:
    return {
        "url": url,
        "title": title,
        "section": _section(url),
        "summary": summary,
        "settings": settings,
    }


def _section(url: str) -> str:
    parts = [part for part in urlsplit(url).path.strip("/").split("/") if part]
    if len(parts) > 1:
        parts = parts[:-1]
    labels = [_LABELS.get(part, part.replace("-", " ").title()) for part in parts]
    return " / ".join(labels)


def _title_tag(html: str) -> str:
    match = re.search(r"<title>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return _squash([match.group(1)])


def _allowed_page(url: str) -> bool:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and (parts.hostname or "").lower() == HOST
        and port in (None, 443)
        and not parts.username
        and not parts.password
    )


def _cached_body(url: str) -> str | None:
    cache = HttpCache(_data_dir() / "http_cache.sqlite")
    key = cache.key("GET", url, None, b"", "anonymous")
    cached = cache.get(key)
    if cached is None:
        return None
    try:
        return cached.body.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _fresh(document: dict) -> bool:
    raw = str(document.get("retrieved_at") or "")
    try:
        when = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return False
    return datetime.now(UTC) - when < timedelta(days=7)


def _provenance(document: dict, cache: str) -> tuple[str, ...]:
    when = _as_of(document) or "an unknown date"
    if cache == "snapshot":
        return (
            f"Answered from the shipped Blueprint snapshot dated {when}. "
            "This is not a live page fetch and the Blueprint may have changed since.",
        )
    return (
        f"Answered from the stored Blueprint index retrieved {when}. "
        "This is not a live page fetch and the Blueprint may have changed since.",
    )


def _as_of(document: dict) -> str | None:
    raw = str(document.get("retrieved_at") or "")
    return raw or None


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _squash(parts: list[str]) -> str:
    return re.sub(r"\s+", " ", "".join(parts)).strip()


def _snapshot_path() -> Path:
    return _PACKAGE / "data" / "blueprint_two_pages.json"


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-asd-blueprint"))


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("asd-blueprint", connector)
