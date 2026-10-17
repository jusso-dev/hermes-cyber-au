"""Read-only Protective Security Policy Framework quotations."""

import json
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Annotated
from urllib.parse import urljoin

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

HOME_URL = "https://www.protectivesecurity.gov.au/"
REQUIREMENTS_URL = "https://www.protectivesecurity.gov.au/publications-library/pspf-page-2026"
PAGES = (
    ("requirements", REQUIREMENTS_URL),
    ("home", HOME_URL),
)
ATTRIBUTION = (
    "Protective Security Policy Framework quotations from the Department of Home Affairs "
    "(www.protectivesecurity.gov.au). Licence not confirmed. "
    "The mandatory requirements spreadsheet is not included. "
    "A missing record is not a PSPF assessment and does not mean no requirement exists. "
    "This connector is not endorsed by the Australian Government."
)
_PACKAGE = Path(__file__).resolve().parents[2]
_WEEK = 7 * 24 * 3600
_DIRECTION_FIELDS = ("id", "title", "published", "url")
_REQUIREMENT_FIELDS = ("id", "title", "url")
_MONTHS = {
    "january": 1,
    "february": 2,
    "march": 3,
    "april": 4,
    "may": 5,
    "june": 6,
    "july": 7,
    "august": 8,
    "september": 9,
    "october": 10,
    "november": 11,
    "december": 12,
}
_WS = re.compile(r"\s+")
_DIRECTION = re.compile(
    r"Direction\s+(?P<id>\d{3}-\d{4})\s+on\s+(?P<title>.+?)"
    r"(?:\s+Direction\s+\d{3}-\d{4})?\s+"
    r"Publication date:\s+(?P<date>\d{1,2}\s+[A-Za-z]+\s+\d{4})\s+"
    r"(?P<body>PSPF Direction\s+\d{3}-\d{4}\b.+?)"
    r"(?=Direction\s+\d{3}-\d{4}\s+on\s+|\Z)",
    re.IGNORECASE | re.DOTALL,
)
_TRANSPORT = None
_SLEEP = time.sleep
_DIRECT = {
    "user-agent": USER_AGENT,
    "accept": "text/html,application/xhtml+xml, */*",
}
_BROWSER = {
    "user-agent": f"{USER_AGENT} (compatible; HTTP/1.1 fallback)",
    "accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "accept-language": "en-AU,en;q=0.9",
    "connection": "close",
}
_Query = Annotated[str, Field(min_length=2)]


def pspf_search(query: _Query) -> dict:
    """Search snapshot quotations. A miss is not a PSPF assessment."""
    if not isinstance(query, str) or len(query.strip()) < 2:
        return _envelope([], "snapshot", warnings=("query must be at least 2 characters",))
    payload, cache, warning, _method = _inventory(force_live=False)
    if payload is None:
        return _envelope([], cache, warnings=(warning or "PSPF snapshot was not usable",))
    _persist(payload)
    rows = _search_store(query.strip().lower())
    warnings = [warning] if warning else []
    if not rows:
        warnings.append(
            f"no PSPF record in the snapshot matches {query.strip()!r}. "
            "This is not a finding that no requirement exists, and it is not a PSPF assessment."
        )
    return _envelope([_public(row) for row in rows], cache, _as_of(payload), tuple(warnings))


def pspf_list_directions() -> dict:
    """List protective security directions with dates and links."""
    payload, cache, warning, _method = _inventory(force_live=False)
    if payload is None:
        return _envelope([], cache, warnings=(warning or "PSPF snapshot was not usable",))
    _persist(payload)
    rows = sorted(
        payload["directions"],
        key=lambda row: (row.get("published") or "", row["id"]),
        reverse=True,
    )
    warnings = [warning] if warning else []
    if not rows:
        warnings.append(
            "no protective security directions in the snapshot. "
            "This is not a finding that none are in force, and it is not a PSPF assessment."
        )
    return _envelope([_public(row) for row in rows], cache, _as_of(payload), tuple(warnings))


def connector() -> Connector:
    return _PspfConnector()


class _PspfConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="pspf",
            server_name="pspf",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "pspf_search",
                    "Search PSPF snapshot quotations. A miss is not a PSPF assessment.",
                    pspf_search,
                ),
                ToolSpec(
                    "pspf_list_directions",
                    "Protective security directions with dates and links. Not a PSPF assessment.",
                    pspf_list_directions,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            payload = _load_snapshot_file()
            if payload is None:
                return Probe(self.key, False, "PSPF snapshot was not usable")
            problem = schema_drift(payload)
            if problem:
                return Probe(self.key, False, problem)
            shaped = _response_problem(_normalise(payload))
            if shaped:
                return Probe(self.key, False, shaped)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        try:
            _limit("pspf:regen")
        except Exception as exc:
            return Probe(self.key, False, redact(str(exc)))
        text, _cache, warning, _method = _fetch_page(REQUIREMENTS_URL, force_live=True)
        if not text:
            return Probe(self.key, False, warning or "PSPF live fetch failed")
        parsed = _parse_document(text, REQUIREMENTS_URL)
        if parsed is None:
            return Probe(self.key, False, "PSPF live page was not usable")
        problem = schema_drift(parsed) or _response_problem(parsed)
        if problem:
            return Probe(self.key, False, problem)
        if not parsed["requirements"] and not parsed["directions"]:
            return Probe(self.key, False, "live probe returned no PSPF records")
        return Probe(self.key, True, "live ok")


def schema_drift(payload) -> str | None:
    if not isinstance(payload, dict):
        return "PSPF payload is not an object"
    directions = payload.get("directions")
    requirements = payload.get("requirements")
    if not isinstance(directions, list):
        return "PSPF schema drift, missing directions"
    if not isinstance(requirements, list):
        return "PSPF schema drift, missing requirements"
    for row in directions:
        if not isinstance(row, dict):
            return "PSPF schema drift, direction is not an object"
        missing = [name for name in _DIRECTION_FIELDS if name not in row]
        if missing:
            return "PSPF schema drift, missing " + ", ".join(missing)
    for row in requirements:
        if not isinstance(row, dict):
            return "PSPF schema drift, requirement is not an object"
        missing = [name for name in _REQUIREMENT_FIELDS if name not in row]
        if missing:
            return "PSPF schema drift, missing " + ", ".join(missing)
    return None


def _inventory(*, force_live: bool) -> tuple[dict | None, str, str, str]:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    pinned = bool(os.environ.get("CYBERAU_PSPF_SNAPSHOT")) and not force_live
    if pinned or offline:
        payload = _load_snapshot_file()
        if payload is None:
            return None, "snapshot", "PSPF snapshot was not usable", "snapshot"
        problem = schema_drift(payload)
        if problem:
            return None, "snapshot", problem, "snapshot"
        state = "stale" if offline and not pinned and _has_records() else "snapshot"
        if offline and not pinned and _has_records():
            return _payload_from_store(), "stale", "served from the last stored poll", "stored"
        return _normalise(payload), state, "", "snapshot"
    try:
        _limit("pspf:regen")
    except Exception as exc:
        shipped = _shipped()
        if shipped is None:
            return None, "snapshot", redact(str(exc)), "snapshot"
        return shipped, "snapshot", redact(str(exc)), "snapshot"
    bodies: dict[str, str] = {}
    warnings: list[str] = []
    caches: list[str] = []
    method = "direct"
    for name, url in PAGES:
        text, cache, warning, used = _fetch_page(url, force_live=force_live)
        caches.append(cache)
        if used == "http11":
            method = "http11"
        if warning:
            warnings.append(f"{name} fetch failed: {warning}" if text is None else warning)
        if text:
            bodies[url] = text
    if bodies:
        parsed = _payload_from_bodies(bodies)
        problem = None if parsed is None else schema_drift(parsed)
        if parsed is not None and not problem and _has_content(parsed):
            parsed, filled = _fill_gaps(parsed)
            warnings.extend(filled)
            note = "; ".join(item for item in warnings if item)
            cache = "snapshot" if filled else _merge_cache(caches)
            return parsed, cache, note, method
        if parsed is None:
            warnings.append("PSPF page was not usable")
        elif problem:
            warnings.append(problem)
        elif not _has_content(parsed):
            warnings.append("PSPF pages contained no requirements or directions")
    if not force_live and _has_records():
        note = "; ".join(warnings) or "served from the last stored poll"
        return _payload_from_store(), "stale", note, "stale"
    shipped = _shipped()
    message = "; ".join(warnings) or "fetch failed"
    if shipped is not None:
        return shipped, "snapshot", f"{message}; served shipped snapshot", "snapshot"
    return None, "snapshot", message, "direct"


def _fetch_page(url: str, *, force_live: bool) -> tuple[str | None, str, str, str]:
    direct = _http(url, _DIRECT, ttl=_WEEK, skip_cache=force_live)
    accepted = _accept(direct)
    if accepted is not None:
        return accepted[0], accepted[1], accepted[2], "direct"
    fallback = _http(url, _BROWSER, ttl=_WEEK, skip_cache=True)
    accepted = _accept(fallback)
    if accepted is not None:
        return accepted[0], accepted[1], accepted[2], "http11"
    message = _failure(fallback) or _failure(direct) or "fetch failed"
    if not force_live:
        cached = _cached_body(url)
        if cached:
            return cached, "stale", "served from cache after the live fetch failed", "stale"
    return None, "snapshot", message, "direct"


def _accept(result: tuple[str | None, str, str]) -> tuple[str, str, str] | None:
    text, warning, cache = result
    if not text or _parse_document(text, REQUIREMENTS_URL) is None:
        return None
    if warning:
        return text, "stale", warning
    return text, cache, ""


def _failure(result: tuple[str | None, str, str]) -> str:
    text, warning, _cache = result
    if text and _parse_document(text, HOME_URL) is None:
        return warning or "PSPF page was not usable"
    return warning


def _http(url: str, headers: dict, *, ttl: int, skip_cache: bool) -> tuple[str | None, str, str]:
    data_dir = _data_dir()
    client = HttpClient(
        "pspf",
        policy=EgressPolicy(_allowlist(), "pspf"),
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
    if response.status in {401, 403}:
        return (
            None,
            (
                f"www.protectivesecurity.gov.au refused the request ({response.status}). "
                "No credential environment variable is configured for this connector."
            ),
            response.cache,
        )
    if response.status >= 400:
        retry = ""
        if response.status == 429:
            retry = " after Retry-After"
        return None, f"upstream status {response.status}{retry}", response.cache
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return None, "PSPF page was not UTF-8", response.cache
    warning = "served from cache after the live fetch failed" if response.cache == "stale" else ""
    return text, warning, response.cache


def _payload_from_bodies(bodies: dict[str, str]) -> dict | None:
    requirements: list[dict] = []
    directions: list[dict] = []
    as_of = None
    for url, text in bodies.items():
        parsed = _parse_document(text, url)
        if parsed is None:
            return None
        as_of = as_of or parsed.get("as_of")
        requirements.extend(parsed["requirements"])
        directions.extend(parsed["directions"])
    return _dedupe({"as_of": as_of, "requirements": requirements, "directions": directions})


def _parse_document(text: str, url: str) -> dict | None:
    stripped = text.strip()
    if not stripped:
        return {"requirements": [], "directions": []}
    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        if schema_drift(payload):
            return None
        return _normalise(payload)
    try:
        return _parse_html(stripped, url)
    except Exception:
        return None


def _parse_html(text: str, url: str) -> dict:
    parser = _PageParser()
    parser.feed(text)
    parser.close()
    plain = _WS.sub(" ", " ".join(parser.parts)).strip()
    directions = _directions_from_text(plain, parser.links, url)
    requirements = []
    publication = _publication_from_text(plain, url)
    if publication is not None:
        requirements.append(publication)
    return {"requirements": requirements, "directions": directions}


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._skip = 0
        self._href: str | None = None
        self._link_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript"}:
            self._skip += 1
            return
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._href = href
                self._link_parts = []

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript"} and self._skip:
            self._skip -= 1
            return
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join(self._link_parts).strip()))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        text = data.strip()
        if not text:
            return
        self.parts.append(text)
        if self._href is not None:
            self._link_parts.append(text)


def _directions_from_text(plain: str, links: list[tuple[str, str]], page_url: str) -> list[dict]:
    found = []
    seen: set[str] = set()
    for match in _DIRECTION.finditer(plain):
        ident = match.group("id")
        if ident in seen:
            continue
        seen.add(ident)
        published = _iso_date(match.group("date"))
        title = _WS.sub(" ", match.group("title")).strip(" -")
        body = _WS.sub(" ", match.group("body")).strip()
        found.append(
            {
                "id": ident,
                "kind": "direction",
                "title": f"Direction {ident} on {title}",
                "url": _direction_url(ident, links, page_url),
                "published": published,
                "text": body,
            }
        )
    return found


def _publication_from_text(plain: str, url: str) -> dict | None:
    if not url.rstrip("/").endswith("pspf-page-2026"):
        return None
    if "PSPF" not in plain and "pspf" not in plain.lower():
        return None
    date_match = re.search(r"Publication date:\s+(\d{1,2}\s+[A-Za-z]+\s+\d{4})", plain)
    sentence = re.search(r"(The PSPF on a page [^.]{0,240}\.)", plain)
    return {
        "id": "pspf-page-2026",
        "kind": "publication",
        "title": "PSPF on a page 2026",
        "url": REQUIREMENTS_URL,
        "published": _iso_date(date_match.group(1)) if date_match else "2026-07-01",
        "text": sentence.group(1) if sentence else "",
    }


def _direction_url(ident: str, links: list[tuple[str, str]], page_url: str) -> str:
    for href, text in links:
        if ident not in href and ident not in text:
            continue
        absolute = urljoin(page_url, href)
        if absolute.startswith("https://www.protectivesecurity.gov.au/"):
            return absolute
    if page_url.startswith("https://www.protectivesecurity.gov.au/"):
        return page_url
    return HOME_URL


def _normalise(payload: dict) -> dict:
    directions = []
    for row in payload.get("directions") or []:
        if isinstance(row, dict) and row.get("id") and row.get("title"):
            directions.append(_record(row, "direction"))
    requirements = []
    for row in payload.get("requirements") or []:
        if isinstance(row, dict) and row.get("id") and row.get("title"):
            requirements.append(_record(row, str(row.get("kind") or "publication")))
    return {
        "as_of": payload.get("as_of"),
        "requirements": requirements,
        "directions": directions,
    }


def _record(row: dict, kind: str) -> dict:
    published = row.get("published")
    return {
        "id": str(row["id"]),
        "kind": kind if kind in {"publication", "direction"} else "publication",
        "title": str(row.get("title") or ""),
        "url": str(row.get("url") or HOME_URL),
        "published": None if published in (None, "") else str(published),
        "text": str(row.get("text") or ""),
    }


def _dedupe(payload: dict) -> dict:
    requirements = []
    directions = []
    seen_requirements: set[str] = set()
    seen_directions: set[str] = set()
    for row in payload["requirements"]:
        if row["id"] in seen_requirements:
            continue
        seen_requirements.add(row["id"])
        requirements.append(row)
    for row in payload["directions"]:
        if row["id"] in seen_directions:
            continue
        seen_directions.add(row["id"])
        directions.append(row)
    payload["requirements"] = requirements
    payload["directions"] = directions
    return payload


def _has_content(payload: dict) -> bool:
    return bool(payload["requirements"] or payload["directions"])


def _fill_gaps(payload: dict) -> tuple[dict, list[str]]:
    shipped = _shipped()
    notes: list[str] = []
    if shipped is None:
        return payload, notes
    if not payload["directions"]:
        payload["directions"] = shipped["directions"]
        notes.append("directions served from the shipped snapshot")
    if not payload["requirements"]:
        payload["requirements"] = shipped["requirements"]
        notes.append("requirements served from the shipped snapshot")
    return payload, notes


def _public(row: dict) -> dict:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "title": _wrap(row.get("title") or ""),
        "url": row.get("url") or HOME_URL,
        "published": row.get("published"),
        "text": _wrap(row.get("text") or ""),
    }


def _wrap(value: str) -> str:
    if not value:
        return ""
    return untrusted_text(value, "pspf")


def _response_problem(payload: dict) -> str | None:
    schema = json.loads(
        (_PACKAGE / "schema" / "pspf_search.response.json").read_text(encoding="utf-8")
    )
    required = schema.get("required") or []
    allowed = ((schema.get("properties") or {}).get("kind") or {}).get("enum") or []
    for row in [*payload.get("requirements", []), *payload.get("directions", [])][:1]:
        public = _public(row)
        missing = [name for name in required if name not in public]
        if missing:
            return "PSPF response schema, missing " + ", ".join(missing)
        if allowed and public.get("kind") not in allowed:
            return "PSPF response schema, kind"
    return None


def _persist(payload: dict) -> None:
    rows = [*payload.get("requirements", []), *payload.get("directions", [])]
    if not rows:
        return
    fetched = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _db() as conn:
        for row in rows:
            conn.execute(
                """
                INSERT INTO records (id, kind, title, url, published, text, fetched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    kind=excluded.kind,
                    title=excluded.title,
                    url=excluded.url,
                    published=excluded.published,
                    text=excluded.text,
                    fetched_at=excluded.fetched_at
                """,
                (
                    row["id"],
                    row["kind"],
                    row["title"],
                    row["url"],
                    row.get("published"),
                    row.get("text") or "",
                    fetched,
                ),
            )


def _search_store(needle: str) -> list[dict]:
    if not _has_records():
        return []
    like = f"%{_like(needle)}%"
    with _db() as conn:
        found = conn.execute(
            """
            SELECT * FROM records
            WHERE lower(id) LIKE ? ESCAPE '\\'
               OR lower(title) LIKE ? ESCAPE '\\'
               OR lower(text) LIKE ? ESCAPE '\\'
               OR lower(url) LIKE ? ESCAPE '\\'
            ORDER BY coalesce(published, '') DESC, id DESC
            """,
            (like, like, like, like),
        ).fetchall()
    return [dict(row) for row in found]


def _like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _has_records() -> bool:
    if not (_data_dir() / "pspf.sqlite").is_file():
        return False
    with _db() as conn:
        row = conn.execute("SELECT 1 FROM records LIMIT 1").fetchone()
    return row is not None


def _payload_from_store() -> dict:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM records ORDER BY coalesce(published, '') DESC, id DESC"
        ).fetchall()
    requirements = []
    directions = []
    for row in rows:
        item = dict(row)
        if item["kind"] == "direction":
            directions.append(item)
        else:
            requirements.append(item)
    return {"as_of": None, "requirements": requirements, "directions": directions}


def _shipped() -> dict | None:
    path = _PACKAGE / "data" / "snapshot.json"
    payload = _read_json(path)
    if payload is None or schema_drift(payload):
        return None
    return _normalise(payload)


def _load_snapshot_file() -> dict | None:
    override = os.environ.get("CYBERAU_PSPF_SNAPSHOT")
    path = Path(override) if override else _PACKAGE / "data" / "snapshot.json"
    return _read_json(path)


def _read_json(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


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


def _iso_date(value: str) -> str | None:
    match = re.fullmatch(r"(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})", value.strip())
    if match is None:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value.strip()):
            return value.strip()
        return None
    month = _MONTHS.get(match.group(2).lower())
    if month is None:
        return None
    return f"{int(match.group(3)):04d}-{month:02d}-{int(match.group(1)):02d}"


def _as_of(payload: dict) -> str | None:
    if payload.get("as_of"):
        return str(payload["as_of"])
    dates = [
        row["published"]
        for row in [*payload.get("requirements", []), *payload.get("directions", [])]
        if row.get("published")
    ]
    return max(dates) if dates else None


def _limit(key: str) -> None:
    RateLimiter(_data_dir() / "rate_limit.sqlite", sleeper=_SLEEP).acquire(
        key,
        rate=2 / _WEEK,
        burst=2,
        window="rolling",
        timeout=1.0,
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


def _envelope(data, cache: str, data_as_of: str | None = None, warnings=()):
    return envelope(
        "pspf",
        data,
        urls=[REQUIREMENTS_URL, HOME_URL],
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-pspf"))
    path.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def _db():
    conn = sqlite3.connect(_data_dir() / "pspf.sqlite")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS records (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            published TEXT,
            text TEXT NOT NULL,
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


register_connector("pspf", connector)
