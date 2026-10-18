"""Read-only DarkOwl Vision search.

Result text is hostile. Snippets are capped and wrapped, and result links are never requested.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import unicodedata
from datetime import UTC, date, datetime, time
from email.utils import formatdate
from pathlib import Path
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from cyberau_common import USER_AGENT
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Probe, ToolSpec, register_connector
from cyberau_premium.base import (
    ExposureFinding,
    PremiumConnector,
    Subject,
    Watchlist,
    canonical_finding,
    clamp_to_terms,
    finding_id,
)
from cyberau_premium.caching import cache_for_terms
from cyberau_premium.catalog import get_vendor
from cyberau_premium.paths import data_dir
from cyberau_premium.redact import redact_text
from cyberau_premium.store import ExposureStore

ORIGIN = "https://api.darkowl.com"
SEARCH_PATH = "/api/v1/search"
TEST_PATH = "/api/v1/test"
SEARCH_URL = ORIGIN + SEARCH_PATH
_SESSION_TTL = 3600
_RATE = 1.0
_BURST = 2
_SNIPPET_MAX = 400
_TERM_MAX = 200
_NOT_CONFIGURED = "DarkOwl is not configured. Set DARKOWL_PUBLIC_KEY and DARKOWL_PRIVATE_KEY."
_UNAVAILABLE = "unavailable: offline and no cached DarkOwl result"
_SNAPSHOT_WARNING = (
    "Served from a local snapshot file, not a live DarkOwl result. "
    "It is not stored and does not feed exposure findings."
)
_MISSING_KEYS = "not configured: set DARKOWL_PUBLIC_KEY and DARKOWL_PRIVATE_KEY"
_SYDNEY = ZoneInfo("Australia/Sydney")
_PACKAGE = Path(__file__).resolve().parents[2]
_ALLOWLIST = _PACKAGE.parent / "egress-allowlist.yaml"
_DEFAULT_FIXTURE = _PACKAGE / "tests" / "fixtures" / "search_synthetic.json"
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)
_UNSAFE = re.compile(r"[&=\r\n?#]|[\x00-\x1f\x7f]")
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,40}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_LINK = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]{1,15}://\S+"
    r"|\b(?:magnet|mailto|data|javascript):\S+"
    r"|\bwww\.\S+"
    r"|\b(?:[a-z0-9-]+\.)+onion\b(?:/\S*)?"
)
_INVISIBLE = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5"
    "\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]"
)
_FENCE = re.compile(r"<<|>>")
_OWL_AUTH = re.compile(r"(?i)\bOWL\s+\S+")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_TRANSPORT = None
_SLEEPER = None
_RNG = None
_RESOLVER = None
_CACHES: dict = {}

logger = logging.getLogger("cyberau.darkowl")


def sign_request(method: str, path: str, when: str, public_key: str, private_key: str) -> str:
    """HMAC-SHA1 of method, decoded path and query, and the UTC Date header value."""
    material = f"{method}{path}{when}".encode()
    digest = hmac.new(private_key.encode(), material, hashlib.sha1).digest()
    signature = base64.b64encode(digest).decode()
    return f"OWL {public_key}:{signature}"


def schema_drift(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return "DarkOwl payload is not an object"
    missing = [name for name in ("results", "total") if name not in payload]
    if missing:
        return "DarkOwl schema drift, missing " + ", ".join(missing)
    results = payload.get("results")
    if not isinstance(results, list):
        return "DarkOwl payload results is not a list"
    if not results:
        return None
    item = results[0]
    if not isinstance(item, dict):
        return "DarkOwl schema drift, result is not an object"
    missing = [name for name in ("id", "crawlDate") if name not in item]
    if missing:
        return "DarkOwl schema drift, missing " + ", ".join(missing)
    return None


def darkowl_search_watchlist(terms: list[str], since: str | None = None) -> dict:
    logger.info("darkowl search")
    kept, problems = _validate_terms(terms, since)
    if problems and not kept:
        return _envelope([], "snapshot", problems)
    records, state, warnings = _collect(kept, since, _watchlist_for(kept))
    return _envelope(records, state, [*problems, *warnings])


def connector() -> PremiumConnector:
    return _DarkOwlConnector()


class _DarkOwlConnector(PremiumConnector):
    def __init__(self) -> None:
        spec = get_vendor("darkowl")
        super().__init__(
            key="darkowl",
            server_name="darkowl",
            attribution=spec.terms.attribution,
            tools=[
                ToolSpec(
                    "darkowl_search_watchlist",
                    "Search for watchlist names, brands and domains; returns hit "
                    "counts, first and last seen dates and source types.",
                    darkowl_search_watchlist,
                )
            ],
            vendor=spec.server,
            licence_env=tuple(spec.licence_env),
            terms=spec.terms,
            quota=spec.quota,
        )

    def exposure_for(self, watchlist: Watchlist, since: date) -> list[ExposureFinding]:
        terms = _terms_from(watchlist)
        records, _state, _warnings = _collect(terms, since.isoformat(), watchlist)
        findings = []
        for record in records:
            finding = record.get("finding")
            if isinstance(finding, ExposureFinding):
                findings.append(finding)
        return findings

    def health(self, *, live: bool = False, check_schema: bool = False) -> Probe:
        if check_schema:
            problem = _schema_problem()
            if problem:
                return Probe(self.key, False, problem)
            if not live:
                return Probe(self.key, True, "schema ok")
        if not live:
            result = self.health_result(live=False)
            return Probe(self.key, result.ok, result.detail)
        logger.info("darkowl health")
        if not self.health_result(live=False).configured:
            return Probe(self.key, False, _MISSING_KEYS)
        payload, _state, warning = _fetch_test()
        if warning:
            return Probe(self.key, False, warning)
        if not _is_hoot(payload):
            return Probe(self.key, False, "live probe did not return the test acknowledgement")
        return Probe(self.key, True, "live ok")


def _collect(
    terms: list[str],
    since: str | None,
    watchlist: Watchlist,
) -> tuple[list[dict], str, list[str]]:
    if not terms:
        return [], "snapshot", []
    if _snapshot_set():
        payload, problem = _read_snapshot()
        if problem or payload is None:
            return [], "snapshot", [problem or "DarkOwl snapshot was not usable"]
        return (
            _records(terms, payload, None, watchlist, store=False),
            "snapshot",
            [_SNAPSHOT_WARNING],
        )
    if lookup("DARKOWL_PUBLIC_KEY") is None or lookup("DARKOWL_PRIVATE_KEY") is None:
        return [], "snapshot", [_NOT_CONFIGURED]
    records: list[dict] = []
    states: list[str] = []
    warnings: list[str] = []
    for term in terms:
        payload, state, warning = _fetch_search(term, since, count=20, sort="d", detail="snippet")
        states.append(state)
        if warning or payload is None:
            warnings.append(warning or "DarkOwl payload was not usable")
            continue
        oldest = None
        shown = payload.get("results")
        total = payload.get("total")
        if isinstance(total, int) and isinstance(shown, list) and shown and total > len(shown):
            oldest, oldest_state, oldest_warning = _fetch_search(
                term, since, count=1, sort="-d", detail="nonbody"
            )
            states.append(oldest_state)
            if oldest_warning:
                warnings.append(oldest_warning)
                oldest = None
        records.extend(_records([term], payload, oldest, watchlist))
    return records, _combine(states), _dedupe(warnings)


def _records(
    terms: list[str],
    payload: dict,
    oldest: dict | None,
    watchlist: Watchlist,
    *,
    store: bool = True,
) -> list[dict]:
    records = []
    for term in terms:
        public, finding = _normalise(term, payload, oldest, watchlist)
        if finding is not None and store:
            _store(finding, watchlist)
            public["finding_id"] = finding.finding_id
            public["finding"] = finding
        records.append(public)
    return records


def _normalise(
    term: str,
    payload: dict,
    oldest: dict | None,
    watchlist: Watchlist,
) -> tuple[dict, ExposureFinding | None]:
    primary = _result_items(payload)
    extra = _result_items(oldest) if oldest else []
    dates: list[datetime] = []
    types: list[str] = []
    refs: list[str] = []
    for item in [*primary, *extra]:
        parsed = _parse_time(item.get("crawlDate"))
        if parsed is not None:
            dates.append(parsed)
        types.extend(_tokens(item.get("groups")))
        network = item.get("network")
        if isinstance(network, str):
            types.extend(_tokens([network]))
        ref = item.get("id")
        if isinstance(ref, str) and _REF.fullmatch(ref):
            refs.append(ref)
    title = None
    snippet = None
    for item in primary:
        if title is None:
            title = _hostile(item.get("title"))
        if snippet is None:
            snippet = _hostile(item.get("snippet"))
    total = payload.get("total")
    hit_count = 0
    if isinstance(total, int) and not isinstance(total, bool) and total >= 0:
        hit_count = total
    first = min(dates) if dates else None
    last = max(dates) if dates else None
    public = {
        "term": term,
        "subject_type": _subject_type(term, watchlist),
        "hit_count": hit_count,
        "first_seen": None if first is None else _iso(first),
        "last_seen": None if last is None else _iso(last),
        "source_types": _dedupe(types),
        "source_refs": _dedupe(refs),
    }
    if title:
        public["title"] = title
    if snippet:
        public["snippet"] = snippet
    if hit_count <= 0:
        return public, None
    source_ref = refs[0] if refs else None
    observed = last or datetime.now(UTC)
    kind = "dark_web_mention"
    finding = ExposureFinding(
        finding_id=finding_id("darkowl", kind, term, source_ref),
        vendor="darkowl",
        kind=kind,
        subject=Subject(type=public["subject_type"], value=term),
        observed_at=observed,
        first_seen=first or observed,
        licence_scope="store_metadata",
        confidence="vendor_reported",
        counts={"hits": hit_count},
        source_ref=source_ref,
        stix_exportable=False,
        contains_personal_information=False,
    )
    finding = clamp_to_terms(canonical_finding(finding), get_vendor("darkowl").terms)
    return public, finding


def _fetch_search(
    term: str,
    since: str | None,
    *,
    count: int,
    sort: str,
    detail: str,
) -> tuple[dict | None, str, str]:
    pairs = _pairs(_query_text(term), count=count, sort=sort, detail=detail, since=since)
    signed, url = _target(pairs)
    return _authorised("GET", signed, url, force_live=False)


def _fetch_test() -> tuple[dict | None, str, str]:
    return _authorised("GET", TEST_PATH, ORIGIN + TEST_PATH, force_live=True)


def _authorised(
    method: str,
    signed_path: str,
    url: str,
    *,
    force_live: bool,
) -> tuple[dict | None, str, str]:
    public = lookup("DARKOWL_PUBLIC_KEY")
    private = lookup("DARKOWL_PRIVATE_KEY")
    if not public or not private:
        return None, "snapshot", _NOT_CONFIGURED
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if offline:
        payload, state = _from_session(url, public)
        if payload is None:
            return None, "snapshot", _UNAVAILABLE
        problem = schema_drift(payload)
        if problem:
            return None, state, problem
        return payload, state, ""
    when = formatdate(usegmt=True)
    header = sign_request(method, signed_path, when, public, private)
    cache = _session_cache()
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_ALLOWLIST)))
    policy_kwargs = {} if _RESOLVER is None else {"resolver": _RESOLVER}
    client = HttpClient(
        "darkowl",
        policy=EgressPolicy(allowlist, "darkowl", **policy_kwargs),
        cache=cache,
        limiter=RateLimiter(data_dir() / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=_RATE,
        burst=_BURST,
        window="rolling",
        auth_scope=_scope(public),
        offline=False,
        timeout=30,
        transport=_TRANSPORT,
        sleeper=_SLEEPER,
        rng=_RNG,
    )
    try:
        try:
            response = client.get(
                url,
                headers={
                    "Date": when,
                    "Authorization": header,
                    "Accept": "application/json",
                },
                ttl=_SESSION_TTL,
                skip_cache=force_live,
            )
        except EgressDenied as exc:
            return None, "snapshot", f"egress refused: {exc}"
        except HttpError as exc:
            return None, "snapshot", _safe(str(exc))
    finally:
        client.close()
    if response.status in (401, 403):
        return (
            None,
            response.cache,
            (
                f"DarkOwl refused the request (HTTP {response.status}). "
                "Check DARKOWL_PUBLIC_KEY and DARKOWL_PRIVATE_KEY."
            ),
        )
    if response.status == 429:
        return None, response.cache, "DarkOwl rate limit reached. Retry after the server delay."
    if response.status >= 400:
        return None, response.cache, f"DarkOwl returned HTTP {response.status}"
    if response.status == 200 and signed_path == TEST_PATH:
        payload = _load_bytes(response.body)
        if payload is None:
            return None, response.cache, "DarkOwl payload was not usable"
        return payload, response.cache, ""
    payload = _load_bytes(response.body)
    if payload is None:
        return None, response.cache, "DarkOwl payload was not usable"
    problem = schema_drift(payload)
    if problem:
        return None, response.cache, problem
    return payload, response.cache, ""


def _store(finding: ExposureFinding, watchlist: Watchlist) -> None:
    try:
        ExposureStore(data_dir() / "intel.sqlite").write(
            finding,
            terms=get_vendor("darkowl").terms,
            watchlist=watchlist,
        )
    except Exception:
        logger.warning("darkowl finding was not stored")


def _from_session(url: str, public_key: str) -> tuple[dict | None, str]:
    cache = _session_cache()
    key = cache.key("GET", url, None, b"", _scope(public_key))
    item = cache.get(key)
    if item is None:
        return None, ""
    payload = _load_bytes(item.body)
    if payload is None:
        return None, ""
    state = "hit" if cache.fresh(item) else "stale"
    return payload, state


def _session_cache():
    path = data_dir() / "http_cache.sqlite"
    key = str(path)
    cache = _CACHES.get(key)
    if cache is None:
        cache = cache_for_terms(path, get_vendor("darkowl").terms)
        _CACHES[key] = cache
    return cache


def _pairs(
    query: str,
    *,
    count: int,
    sort: str,
    detail: str,
    since: str | None,
) -> list[tuple[str, str]]:
    pairs = [
        ("q", query),
        ("count", str(count)),
        ("offset", "0"),
        ("sort", sort),
        ("detail", detail),
        ("highlight", "false"),
    ]
    if since:
        pairs.append(("from", _from_zulu(since)))
    return pairs


def _target(pairs: list[tuple[str, str]]) -> tuple[str, str]:
    raw = "&".join(f"{key}={value}" for key, value in pairs)
    signed = f"{SEARCH_PATH}?{raw}"
    url = SEARCH_URL + "?" + urlencode(pairs)
    return signed, url


def _query_text(term: str) -> str:
    return '"' + term.replace('"', " ").replace("\\", " ").strip() + '"'


def _from_zulu(since: str) -> str:
    day = date.fromisoformat(since)
    start = datetime.combine(day, time.min, tzinfo=_SYDNEY)
    return start.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_terms(terms: list[str] | None, since: str | None) -> tuple[list[str], list[str]]:
    if since is not None and (not _DATE.fullmatch(since) or not _real_date(since)):
        return [], ["since must be YYYY-MM-DD in Australia/Sydney"]
    if not isinstance(terms, list) or not terms:
        return [], ["terms must list at least one value"]
    problems: list[str] = []
    incoming = terms
    if len(incoming) > 20:
        problems.append("terms is capped at 20")
        incoming = incoming[:20]
    kept = []
    for term in incoming:
        if not isinstance(term, str) or len(term.strip()) < 3:
            problems.append("a term was skipped because it is shorter than 3 characters")
            continue
        if len(term) > _TERM_MAX or _UNSAFE.search(term):
            problems.append("a term was skipped because it would make an ambiguous query")
            continue
        kept.append(term.strip())
    if not kept and not problems:
        problems.append("terms must list at least one value")
    return kept, problems


def _terms_from(watchlist: Watchlist) -> list[str]:
    excluded = {item.casefold() for item in watchlist.exclude}
    raw: list[str] = [
        *watchlist.domains,
        *watchlist.email_domains,
        *watchlist.brands,
    ]
    for item in watchlist.subsidiaries:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str):
            raw.append(name)
        for domain in item.get("domains") or []:
            if isinstance(domain, str):
                raw.append(domain)
    values: list[str] = []
    seen: set[str] = set()
    for item in raw:
        text = item.strip()
        key = text.casefold()
        if len(text) < 3 or len(text) > _TERM_MAX or key in excluded or key in seen:
            continue
        if _UNSAFE.search(text):
            continue
        seen.add(key)
        values.append(text)
    values.sort(key=str.casefold)
    return values[:20]


def _watchlist_for(terms: list[str]) -> Watchlist:
    domains = [term for term in terms if _DOMAIN.fullmatch(term)]
    brands = [term for term in terms if term not in domains]
    return Watchlist(domains=domains, brands=brands)


def _subject_type(term: str, watchlist: Watchlist) -> str:
    folded = term.casefold()
    if folded in {item.casefold() for item in watchlist.email_domains}:
        return "email_domain"
    if _DOMAIN.fullmatch(term) or folded in {item.casefold() for item in watchlist.domains}:
        return "domain"
    return "brand"


def _result_items(payload: dict | None) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    results = payload.get("results")
    if not isinstance(results, list):
        return []
    return [item for item in results if isinstance(item, dict)]


def _tokens(values) -> list[str]:
    if not isinstance(values, list):
        return []
    kept = []
    for value in values:
        if isinstance(value, str) and _TOKEN.fullmatch(value.casefold()):
            kept.append(value.casefold())
    return kept


def _hostile(value) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    flat = _INVISIBLE.sub("", unicodedata.normalize("NFKC", value))
    cleaned = redact_text(_LINK.sub("[link removed]", flat))
    cleaned = _FENCE.sub(" ", cleaned)
    return untrusted_text(cleaned, "darkowl", max_len=_SNIPPET_MAX)


def _parse_time(value) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scope(public_key: str) -> str:
    return hashlib.sha256(public_key.encode()).hexdigest()


def _safe(text: str) -> str:
    cleaned = _redact_keys(redact(text))
    folded = cleaned.casefold()
    if "offline and no cache" in folded:
        return _UNAVAILABLE
    if "timed out" in folded or "timeout" in folded:
        return "DarkOwl request timed out"
    return cleaned or "DarkOwl request failed"


def _redact_keys(text: str) -> str:
    text = _OWL_AUTH.sub("OWL [REDACTED]", text)
    for name in ("DARKOWL_PUBLIC_KEY", "DARKOWL_PRIVATE_KEY"):
        value = lookup(name)
        if value:
            text = text.replace(value, "[REDACTED]")
    return text


def _snapshot_set() -> bool:
    return bool(os.environ.get("CYBERAU_DARKOWL_SNAPSHOT"))


def _read_snapshot() -> tuple[dict | None, str]:
    payload = _load_path(Path(os.environ["CYBERAU_DARKOWL_SNAPSHOT"]))
    if payload is None:
        return None, "DarkOwl snapshot was not usable"
    problem = schema_drift(payload)
    if problem:
        return None, problem
    return payload, ""


def _schema_problem() -> str | None:
    raw = os.environ.get("CYBERAU_DARKOWL_SNAPSHOT")
    path = Path(raw) if raw else _DEFAULT_FIXTURE
    payload = _load_path(path)
    if payload is None:
        return "DarkOwl snapshot was not usable"
    return schema_drift(payload)


def _load_path(path: Path) -> dict | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    return _load_text(text)


def _load_bytes(body: bytes) -> dict | None:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return _load_text(text)


def _load_text(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _is_hoot(payload: dict | None) -> bool:
    if not isinstance(payload, dict):
        return False
    return '"hoot"' in json.dumps(payload).casefold()


def _real_date(value: str) -> bool:
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _combine(states: list[str]) -> str:
    if not states:
        return "snapshot"
    if "stale" in states:
        return "stale"
    if "miss" in states:
        return "miss"
    if "snapshot" in states:
        return "snapshot"
    return "hit"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    kept = []
    for value in values:
        if value not in seen:
            seen.add(value)
            kept.append(value)
    return kept


def _envelope(data, cache: str, warnings: list[str]) -> dict:
    public = []
    for item in data:
        if not isinstance(item, dict):
            public.append(item)
            continue
        public.append({key: value for key, value in item.items() if key != "finding"})
    return envelope(
        "darkowl",
        public,
        urls=[SEARCH_URL],
        cache=cache,
        warnings=_dedupe([_redact_keys(item) for item in warnings]),
        attribution=get_vendor("darkowl").terms.attribution,
    )


register_connector("darkowl", connector)
