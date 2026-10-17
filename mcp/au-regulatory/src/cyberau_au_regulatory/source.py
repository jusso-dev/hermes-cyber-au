"""Read-only Australian reporting obligations."""

import hashlib
import json
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

OAIC_QUICK = (
    "https://www.oaic.gov.au/privacy/notifiable-data-breaches/"
    "quick-reference-guide-for-responding-to-data-breaches"
)
OAIC_SCHEME = (
    "https://www.oaic.gov.au/privacy/notifiable-data-breaches/"
    "preventing-preparing-for-and-responding-to-data-breaches/"
    "data-breach-preparation-and-response/part-4-notifiable-data-breach-ndb-scheme"
)
CYBER_REPORT = "https://www.cyber.gov.au/report-a-cyber-security-incident"
CISC_PDF = "https://www.cisc.gov.au/resources-subsite/Documents/ncsi-guidance.pdf"
CSA_TEXT = "https://www.legislation.gov.au/C2024A00098/latest/text"
ATTRIBUTION = (
    "Quotes are from Commonwealth legislation on the Federal Register of Legislation. "
    "This is guidance, not legal advice, and it is not a substitute for reading the Act "
    "or getting legal advice. This connector is not endorsed by the OAIC, the Australian "
    "Signals Directorate, the Australian Cyber Security Centre or the Cyber and "
    "Infrastructure Security Centre."
)
REGIMES = ("ndb", "soci", "ransomware_payment")
_Regime = Literal["ndb", "soci", "ransomware_payment"]
_FIELDS = ("regime", "trigger", "rule", "quote", "source_url", "retrieved_at", "sha256")
_FROM_AWARENESS = {"awareness", "belief", "payment_or_awareness"}
_SYDNEY = ZoneInfo("Australia/Sydney")
_WEEK = 7 * 24 * 3600
_PACKAGE = Path(__file__).resolve().parents[2]
_PDF_TEXT = re.compile(rb"\((?:\\.|[^\\)])*\)")
_SOURCES = (
    {"url": OAIC_QUICK, "markers": ("30 days", "notifiable")},
    {"url": OAIC_SCHEME, "markers": ("as soon as practicable", "notifiable")},
    {"url": CYBER_REPORT, "markers": ("12 hours", "72 hours")},
    {"url": CISC_PDF, "markers": ("84 hours", "48 hours")},
    {"url": CSA_TEXT, "markers": ("72 hours", "ransomware")},
)
_TRANSPORT = None
_RESOLVER = None
_CLOCK = None


def aureg_obligation(
    regime: _Regime,
    trigger: Annotated[
        str | None,
        Field(description="For example 'critical_incident', 'other_incident', 'suspected_breach'"),
    ] = None,
) -> dict:
    problem = _regime_problem(regime)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    payload, cache, warning = _load()
    if warning:
        return _envelope([], cache, warnings=(warning,))
    wanted = _trigger(trigger)
    rows = _match(payload, regime, wanted)
    if not rows:
        note = (
            f"no matching obligation for trigger {wanted!r}"
            if wanted
            else f"no obligations for regime {regime}"
        )
        return _envelope([], cache, warnings=(note,))
    public = [_public_obligation(row) for row in rows]
    warnings = _warn_hashes(rows)
    stored = _persist(public)
    if stored:
        warnings.append(stored)
    return _envelope(public, cache, _urls(rows), _as_of(payload), tuple(warnings))


def aureg_deadline(regime: _Regime, trigger: str, aware_at: str) -> dict:
    warnings: list[str] = []
    problem = _regime_problem(regime)
    if problem:
        warnings.append(problem)
    wanted = _trigger(trigger)
    if not wanted:
        warnings.append("trigger is required")
    aware, aware_note = _parse_aware(aware_at)
    if aware is None:
        warnings.append(aware_note)
    elif aware_note:
        warnings.append(aware_note)
    if problem or not wanted or aware is None:
        return _envelope([], "snapshot", warnings=tuple(warnings))
    payload, cache, warning = _load()
    if warning:
        warnings.append(warning)
        return _envelope([], cache, warnings=tuple(warnings))
    rows = _match(payload, regime, wanted)
    if not rows:
        warnings.append(f"no matching obligation for trigger {wanted!r}")
        return _envelope([], cache, warnings=tuple(warnings))
    public = [_public_deadline(row, aware) for row in rows]
    warnings.extend(_warn_hashes(rows))
    stored = _persist(public)
    if stored:
        warnings.append(stored)
    return _envelope(public, cache, _urls(rows), _as_of(payload), tuple(warnings))


def refresh_sources(
    urls: list[str] | None = None,
    *,
    force: bool = False,
    ttl: int = _WEEK,
) -> dict:
    """Fetch the guidance pages used to confirm the shipped rules. Not an MCP tool."""
    chosen = list(_SOURCES)
    if urls is not None:
        wanted = set(urls)
        chosen = [item for item in _SOURCES if item["url"] in wanted]
        unknown = wanted - {item["url"] for item in chosen}
        if unknown and not chosen:
            return _envelope(
                [],
                "snapshot",
                warnings=tuple(f"url is not a known source: {item}" for item in sorted(unknown)),
            )
    rows = []
    warnings = []
    caches = []
    for item in chosen:
        text, cache, warning = _fetch_page(item["url"], force=force, ttl=ttl)
        caches.append(cache)
        if warning:
            warnings.append(warning)
            rows.append({"url": item["url"], "ok": False, "cache": cache})
            continue
        missing = _missing_markers(text or "", item["markers"])
        if missing:
            warnings.append("schema drift, missing " + ", ".join(missing) + f" at {item['url']}")
            rows.append({"url": item["url"], "ok": False, "cache": cache})
            continue
        rows.append({"url": item["url"], "ok": True, "cache": cache})
    state = "stale" if "stale" in caches else (caches[-1] if caches else "snapshot")
    return _envelope(rows, state, [item["url"] for item in chosen], warnings=tuple(warnings))


def connector() -> Connector:
    return _RegulatoryConnector()


class _RegulatoryConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="au-regulatory",
            server_name="aureg",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "aureg_obligation",
                    "Encoded reporting rule, deadline and source quote.",
                    aureg_obligation,
                ),
                ToolSpec(
                    "aureg_deadline",
                    "Deadlines in Australia/Sydney from an awareness time.",
                    aureg_deadline,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            payload, warning = _health_payload()
            if warning:
                return Probe(self.key, False, warning)
            problem = schema_drift(payload or {})
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        text, _cache, warning = _fetch_page(CSA_TEXT, force=True)
        if warning:
            return Probe(self.key, False, warning)
        missing = _missing_markers(text or "", ("72 hours", "ransomware"))
        if missing:
            return Probe(self.key, False, "live page missing " + ", ".join(missing))
        payload, read_warning = _health_payload()
        if read_warning:
            return Probe(self.key, False, read_warning)
        problem = schema_drift(payload or {})
        if problem:
            return Probe(self.key, False, problem)
        rows = (payload or {}).get("obligations") or []
        if not rows:
            return Probe(self.key, False, "live probe found no obligations")
        schema_problem = _response_problem(_public_obligation(rows[0]), "aureg_obligation")
        if schema_problem:
            return Probe(self.key, False, schema_problem)
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return "obligations payload is not an object"
    rows = payload.get("obligations")
    if not isinstance(rows, list):
        return "obligations schema drift, missing obligations"
    if not rows:
        return None
    row = rows[0]
    if not isinstance(row, dict):
        return "obligations schema drift, record is not an object"
    missing = [name for name in _FIELDS if name not in row]
    if missing:
        return "obligations schema drift, missing " + ", ".join(missing)
    return None


def _regime_problem(regime: str) -> str:
    if regime not in REGIMES:
        return "regime is not ndb, soci or ransomware_payment"
    return ""


def _trigger(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def _load() -> tuple[dict | None, str, str]:
    override = os.environ.get("CYBERAU_AUREG_SNAPSHOT", "").strip()
    if override:
        return _read(Path(override), "snapshot")
    if os.environ.get("CYBERAU_OFFLINE") == "1":
        current = _data_dir() / "obligations-current.json"
        if current.is_file():
            payload, _cache, warning = _read(current, "stale")
            if warning:
                shipped, shipped_cache, shipped_warning = _read(_snapshot_path(), "snapshot")
                note = warning if not shipped_warning else f"{warning}; {shipped_warning}"
                return shipped, shipped_cache, note
            return payload, "stale", ""
    return _read(_snapshot_path(), "snapshot")


def _read(path: Path, cache: str) -> tuple[dict | None, str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None, cache, "obligations snapshot is missing"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None, cache, "obligations payload was not usable"
    if not isinstance(payload, dict):
        return None, cache, "obligations payload was not usable"
    problem = schema_drift(payload)
    if problem:
        return payload, cache, problem
    return payload, cache, ""


def _health_payload() -> tuple[dict | None, str]:
    override = os.environ.get("CYBERAU_AUREG_SNAPSHOT", "").strip()
    path = Path(override) if override else _snapshot_path()
    payload, _cache, warning = _read(path, "snapshot")
    if warning and payload is not None and schema_drift(payload):
        return payload, ""
    return payload, warning


def _match(payload: dict | None, regime: str, trigger: str | None) -> list[dict]:
    rows = []
    for row in (payload or {}).get("obligations") or []:
        if not isinstance(row, dict) or row.get("regime") != regime:
            continue
        if trigger and row.get("trigger") != trigger:
            continue
        rows.append(row)
    return rows


def _public_obligation(row: dict) -> dict:
    quote = str(row.get("quote") or "")
    return {
        "regime": row.get("regime") or "",
        "trigger": row.get("trigger") or "",
        "rule": untrusted_text(str(row.get("rule") or ""), "aureg"),
        "citation": row.get("citation") or "",
        "quote": untrusted_text(quote, "aureg"),
        "source_url": row.get("source_url") or "",
        "guidance_url": row.get("guidance_url") or "",
        "retrieved_at": row.get("retrieved_at") or "",
        "sha256": hashlib.sha256(quote.encode()).hexdigest(),
        "deadlines": [_clock_view(item) for item in row.get("clocks") or []],
    }


def _public_deadline(row: dict, aware: datetime) -> dict:
    record = _public_obligation(row)
    record["aware_at"] = aware.isoformat(timespec="seconds")
    record["timezone"] = "Australia/Sydney"
    record["deadlines"] = [_due(item, aware) for item in row.get("clocks") or []]
    return record


def _clock_view(item: dict) -> dict:
    return {
        "name": item.get("name") or "",
        "from": item.get("from") or "",
        "hours": item.get("hours"),
        "days": item.get("days"),
        "basis": item.get("basis") or "",
    }


def _due(item: dict, aware: datetime) -> dict:
    origin = item.get("from") or ""
    due_at = None
    if origin in _FROM_AWARENESS:
        if item.get("days"):
            due_at = (aware + timedelta(days=int(item["days"]))).isoformat(timespec="seconds")
        elif item.get("hours"):
            due_at = (aware + timedelta(hours=int(item["hours"]))).isoformat(timespec="seconds")
    return {"name": item.get("name") or "", "due_at": due_at, "basis": item.get("basis") or ""}


def _parse_aware(value: str) -> tuple[datetime | None, str]:
    if not isinstance(value, str) or not value.strip():
        return None, "aware_at is not a date-time"
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None, "aware_at is not a date-time"
    if parsed.tzinfo is None:
        return (
            parsed.replace(tzinfo=_SYDNEY),
            "aware_at had no offset and was read as Australia/Sydney",
        )
    return parsed.astimezone(_SYDNEY), ""


def _warn_hashes(rows: list[dict]) -> list[str]:
    warnings = []
    for row in rows:
        quote = str(row.get("quote") or "")
        digest = hashlib.sha256(quote.encode()).hexdigest()
        stored = row.get("sha256")
        if stored and stored != digest:
            warnings.append("sha256 does not match the quoted sentence")
            break
    return warnings


def _persist(rows: list[dict]) -> str:
    if not rows:
        return ""
    try:
        path = _data_dir() / "aureg-obligations.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    except OSError as exc:
        return f"intel store was not updated: {exc}"
    return ""


def _fetch_page(url: str, *, force: bool, ttl: int = _WEEK) -> tuple[str | None, str, str]:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force
    data_dir = _data_dir()
    cache = HttpCache(data_dir / "http_cache.sqlite")
    key = cache.key("GET", url, None, b"", "anonymous")
    if offline:
        cached = cache.get(key)
        if cached is None:
            return None, "snapshot", f"offline and no cache for {url}"
        text, error = _page_text(cached.body, url)
        if error:
            return None, "stale", error
        state = "hit" if cache.fresh(cached) else "stale"
        return text, state, ""
    host = urlsplit(url).hostname or ""
    if not host:
        return None, "snapshot", "URL has no host"
    try:
        _limit(host)
        client = _client(cache)
        try:
            response = client.get(url, ttl=ttl, stale_if_error=_WEEK, skip_cache=force)
        finally:
            client.close()
    except (HttpError, EgressDenied, TimeoutError) as exc:
        if force:
            return None, "snapshot", redact(str(exc)) or "unavailable"
        cached = cache.get(key)
        if cached:
            text, error = _page_text(cached.body, url)
            if error:
                return None, "stale", error
            return text, "stale", ""
        return None, "snapshot", redact(str(exc)) or "unavailable"
    if response.status in (401, 403):
        return (
            None,
            response.cache,
            (
                f"upstream returned {response.status}. "
                "This connector does not send a credential; no env var is required."
            ),
        )
    if response.status >= 400:
        return None, response.cache, f"upstream status {response.status}"
    text, error = _page_text(response.body, url)
    if error:
        return None, response.cache, error
    return text, response.cache, ""


def _page_text(body: bytes, url: str) -> tuple[str | None, str]:
    if url.lower().endswith(".pdf") or body.startswith(b"%PDF"):
        if not body.startswith(b"%PDF"):
            return None, "pdf payload was not usable"
        parts = []
        for match in _PDF_TEXT.findall(body):
            parts.append(match[1:-1].decode("latin-1"))
        if not parts:
            return None, "pdf payload was not usable"
        return " ".join(parts), ""
    try:
        return body.decode("utf-8"), ""
    except UnicodeDecodeError:
        return None, "upstream payload was not usable"


def _missing_markers(text: str, markers: tuple[str, ...]) -> list[str]:
    folded = text.lower()
    return [item for item in markers if item.lower() not in folded]


def _limit(host: str) -> None:
    # Binding ceiling: one fetch every five seconds. Regeneration is weekly.
    RateLimiter(
        _data_dir() / "rate_limit.sqlite",
        clock=_clock(),
        sleeper=_sleeper(),
    ).acquire(
        f"au-regulatory:refresh:{host}",
        rate=1 / 5,
        burst=1,
        window="rolling",
        timeout=60,
    )


def _client(cache: HttpCache) -> HttpClient:
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    policy = EgressPolicy(allowlist, "au-regulatory", resolver=_RESOLVER)
    return HttpClient(
        "au-regulatory",
        policy=policy,
        cache=cache,
        limiter=RateLimiter(
            _data_dir() / "rate_limit.sqlite",
            clock=_clock(),
            sleeper=_sleeper(),
        ),
        user_agent=USER_AGENT,
        rate=1 / 5,
        burst=1,
        window="rolling",
        timeout=60,
        retries=3,
        transport=_TRANSPORT,
        sleeper=_sleeper(),
    )


def _clock():
    if _CLOCK is None:
        return time.monotonic
    return _CLOCK


def _sleeper():
    if _CLOCK is None:
        return time.sleep
    return _CLOCK.sleep


def _response_problem(record: dict, name: str) -> str | None:
    path = _PACKAGE / "schema" / f"{name}.response.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(record, schema)
    except jsonschema.ValidationError as exc:
        return exc.message
    return None


def _urls(rows: list[dict]) -> list[str]:
    found = []
    for row in rows:
        for key in ("source_url", "guidance_url"):
            value = row.get(key) or ""
            if value and value not in found:
                found.append(value)
    return found


def _as_of(payload: dict | None) -> str | None:
    if not payload:
        return None
    value = payload.get("retrieved_at")
    return str(value) if value else None


def _envelope(data, cache: str, urls=None, data_as_of: str | None = None, warnings=()):
    if isinstance(urls, str):
        urls = [urls]
    return envelope(
        "au-regulatory",
        data,
        urls=list(urls or []),
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _snapshot_path() -> Path:
    return _PACKAGE / "data" / "obligations-2026-10-17.json"


def _data_dir() -> Path:
    raw = os.environ.get("CYBERAU_DATA_DIR", "").strip()
    path = Path(raw) if raw else Path("/tmp/cyberau-aureg")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("au-regulatory", connector)
