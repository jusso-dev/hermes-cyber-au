"""Read-only Flashpoint Ignite indicators.

The credential sightings search is not implemented. On 17 October 2026 the
docs portal redirected to an Ignite sign-in page, so that path was not
confirmed. This module calls only the indicators collection that returned
401 without a token.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Annotated

from cyberau_common import USER_AGENT
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Probe, ToolSpec, register_connector
from cyberau_premium.base import ExposureFinding, PremiumConnector, Watchlist
from cyberau_premium.caching import cache_for_terms
from cyberau_premium.catalog import get_vendor
from cyberau_premium.redact import redact_text
from pydantic import Field

# Confirmed on 17 October 2026: 401 {"message":"Unauthorized"} with no token.
# The portal did not show query parameters, so none are sent.
INDICATORS_URL = "https://api.flashpoint.io/technical-intelligence/v2/indicators"
# Flashpoint has not published a limit. This ceiling is ours.
_RATE = 0.5
_BURST = 2
_SESSION_TTL = 900
_LIST_KEYS = ("items", "indicators", "data", "results")
_HISTORY_FIELDS = ("value", "type", "source_ref", "first_seen", "last_seen", "score")
_PACKAGE = Path(__file__).resolve().parents[2]
_TOOL_DESCRIPTION = (
    "Indicator context for one value from Flashpoint Ignite. "
    "Commercial licence: session cache, metadata only, no STIX export, "
    "no sharing outside the profile. Read only."
)

_TRANSPORT = None
_SLEEPER = None
_RNG = None
_RESOLVER = None
_CACHES: dict[str, object] = {}


def flashpoint_indicator(value: Annotated[str, Field(min_length=3)]) -> dict:
    if not isinstance(value, str) or len(value.strip()) < 3:
        return _envelope([], "snapshot", warnings=("value must be at least 3 characters",))
    payload, cache, warning = _fetch()
    if warning:
        return _envelope([], cache, warnings=(warning,))
    if payload is None:
        return _envelope([], cache, warnings=("Flashpoint indicator response was not usable",))
    problem = schema_drift(payload)
    if problem:
        return _envelope([], cache, warnings=(problem,))
    rows = _match(payload, value.strip())
    warnings: list[str] = []
    if not rows:
        warnings.append(
            "No indicator with that value was in the response. "
            "The docs portal did not confirm a value filter, so none is sent."
        )
    _persist(rows)
    notice = _notice(cache)
    if notice:
        warnings.insert(0, notice)
    return _envelope(rows, cache, warnings=tuple(warnings))


def schema_drift(payload: dict) -> str | None:
    records = _records(payload)
    if records is None:
        return "Flashpoint indicator payload has no indicator list"
    if not records:
        return None
    first = records[0]
    if not isinstance(first, dict):
        return "Flashpoint indicator entries are not objects"
    missing = [name for name in _required_fields() if name not in first]
    if missing:
        return "Flashpoint indicator schema drift, missing " + ", ".join(missing)
    return None


@dataclass
class FlashpointConnector(PremiumConnector):
    def exposure_for(self, watchlist: Watchlist, since: date) -> list[ExposureFinding]:
        """Return no findings.

        Compromised-credential search is not called. The docs portal did not
        confirm that path, and the indicator collection is not an exposure search.
        """
        return []

    def health(self, *, live: bool = False, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            if not os.environ.get("CYBERAU_FLASHPOINT_SNAPSHOT"):
                return Probe(self.key, True, "schema ok, no local copy to check")
            try:
                payload = _load(_snapshot_text())
            except OSError:
                payload = None
            problem = schema_drift(payload or {})
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        result = self.health_result(live=False)
        if not result.configured:
            if live:
                return Probe(self.key, False, "FLASHPOINT_API_TOKEN is not set")
            return Probe(self.key, result.ok, result.detail)
        if not live:
            return Probe(self.key, True, "offline ok")
        try:
            payload, cache, warning = _fetch(force_live=True)
        except HttpError as exc:
            return Probe(self.key, False, str(exc))
        if warning:
            return Probe(self.key, False, warning)
        if cache != "miss":
            return Probe(self.key, False, f"live check was answered from a {cache} copy")
        problem = schema_drift(payload or {})
        if problem:
            return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def connector() -> FlashpointConnector:
    spec = get_vendor("flashpoint")
    return FlashpointConnector(
        key="flashpoint",
        server_name="flashpoint",
        attribution=spec.terms.attribution,
        vendor=spec.server,
        licence_env=tuple(spec.licence_env),
        terms=spec.terms,
        quota=spec.quota,
        tools=[
            ToolSpec(
                "flashpoint_indicator",
                _TOOL_DESCRIPTION,
                flashpoint_indicator,
            )
        ],
    )


def _fetch(*, force_live: bool = False) -> tuple[dict | None, str, str]:
    snapshot_env = os.environ.get("CYBERAU_FLASHPOINT_SNAPSHOT")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    cache = _cache()
    token = lookup("FLASHPOINT_API_TOKEN")
    key = cache.key("GET", INDICATORS_URL, None, b"", _scope(token))
    if not force_live:
        cached = cache.get(key)
        if cached and (offline or cache.fresh(cached)):
            payload = _decode(cached.body)
            state = "hit" if cache.fresh(cached) else "stale"
            return payload, state, ""
    if snapshot_env and not force_live:
        try:
            payload = _load(_snapshot_text())
        except OSError:
            payload = None
        if payload is None:
            return None, "snapshot", "Flashpoint snapshot was not usable"
        return payload, "snapshot", ""
    if offline:
        return None, "snapshot", "Flashpoint is unavailable: offline mode and no cached copy"
    if token is None:
        return None, "snapshot", "FLASHPOINT_API_TOKEN is not set"
    client = _client(cache)
    try:
        response = client.get(
            INDICATORS_URL,
            headers={"authorization": f"Bearer {token}"},
            ttl=_SESSION_TTL,
            skip_cache=force_live,
        )
    except (HttpError, EgressDenied, TimeoutError) as exc:
        cached = None if force_live else cache.get(key)
        if cached:
            return _decode(cached.body), "stale", ""
        return None, "snapshot", redact(str(exc))
    finally:
        client.close()
    if response.status in {401, 403}:
        return (
            None,
            response.cache,
            f"Flashpoint returned {response.status}. Check FLASHPOINT_API_TOKEN.",
        )
    if response.status >= 400:
        return None, response.cache, f"Flashpoint returned status {response.status}"
    return _decode(response.body), response.cache, ""


def _match(payload: dict, value: str) -> list[dict]:
    wanted = value.casefold()
    rows = []
    for item in _records(payload) or []:
        if not isinstance(item, dict):
            continue
        raw = item.get("value")
        if not isinstance(raw, str) or raw.casefold() != wanted:
            continue
        rows.append(_record(item))
    return rows


def _record(item: dict) -> dict:
    row: dict[str, str] = {"value": item["value"]}
    kind = item.get("type")
    if isinstance(kind, str) and kind:
        row["type"] = kind
    ref = item.get("id")
    if isinstance(ref, str) and ref:
        row["source_ref"] = ref
    for name in ("first_seen", "last_seen"):
        stamp = item.get(name)
        if isinstance(stamp, str) and stamp:
            row[name] = stamp
    score = item.get("score")
    if isinstance(score, str) and score:
        row["score"] = score
    elif isinstance(score, (int, float)) and not isinstance(score, bool):
        row["score"] = str(score)
    summary = item.get("summary")
    if isinstance(summary, str) and summary.strip():
        row["summary"] = untrusted_text(redact_text(summary), "flashpoint")
    return row


def _records(payload: dict) -> list | None:
    if not isinstance(payload, dict):
        return None
    for name in _LIST_KEYS:
        found = payload.get(name)
        if isinstance(found, list):
            return found
    for found in payload.values():
        if isinstance(found, list):
            return found
    return None


def _persist(rows: list[dict]) -> None:
    if not rows:
        return
    directory = _data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "flashpoint-indicators.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            kept = {
                name: redact_text(row[name])
                for name in _HISTORY_FIELDS
                if isinstance(row.get(name), str)
            }
            handle.write(json.dumps(kept, sort_keys=True) + "\n")


def _cache():
    directory = str(_data_dir())
    cached = _CACHES.get(directory)
    if cached is not None:
        return cached
    created = cache_for_terms(
        Path(directory) / "http_cache.sqlite",
        get_vendor("flashpoint").terms,
    )
    _CACHES[directory] = created
    return created


def _client(cache) -> HttpClient:
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    kwargs = {}
    if _RESOLVER is not None:
        kwargs["resolver"] = _RESOLVER
    return HttpClient(
        "flashpoint",
        policy=EgressPolicy(allowlist, "flashpoint", **kwargs),
        cache=cache,
        limiter=RateLimiter(_data_dir() / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=_RATE,
        burst=_BURST,
        window="rolling",
        auth_scope=_scope(lookup("FLASHPOINT_API_TOKEN")),
        transport=_TRANSPORT,
        sleeper=_SLEEPER,
        rng=_RNG,
    )


def _scope(token: str | None) -> str:
    if not token:
        return "anonymous"
    return hashlib.sha256(token.encode()).hexdigest()


def _snapshot_text() -> str:
    return Path(os.environ["CYBERAU_FLASHPOINT_SNAPSHOT"]).read_text(encoding="utf-8")


def _required_fields() -> tuple[str, ...]:
    path = _PACKAGE / "schema" / "flashpoint_indicator.response.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    return tuple(str(item) for item in document.get("required") or ())


def _decode(body: bytes) -> dict | None:
    try:
        return _load(body.decode("utf-8"))
    except UnicodeDecodeError:
        return None


def _load(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _notice(cache: str) -> str:
    """Say so when the rows did not come from a fresh live response."""
    if cache == "snapshot":
        return "Served from a local snapshot file. This is not a live Flashpoint result."
    if cache == "stale":
        return "Stale result: an expired session copy, because Flashpoint could not be reached."
    return ""


def _envelope(
    data,
    cache: str,
    warnings: tuple[str, ...] = (),
) -> dict:
    stamps = [
        row["last_seen"]
        for row in data
        if isinstance(row, dict) and isinstance(row.get("last_seen"), str)
    ]
    as_of = max(stamps) if stamps else None
    return envelope(
        "flashpoint",
        data,
        urls=[INDICATORS_URL],
        cache=cache,
        data_as_of=as_of,
        warnings=warnings,
        attribution=get_vendor("flashpoint").terms.attribution,
    )


def _data_dir() -> Path:
    raw = os.environ.get("CYBERAU_DATA_DIR")
    if raw:
        return Path(raw)
    return Path("/tmp") / "cyberau-flashpoint"


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("flashpoint", connector)
