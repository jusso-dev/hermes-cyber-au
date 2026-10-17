"""Read-only TAXII 2.1 client for a user-supplied API root.

ASD CTIS works when the user brings an API root and credentials from onboarding.
The connector does not ship a host, a collection id, or a secret, and it never
writes to the upstream server.
"""

import base64
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimited, RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

TERMS = (
    "CTIS content is covered by the ASD Network Partner deed. "
    "It must not be copied into a public repository, a shared log, or an export "
    "without a TLP check."
)
DOCTOR_NOTE = "off by default: licence terms"
ATTRIBUTION = TERMS + " This connector is not endorsed by ASD."
WINDOW_WARNING = (
    "added_after is older than 30 days. CTIS guidance is to poll indicators at most a month old."
)
UNAVAILABLE = "TAXII is unavailable. There is no cached or snapshot copy."
POLL_LIMIT = "TAXII poll limit reached. Stay at or under one poll an hour."
PAGE_LIMIT = "TAXII page limit reached for this hour."
ACCEPT = "application/taxii+json;version=2.1"
REQUIRED_ENV = (
    "TAXII_API_ROOT",
    "TAXII_COLLECTION_ID",
    "TAXII_USERNAME",
    "TAXII_PASSWORD",
)
# One poll an hour, matching the Sentinel CTIS guide, with room for 20 pages in that poll.
POLL_RATE = 1 / 3600
POLL_BURST = 1
PAGE_RATE = 20 / 3600
PAGE_BURST = 20
PAGE_CAP = 20
COLLECTION_TTL = 24 * 3600
OBJECT_TTL = 3600
_EXTERNAL_MAX = 1
_RANK = {"CLEAR": 0, "GREEN": 1, "AMBER": 2, "AMBER+STRICT": 3, "RED": 4}
# Public OASIS ids. TLP 2.0 is from cti-stix-common-objects. TLP 1.0 is from STIX 2.1.
_TLP_IDS = {
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": "CLEAR",
    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": "GREEN",
    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421": "AMBER",
    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003": "AMBER+STRICT",
    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1": "RED",
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "CLEAR",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "AMBER",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "RED",
}
_PACKAGE = Path(__file__).resolve().parents[2]
_COLLECTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ADDED_AFTER = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_TYPE_NAME = re.compile(r"^[a-z0-9-]{1,64}$")
_LABEL = re.compile(r"^[A-Za-z0-9:+._-]{1,64}$")
_QUOTED = re.compile(r"=\s*'([^']*)'")
_TRANSPORT = None
_RESOLVER = None
_SLEEP = time.sleep
_Limit = Annotated[int, Field(ge=1, le=1000)]
_AddedAfter = Annotated[str, Field(pattern=_ADDED_AFTER.pattern)]
_Indicator = Annotated[str, Field(min_length=3)]


def taxii_list_collections() -> dict:
    """Collections the configured credentials can read."""
    try:
        rows, cache, warning, urls = _list_collections(force_live=False)
    except sqlite3.Error:
        return _envelope([], "snapshot", warnings=("TAXII store could not be read.",))
    warnings = (warning,) if warning else ()
    return _envelope(rows, cache, warnings=warnings, urls=urls)


def taxii_get_objects(
    added_after: _AddedAfter | None = None,
    types: list[str] | None = None,
    limit: _Limit = 100,
) -> dict:
    """Page through STIX objects with added_after and type filters."""
    problem = _validate_objects(added_after, types, limit)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    warnings: list[str] = []
    if added_after and _older_than_month(added_after):
        warnings.append(WINDOW_WARNING)
    try:
        rows, cache, warning, urls, as_of = _gather_objects(
            added_after, _clean_types(types), limit, force_live=False
        )
    except sqlite3.Error:
        return _envelope([], "snapshot", warnings=("TAXII store could not be read.",))
    if warning:
        warnings.append(warning)
    return _envelope(rows, cache, warnings=tuple(warnings), urls=urls, data_as_of=as_of)


def taxii_lookup_indicator(value: _Indicator) -> dict:
    """Find stored indicators matching an IP, domain, URL or hash."""
    problem = _validate_value(value)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    try:
        cache, warning = _ensure_stored()
        local = bool(os.environ.get("CYBERAU_TAXII_SNAPSHOT")) or _offline()
        if warning and _missing_env() and not local:
            return _envelope([], "snapshot", warnings=(warning,))
        rows, extra = _search(value.strip())
    except sqlite3.Error:
        return _envelope([], "snapshot", warnings=("TAXII store could not be read.",))
    warnings = [item for item in (warning, extra) if item]
    as_of = _as_of(rows)
    return _envelope(rows, cache, warnings=tuple(warnings), data_as_of=as_of)


def taxii_sync_status() -> dict:
    """Last sync time, object counts and errors per collection."""
    try:
        rows = _sync_rows()
    except sqlite3.Error:
        return _envelope([], "snapshot", warnings=("TAXII store could not be read.",))
    if not rows:
        return _envelope([], "snapshot", warnings=("No TAXII sync has run yet.",))
    return _envelope(rows, "snapshot")


def profile_enabled(*, default_enabled: bool, user_enabled: bool | None) -> bool:
    """A fresh install uses the catalogue default. A profile update keeps an explicit choice."""
    if user_enabled is None:
        return default_enabled
    return user_enabled


def export_stix(*, override: bool = False) -> dict:
    """STIX bundle for use outside the profile. TLP:AMBER and above stay out unless overridden."""
    chosen = _selected(override=override)
    raw = [item[0] for item in chosen]
    digest = uuid.uuid5(uuid.NAMESPACE_URL, "taxii-ctis:" + ",".join(item["id"] for item in raw))
    return {"type": "bundle", "id": f"bundle--{digest}", "objects": raw}


def briefing_records(*, override: bool = False) -> dict:
    """Normalised records safe to send outside the profile."""
    records = [item[1] for item in _selected(override=override)]
    warnings: list[str] = []
    if override:
        warnings.append("TLP override applied for this run. AMBER and above are included.")
    return {"records": records, "warnings": warnings}


def connector() -> Connector:
    return _TaxiiConnector()


class _TaxiiConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="taxii-ctis",
            server_name="taxii",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "taxii_list_collections",
                    "Collections the configured credentials can read.",
                    taxii_list_collections,
                ),
                ToolSpec(
                    "taxii_get_objects",
                    "Page through STIX objects with added_after and type filters.",
                    taxii_get_objects,
                ),
                ToolSpec(
                    "taxii_lookup_indicator",
                    "Find stored indicators matching an IP, domain, URL or hash.",
                    taxii_lookup_indicator,
                ),
                ToolSpec(
                    "taxii_sync_status",
                    "Last sync time, object counts and errors per collection.",
                    taxii_sync_status,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if not live:
            if check_schema:
                return _schema_probe(self.key)
            return Probe(self.key, True, "offline ok")
        missing = _missing_env()
        if missing:
            return Probe(self.key, False, missing)
        try:
            rows, _cache, warning, _urls = _list_collections(force_live=True)
        except sqlite3.Error:
            return Probe(self.key, False, "TAXII store could not be read.")
        if warning:
            return Probe(self.key, False, warning)
        problem = _validate_records("taxii_list_collections", rows)
        if problem:
            return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict, *, kind: str) -> str | None:
    if kind == "collections":
        rows = payload.get("collections")
        if not isinstance(rows, list):
            return "TAXII payload has no collections list"
        for row in rows:
            if not isinstance(row, dict) or "id" not in row:
                return "TAXII schema drift, missing id"
        return None
    if kind == "objects":
        rows = payload.get("objects")
        if not isinstance(rows, list):
            return "TAXII payload has no objects list"
        for row in rows:
            if not isinstance(row, dict) or "id" not in row or "type" not in row:
                return "TAXII schema drift, missing id"
        return None
    return None


def _list_collections(*, force_live: bool) -> tuple[list[dict], str, str, list[str]]:
    if not force_live and os.environ.get("CYBERAU_TAXII_SNAPSHOT"):
        return _collections_from_payload(*_snapshot_payload("collections.json", "collections"), [])
    if not force_live and _offline():
        url = _offline_collections_url()
        if url:
            payload, state = _cached_payload(url, {})
            if payload is not None:
                return _collections_from_payload(payload, state, "", [url])
        return _collections_from_payload(*_snapshot_payload("collections.json", "collections"), [])
    missing = _missing_env()
    if missing:
        return [], "snapshot", missing, []
    root, problem, spent = _resolve_root(force_live=force_live)
    if problem:
        return [], "snapshot", problem, []
    url = _collections_url(root)
    payload, cache, warning = _http_json(
        url,
        {},
        ttl=COLLECTION_TTL,
        poll=not spent,
        force_live=force_live,
        kind="collections",
    )
    if warning or payload is None:
        return [], cache, warning or UNAVAILABLE, [url]
    problem = schema_drift(payload, kind="collections")
    if problem:
        return [], cache, problem, [url]
    rows = _collection_rows(payload)
    _save_collections(rows)
    return rows, cache, "", [url]


def _gather_objects(
    added_after: str | None,
    types: list[str] | None,
    limit: int,
    *,
    force_live: bool,
) -> tuple[list[dict], str, str, list[str], str | None]:
    if not force_live and (os.environ.get("CYBERAU_TAXII_SNAPSHOT") or _offline()):
        if os.environ.get("CYBERAU_TAXII_SNAPSHOT"):
            payload, cache, warning = _snapshot_payload("objects.json", "objects")
            urls: list[str] = []
        else:
            payload, cache, warning, urls = _offline_objects()
        if warning or payload is None:
            return [], cache, warning or UNAVAILABLE, urls, None
        problem = schema_drift(payload, kind="objects")
        if problem:
            return [], cache, problem, urls, None
        raw = [item for item in payload.get("objects") or [] if isinstance(item, dict)]
        _persist_objects(raw)
        rows = [_normalise(item) for item in raw if _keep(item, added_after, types)]
        extra = ""
        if payload.get("more"):
            extra = "TAXII snapshot ended before the server's next page."
        note = " ".join(part for part in (warning, extra) if part)
        return rows[:limit], cache, note, urls, _as_of(rows[:limit])
    missing = _missing_env()
    if missing:
        return [], "snapshot", missing, [], None
    collection = lookup("TAXII_COLLECTION_ID")
    problem = _collection_problem(collection)
    if problem:
        return [], "snapshot", problem, [], None
    root, problem, spent = _resolve_root(force_live=force_live)
    if problem:
        return [], "snapshot", problem, [], None
    url = _objects_url(root, collection or "")
    raw, cache, warning, _saw_more = _page_objects(
        url,
        added_after=added_after,
        types=types,
        limit=limit,
        poll=not spent,
        force_live=force_live,
    )
    if warning and not raw:
        _note_error(collection or "unconfigured", warning)
        return [], cache, warning, [url], None
    _persist_objects(raw)
    rows = [_normalise(item) for item in raw if _keep(item, added_after, types)]
    return rows[:limit], cache, warning, [url], _as_of(rows[:limit])


def _page_objects(
    url: str,
    *,
    added_after: str | None,
    types: list[str] | None,
    limit: int,
    poll: bool,
    force_live: bool,
) -> tuple[list[dict], str, str, bool]:
    params: dict[str, str] = {"limit": str(limit)}
    if added_after:
        params["added_after"] = added_after
    if types:
        params["match[type]"] = ",".join(types)
    collected: list[dict] = []
    caches: list[str] = []
    seen: set[str] = set()
    warning = ""
    saw_more = False
    for index in range(PAGE_CAP):
        payload, cache, problem = _http_json(
            url,
            params,
            ttl=OBJECT_TTL,
            poll=poll and index == 0,
            force_live=force_live,
            kind="objects",
        )
        caches.append(cache)
        if problem or payload is None:
            return collected, _merge_cache(caches), problem or UNAVAILABLE, saw_more
        drift = schema_drift(payload, kind="objects")
        if drift:
            return [], _merge_cache(caches), drift, saw_more
        for item in payload.get("objects") or []:
            if isinstance(item, dict):
                collected.append(item)
        kept = [item for item in collected if _keep(item, added_after, types)]
        if len(kept) >= limit or not payload.get("more"):
            return collected, _merge_cache(caches), "", bool(payload.get("more"))
        saw_more = True
        token = payload.get("next")
        if not isinstance(token, str) or not token or token in seen:
            warning = "TAXII page said more but sent no usable next token."
            break
        seen.add(token)
        params = {"limit": str(max(1, limit)), "next": token}
    else:
        warning = "TAXII page cap reached for this poll."
    return collected, _merge_cache(caches), warning, saw_more


def _ensure_stored() -> tuple[str, str]:
    if os.environ.get("CYBERAU_TAXII_SNAPSHOT") or _offline():
        _rows, cache, warning, _urls, _stamp = _gather_objects(None, None, 1000, force_live=False)
        return cache, warning
    missing = _missing_env()
    if missing:
        return "snapshot", missing
    if _object_count() > 0:
        return "hit", ""
    start = (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _rows, cache, warning, _urls, _stamp = _gather_objects(
        start, ["indicator"], 1000, force_live=False
    )
    return cache, warning


def _resolve_root(*, force_live: bool) -> tuple[str, str, bool]:
    configured = lookup("TAXII_API_ROOT")
    if not configured:
        return "", "Set TAXII_API_ROOT.", False
    problem = _validate_root(configured)
    if problem:
        return "", problem, False
    if not _is_discovery(configured):
        return _normal_root(configured), "", False
    payload, _cache, warning = _http_json(
        _normal_root(configured),
        {},
        ttl=COLLECTION_TTL,
        poll=True,
        force_live=force_live,
        kind="discovery",
    )
    if warning or payload is None:
        return "", warning or UNAVAILABLE, True
    if not isinstance(payload.get("api_roots"), list):
        return "", "TAXII discovery payload has no api_roots list.", True
    chosen = _choose_root(payload)
    if not chosen:
        return "", "TAXII discovery did not list an allowlisted API root.", True
    return chosen, "", True


def _choose_root(payload: dict) -> str:
    candidates: list[str] = []
    default = payload.get("default")
    if isinstance(default, str):
        candidates.append(default)
    roots = payload.get("api_roots")
    if isinstance(roots, list):
        candidates.extend(item for item in roots if isinstance(item, str))
    for candidate in candidates:
        if _validate_root(candidate):
            continue
        if _allowed(candidate):
            return _normal_root(candidate)
    return ""


def _http_json(
    url: str,
    params: dict[str, str],
    *,
    ttl: int,
    poll: bool,
    force_live: bool,
    kind: str,
) -> tuple[dict | None, str, str]:
    if not force_live and os.environ.get("CYBERAU_TAXII_SNAPSHOT"):
        return _snapshot_payload(_snapshot_name(kind), kind if kind != "discovery" else "")
    if not force_live and _offline():
        payload, state = _cached_payload(url, params)
        if payload is not None:
            return payload, state, ""
        filename = _snapshot_name(kind)
        if (_PACKAGE / "data" / filename).is_file():
            return _snapshot_payload(filename, kind if kind != "discovery" else "")
        return None, "snapshot", UNAVAILABLE
    missing = _missing_env()
    if missing:
        return None, "snapshot", missing
    limited = _take(poll=poll, host=_host(url))
    if limited:
        return None, "snapshot", limited
    cache = _cache()
    client = HttpClient(
        "taxii-ctis",
        policy=_policy(),
        cache=cache,
        limiter=RateLimiter(_data_dir() / "rate_limit.sqlite", sleeper=_SLEEP),
        user_agent=USER_AGENT,
        rate=10,
        burst=30,
        window="rolling",
        timeout=60,
        auth_scope=_auth_scope(),
        transport=_TRANSPORT,
        sleeper=_SLEEP,
    )
    headers = {"Accept": ACCEPT, "Authorization": _basic_header()}
    try:
        try:
            response = client.get(
                url,
                params=params or None,
                headers=headers,
                ttl=ttl,
                skip_cache=force_live,
            )
        except EgressDenied as exc:
            return None, "snapshot", _scrub(str(exc))
        except (HttpError, TimeoutError, RateLimited):
            payload, state = _cached_payload(url, params)
            if payload is not None:
                return payload, "stale", ""
            return None, "snapshot", UNAVAILABLE
    finally:
        client.close()
    if response.status in (401, 403):
        return None, "snapshot", _auth_failure(response.status)
    if response.status >= 400:
        payload, state = _cached_payload(url, params)
        if payload is not None and not force_live:
            return payload, "stale", ""
        return None, "snapshot", f"TAXII request failed (HTTP {response.status})."
    payload, problem = _parse_bytes(response.body)
    if problem:
        return None, response.cache, problem
    return payload, response.cache, ""


def _snapshot_payload(filename: str, kind: str) -> tuple[dict | None, str, str]:
    path = _snapshot_dir() / filename
    if not path.is_file():
        return None, "snapshot", UNAVAILABLE
    payload, problem = _read_json(path)
    if problem or payload is None:
        return None, "snapshot", problem or UNAVAILABLE
    if kind:
        drift = schema_drift(payload, kind=kind)
        if drift:
            return None, "snapshot", drift
    return payload, "snapshot", ""


def _schema_probe(key: str) -> Probe:
    folder = _snapshot_dir()
    for filename, kind in (("collections.json", "collections"), ("objects.json", "objects")):
        path = folder / filename
        if not path.is_file():
            return Probe(key, False, f"snapshot {filename} is missing")
        payload, problem = _read_json(path)
        if problem or payload is None:
            return Probe(key, False, problem or UNAVAILABLE)
        drift = schema_drift(payload, kind=kind)
        if drift:
            return Probe(key, False, drift)
    return Probe(key, True, "schema ok")


def _collection_rows(payload: dict) -> list[dict]:
    rows = []
    for item in payload.get("collections") or []:
        if not isinstance(item, dict) or item.get("can_read") is not True:
            continue
        media = item.get("media_types") if isinstance(item.get("media_types"), list) else []
        rows.append(
            {
                "id": str(item.get("id") or ""),
                "title": _text(str(item.get("title") or "")),
                "description": _text(str(item.get("description") or "")),
                "can_read": True,
                "can_write": item.get("can_write") is True,
                "media_types": [str(value) for value in media],
            }
        )
    return rows


def _normalise(obj: dict) -> dict:
    pattern = str(obj.get("pattern") or "")
    return {
        "id": str(obj.get("id") or ""),
        "type": str(obj.get("type") or ""),
        "name": _text(str(obj.get("name") or "")),
        "description": _text(str(obj.get("description") or "")),
        "pattern": _text(pattern) if pattern else "",
        "valid_from": _stamp(obj.get("valid_from")),
        "valid_until": _stamp(obj.get("valid_until")),
        "created": _stamp(obj.get("created")),
        "modified": _stamp(obj.get("modified")),
        "tlp": _tlp(obj),
        "revoked": obj.get("revoked") is True,
        "expired": _expired(obj),
        "labels": _labels(obj),
        "values": [{"kind": kind, "value": value} for kind, value in _indicator_values(pattern)],
        "source_ref": str(obj.get("source_ref") or ""),
        "target_ref": str(obj.get("target_ref") or ""),
        "relationship_type": str(obj.get("relationship_type") or ""),
    }


def _keep(obj: dict, added_after: str | None, types: list[str] | None) -> bool:
    if types and str(obj.get("type") or "") not in types:
        return False
    if not added_after:
        return True
    stamp = _stamp(obj.get("modified")) or _stamp(obj.get("created"))
    if not stamp:
        return True
    return stamp >= added_after


def _tlp(obj: dict) -> str:
    found: list[str] = []
    refs = obj.get("object_marking_refs")
    if isinstance(refs, list):
        for ref in refs:
            mark = _TLP_IDS.get(str(ref))
            if mark:
                found.append(mark)
    for label in _labels(obj):
        mark = _from_text(label)
        if mark:
            found.append(mark)
    extensions = obj.get("extensions")
    if isinstance(extensions, dict):
        for value in extensions.values():
            if isinstance(value, dict) and "tlp_2_0" in value:
                mark = _from_text(str(value.get("tlp_2_0") or ""))
                if mark:
                    found.append(mark)
    definition = obj.get("definition")
    if isinstance(definition, dict) and "tlp" in definition:
        mark = _from_text(str(definition.get("tlp") or ""))
        if mark:
            found.append(mark)
    if not found:
        return "CLEAR"
    return max(found, key=lambda item: _RANK[item])


def _from_text(value: str) -> str | None:
    text = value.strip().lower().replace(" ", "").replace("_", "+")
    for prefix in ("tlp:", "tlp="):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    if text in {"clear", "white"}:
        return "CLEAR"
    if text == "green":
        return "GREEN"
    if text in {"amber+strict", "amberstrict"}:
        return "AMBER+STRICT"
    if text == "amber":
        return "AMBER"
    if text == "red":
        return "RED"
    return None


def _expired(obj: dict) -> bool:
    until = obj.get("valid_until")
    if not isinstance(until, str) or not until:
        return False
    try:
        parsed = datetime.fromisoformat(until.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed < datetime.now(UTC)


def _indicator_values(pattern: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in _QUOTED.finditer(pattern or ""):
        raw = match.group(1).strip()
        kind = _kind(raw)
        if not kind:
            continue
        key = raw.lower()
        if key in seen:
            continue
        seen.add(key)
        found.append((kind, raw))
    return found


def _kind(value: str) -> str | None:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}", value):
        return "hash"
    if re.fullmatch(
        r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
        value,
    ):
        return "domain"
    return None


def _labels(obj: dict) -> list[str]:
    labels = obj.get("labels")
    if not isinstance(labels, list):
        return []
    cleaned = []
    for item in labels:
        text = str(item)
        if _LABEL.fullmatch(text):
            cleaned.append(text)
        elif text:
            cleaned.append(_text(text))
    return cleaned


def _selected(*, override: bool) -> list[tuple[dict, dict]]:
    chosen = []
    for raw, normalised in _stored_pairs():
        rank = _RANK[_tlp(raw)]
        if override or rank <= _EXTERNAL_MAX:
            chosen.append((raw, normalised))
    chosen.sort(key=lambda item: str(item[0].get("id") or ""))
    return chosen


def _search(value: str) -> tuple[list[dict], str]:
    needle = value.lower()
    with _db() as conn:
        rows = conn.execute(
            """
            SELECT o.normalised
            FROM indicator_values AS v
            JOIN objects AS o ON o.id = v.object_id
            WHERE v.value = ? AND o.expired = 0 AND o.revoked = 0
            ORDER BY o.id
            """,
            (needle,),
        ).fetchall()
        if rows:
            return [json.loads(row[0]) for row in rows], ""
        flags = conn.execute(
            """
            SELECT o.expired, o.revoked
            FROM indicator_values AS v
            JOIN objects AS o ON o.id = v.object_id
            WHERE v.value = ?
            """,
            (needle,),
        ).fetchall()
    if any(flag[0] for flag in flags):
        return [], "The matching indicator is expired."
    if any(flag[1] for flag in flags):
        return [], "The matching indicator is revoked."
    return [], "No stored indicator matched."


def _persist_objects(raw_objects: list[dict]) -> None:
    collection = _active_collection()
    now = _now()
    with _db() as conn:
        for obj in raw_objects:
            if "id" not in obj or "type" not in obj:
                continue
            object_id = str(obj["id"])
            existing = conn.execute(
                "SELECT first_seen FROM objects WHERE id = ?",
                (object_id,),
            ).fetchone()
            first = existing[0] if existing else now
            normalised = _normalise(obj)
            conn.execute(
                """
                INSERT INTO objects (
                    id, collection_id, type, tlp, expired, revoked, modified,
                    raw, normalised, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    collection_id=excluded.collection_id,
                    type=excluded.type,
                    tlp=excluded.tlp,
                    expired=excluded.expired,
                    revoked=excluded.revoked,
                    modified=excluded.modified,
                    raw=excluded.raw,
                    normalised=excluded.normalised,
                    last_seen=excluded.last_seen
                """,
                (
                    object_id,
                    collection,
                    normalised["type"],
                    normalised["tlp"],
                    int(normalised["expired"]),
                    int(normalised["revoked"]),
                    normalised["modified"],
                    json.dumps(obj, sort_keys=True),
                    json.dumps(normalised, sort_keys=True),
                    first,
                    now,
                ),
            )
            conn.execute("DELETE FROM indicator_values WHERE object_id = ?", (object_id,))
            for item in normalised["values"]:
                conn.execute(
                    "INSERT INTO indicator_values (value, object_id) VALUES (?, ?)",
                    (item["value"].lower(), object_id),
                )
        count = conn.execute(
            "SELECT COUNT(*) FROM objects WHERE collection_id = ?",
            (collection,),
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO sync_status (collection_id, last_sync, object_count, error)
            VALUES (?, ?, ?, '')
            ON CONFLICT(collection_id) DO UPDATE SET
                last_sync=excluded.last_sync,
                object_count=excluded.object_count,
                error=''
            """,
            (collection, now, count),
        )


def _save_collections(rows: list[dict]) -> None:
    now = _now()
    with _db() as conn:
        for row in rows:
            conn.execute(
                """
                INSERT INTO collections (id, title, can_read, raw, fetched_at)
                VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title,
                    can_read=excluded.can_read,
                    raw=excluded.raw,
                    fetched_at=excluded.fetched_at
                """,
                (row["id"], row["title"], json.dumps(row, sort_keys=True), now),
            )


def _note_error(collection: str, message: str) -> None:
    if not collection:
        return
    with _db() as conn:
        conn.execute(
            """
            INSERT INTO sync_status (collection_id, last_sync, object_count, error)
            VALUES (?, NULL, 0, ?)
            ON CONFLICT(collection_id) DO UPDATE SET error=excluded.error
            """,
            (collection, message),
        )


def _sync_rows() -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            """
            SELECT collection_id, last_sync, object_count, error
            FROM sync_status
            ORDER BY collection_id
            """
        ).fetchall()
    return [
        {
            "collection_id": row[0],
            "last_sync": row[1],
            "object_count": row[2],
            "error": row[3] or "",
        }
        for row in rows
    ]


def _stored_pairs() -> list[tuple[dict, dict]]:
    with _db() as conn:
        rows = conn.execute("SELECT raw, normalised FROM objects ORDER BY id").fetchall()
    pairs = []
    for raw_text, normalised_text in rows:
        try:
            raw = json.loads(raw_text)
            normalised = json.loads(normalised_text)
        except json.JSONDecodeError:
            continue
        if isinstance(raw, dict) and isinstance(normalised, dict):
            pairs.append((raw, normalised))
    return pairs


def _object_count() -> int:
    with _db() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0])


def _take(*, poll: bool, host: str) -> str:
    limiter = RateLimiter(_data_dir() / "rate_limit.sqlite", sleeper=_SLEEP)
    if poll:
        try:
            limiter.acquire(
                f"taxii:poll:{host}",
                rate=POLL_RATE,
                burst=POLL_BURST,
                window="rolling",
                timeout=0,
            )
        except RateLimited:
            return POLL_LIMIT
    try:
        limiter.acquire(
            f"taxii:page:{host}",
            rate=PAGE_RATE,
            burst=PAGE_BURST,
            window="rolling",
            timeout=0,
        )
    except RateLimited:
        return PAGE_LIMIT
    return ""


def _cached_payload(url: str, params: dict[str, str]) -> tuple[dict | None, str]:
    cache = _cache()
    item = cache.get(cache.key("GET", url, params, b"", _auth_scope()))
    if item is None:
        return None, ""
    payload, problem = _parse_bytes(item.body)
    if problem or payload is None:
        return None, ""
    return payload, "hit" if cache.fresh(item) else "stale"


def _validate_objects(added_after: str | None, types: list[str] | None, limit: int) -> str:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        return "limit must be an integer from 1 to 1000."
    if added_after is not None and not _ADDED_AFTER.fullmatch(added_after):
        return "added_after must be an ISO-8601 date-time."
    if types is None:
        return ""
    if not isinstance(types, list):
        return "types must be a list of STIX type names."
    for name in types:
        if not isinstance(name, str) or not _TYPE_NAME.fullmatch(name.strip().lower()):
            return "types must be a list of STIX type names."
    return ""


def _validate_value(value: str) -> str:
    if not isinstance(value, str) or len(value.strip()) < 3:
        return "value must be at least 3 characters."
    return ""


def _clean_types(types: list[str] | None) -> list[str] | None:
    if not types:
        return None
    return [name.strip().lower() for name in types]


def _older_than_month(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed < datetime.now(UTC) - timedelta(days=30)


def _missing_env() -> str:
    missing = [name for name in REQUIRED_ENV if not lookup(name)]
    if not missing:
        return ""
    return "Set " + ", ".join(missing) + "."


def _collection_problem(value: str | None) -> str:
    if not value:
        return "Set TAXII_COLLECTION_ID."
    if not _COLLECTION_ID.fullmatch(value):
        return "TAXII_COLLECTION_ID must be a single path token."
    return ""


def _validate_root(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.username or parts.password:
        return "A TAXII URL must use https and must not include a password."
    if parts.scheme.lower() != "https" or not parts.hostname:
        return "A TAXII URL must use https and must not include a password."
    return ""


def _is_discovery(url: str) -> bool:
    path = urlsplit(url).path.rstrip("/")
    return path == "/taxii2" or path.endswith("/taxii2")


def _normal_root(url: str) -> str:
    return url.strip().rstrip("/") + "/"


def _collections_url(root: str) -> str:
    return _normal_root(root) + "collections/"


def _objects_url(root: str, collection: str) -> str:
    return _normal_root(root) + "collections/" + collection + "/objects/"


def _active_collection() -> str:
    value = lookup("TAXII_COLLECTION_ID")
    if value and _COLLECTION_ID.fullmatch(value):
        return value
    return "unconfigured"


def _collections_from_payload(
    payload: dict | None,
    cache: str,
    warning: str,
    urls: list[str],
) -> tuple[list[dict], str, str, list[str]]:
    if warning or payload is None:
        return [], cache, warning or UNAVAILABLE, urls
    problem = schema_drift(payload, kind="collections")
    if problem:
        return [], cache, problem, urls
    rows = _collection_rows(payload)
    _save_collections(rows)
    return rows, cache, "", urls


def _offline_collections_url() -> str:
    root = lookup("TAXII_API_ROOT")
    if not root or _validate_root(root) or _is_discovery(root):
        return ""
    return _collections_url(root)


def _offline_objects() -> tuple[dict | None, str, str, list[str]]:
    root = lookup("TAXII_API_ROOT")
    collection = lookup("TAXII_COLLECTION_ID")
    if root and collection and not _validate_root(root) and not _collection_problem(collection):
        url = _objects_url(root, collection)
        payload, state = _cached_payload(url, {})
        if payload is not None:
            return payload, state, "", [url]
    payload, cache, warning = _snapshot_payload("objects.json", "objects")
    return payload, cache, warning, []


def _offline() -> bool:
    return os.environ.get("CYBERAU_OFFLINE") == "1"


def _snapshot_dir() -> Path:
    override = os.environ.get("CYBERAU_TAXII_SNAPSHOT")
    if override:
        return Path(override)
    return _PACKAGE / "data"


def _snapshot_name(kind: str) -> str:
    if kind == "collections":
        return "collections.json"
    if kind == "discovery":
        return "discovery.json"
    return "objects.json"


def _allowed(url: str) -> bool:
    try:
        _policy().check(url)
    except EgressDenied:
        return False
    return True


def _policy() -> EgressPolicy:
    path = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    return EgressPolicy(path, "taxii-ctis", resolver=_RESOLVER)


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


def _cache() -> HttpCache:
    return HttpCache(_data_dir() / "http_cache.sqlite")


def _auth_scope() -> str:
    user = lookup("TAXII_USERNAME")
    if not user:
        return "anonymous"
    return hashlib.sha256(user.encode()).hexdigest()[:16]


def _basic_header() -> str:
    user = lookup("TAXII_USERNAME") or ""
    password = lookup("TAXII_PASSWORD") or ""
    token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
    return "Basic " + token


def _auth_failure(status: int) -> str:
    return f"TAXII authentication failed (HTTP {status}). Check TAXII_USERNAME and TAXII_PASSWORD."


def _scrub(message: str) -> str:
    cleaned = redact(message)
    password = lookup("TAXII_PASSWORD")
    if password and len(password) >= 8:
        cleaned = cleaned.replace(password, "[REDACTED]")
    header = _basic_header() if lookup("TAXII_USERNAME") and lookup("TAXII_PASSWORD") else ""
    if header and header in cleaned:
        cleaned = cleaned.replace(header, "Basic [REDACTED]")
    return cleaned


def _text(value: str) -> str:
    if not value:
        return ""
    return untrusted_text(value, "taxii")


def _stamp(value) -> str:
    if not isinstance(value, str):
        return ""
    return value


def _as_of(rows: list[dict]) -> str | None:
    stamps = [row["modified"] for row in rows if row.get("modified")]
    return max(stamps) if stamps else None


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-taxii"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _read_json(path: Path) -> tuple[dict | None, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None, UNAVAILABLE
    return _parse_text(text)


def _parse_bytes(body: bytes) -> tuple[dict | None, str]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None, "TAXII response was not valid JSON."
    return _parse_text(text)


def _parse_text(text: str) -> tuple[dict | None, str]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None, "TAXII response was not valid JSON."
    if not isinstance(payload, dict):
        return None, "TAXII response was not a JSON object."
    return payload, ""


def _validate_records(name: str, records: list[dict]) -> str:
    schema = json.loads((_PACKAGE / "schema" / f"{name}.response.json").read_text(encoding="utf-8"))
    try:
        for record in records:
            jsonschema.validate(record, schema)
    except jsonschema.ValidationError as exc:
        return "response schema: " + exc.message
    return ""


def _envelope(
    data,
    cache: str,
    warnings: tuple[str, ...] = (),
    urls: list[str] | None = None,
    data_as_of: str | None = None,
) -> dict:
    return envelope(
        "taxii-ctis",
        data,
        urls=urls or [],
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


@contextmanager
def _db():
    conn = sqlite3.connect(_data_dir() / "taxii_objects.sqlite")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS objects (
            id TEXT PRIMARY KEY,
            collection_id TEXT NOT NULL,
            type TEXT NOT NULL,
            tlp TEXT NOT NULL,
            expired INTEGER NOT NULL,
            revoked INTEGER NOT NULL,
            modified TEXT NOT NULL,
            raw TEXT NOT NULL,
            normalised TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS indicator_values (
            value TEXT NOT NULL,
            object_id TEXT NOT NULL,
            PRIMARY KEY (value, object_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sync_status (
            collection_id TEXT PRIMARY KEY,
            last_sync TEXT,
            object_count INTEGER NOT NULL,
            error TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS collections (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            can_read INTEGER NOT NULL,
            raw TEXT NOT NULL,
            fetched_at TEXT NOT NULL
        )
        """
    )
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


register_connector("taxii-ctis", connector)
