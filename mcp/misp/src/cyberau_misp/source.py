"""Read-only MISP connector for a user-supplied instance, including AusMISP.

The official MISP MCP server is pinned, not vendored. GitHub reports no licence
file for MISP/misp-mcp at the pinned commit.
"""

import hashlib
import ipaddress
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import jsonschema
import yaml
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimited, RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

PIN_REPO = "https://github.com/MISP/misp-mcp"
PIN_COMMIT = "3d033828a78b6b3cb2292b255c8d2ad093c1bee5"
PINNED_LAUNCHER = "misp-mcp"
READ_TOOLS = ("search_attributes", "get_event", "search_events")
TERMS = "MISP software is AGPL-3.0; feed terms vary per feed. Respect TLP and sharing groups."
ATTRIBUTION = f"{TERMS} Not affiliated with MISP or AusCERT."
DOCTOR_NOTE = "off by default: licence terms. See docs/connectors/misp.md."
RATE = 30 / 60
BURST = 30
TTL = 300

_PACKAGE = Path(__file__).resolve().parents[2]
_DEFAULT_SNAPSHOT = _PACKAGE / "tests" / "fixtures" / "event_three_attributes.json"
_SCHEMA = _PACKAGE / "schema"
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")
_EVENT_ID = re.compile(r"[A-Za-z0-9-]{1,64}")
_Limit = Annotated[int, Field(ge=1, le=100)]
_Days = Annotated[int, Field(ge=1, le=90)]
_EventId = Annotated[str, Field(pattern=r"^[A-Za-z0-9-]{1,64}$")]
_TLP_RANK = {
    "clear": 0,
    "white": 0,
    "green": 1,
    "amber": 2,
    "amber+strict": 3,
    "red": 4,
    "ex:chr": 4,
}
_RESTRICTED_RANK = 2
_LIMITED_DISTRIBUTION = {"0", "4"}
_TRANSPORT = None
_RESOLVER = None
_SLEEPER = None


def search_attributes(
    value: str | None = None,
    attribute_type: str | None = None,
    category: str | None = None,
    limit: _Limit = 50,
) -> dict:
    """Search attributes on the configured MISP or AusMISP instance."""
    problem = _check_bound(limit, 100, "limit")
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    payload, cache, warning = _fetch(
        "/attributes/restSearch",
        _attribute_body(value, attribute_type, category, limit),
    )
    urls = _urls("/attributes/restSearch")
    if warning:
        return _envelope([], cache, urls=urls, warnings=(warning,))
    rows, problem = _attributes_from(payload, value, attribute_type, category)
    if problem:
        return _envelope([], cache, urls=urls, warnings=(problem,))
    rows = rows[:limit]
    if cache != "snapshot":
        _persist(rows)
    warnings = ("no matching MISP records",) if not rows else _handling(rows)
    return _envelope(rows, cache, urls=urls, warnings=warnings)


def get_event(event_id: _EventId) -> dict:
    """One MISP event by id or uuid, including galaxies."""
    if not isinstance(event_id, str) or _EVENT_ID.fullmatch(event_id) is None:
        return _envelope(None, "snapshot", warnings=("event_id must be an id or uuid",))
    payload, cache, warning = _fetch("/events/restSearch", _event_body(event_id))
    urls = _urls("/events/restSearch")
    if warning:
        return _envelope(None, cache, urls=urls, warnings=(warning,))
    events, problem = _events_from(payload)
    if problem:
        return _envelope(None, cache, urls=urls, warnings=(problem,))
    chosen = [item for item in events if item["id"] == event_id or item["uuid"] == event_id]
    if not chosen:
        return _envelope(None, cache, urls=urls, warnings=("no matching MISP records",))
    event = chosen[0]
    if cache != "snapshot":
        _persist([event])
    return _envelope(event, cache, urls=urls, as_of=_as_of([event]), warnings=_handling([event]))


def search_events(days: _Days = 7, limit: _Limit = 20, published_only: bool = True) -> dict:
    """Recent MISP events, including galaxies."""
    problem = _check_bound(days, 90, "days") or _check_bound(limit, 100, "limit")
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    payload, cache, warning = _fetch(
        "/events/restSearch",
        _recent_body(limit, days, published_only),
    )
    urls = _urls("/events/restSearch")
    if warning:
        return _envelope([], cache, urls=urls, warnings=(warning,))
    events, problem = _events_from(payload)
    if problem:
        return _envelope([], cache, urls=urls, warnings=(problem,))
    if published_only:
        events = [item for item in events if item["published"]]
    events = events[:limit]
    if cache != "snapshot":
        _persist(events)
    warnings = ("no matching MISP records",) if not events else _handling(events)
    return _envelope(events, cache, urls=urls, as_of=_as_of(events), warnings=warnings)


def refuse_write(action: str) -> dict:
    """Writes are not part of this connector."""
    return _envelope(
        None,
        "snapshot",
        warnings=(
            f"MISP write ({action}) is excluded. This connector is read-only. "
            "Check MISP_API_KEY is a read-only key.",
        ),
    )


def render_mcp_server(*, profile_home: str, key_present: bool) -> dict:
    """Fresh bootstrap render. A present key does not enable the server."""
    del key_present
    home = profile_home.rstrip("/")
    return {
        "command": f"{home}/mcp/.venv/bin/cyberau-mcp",
        "args": ["serve", "misp"],
        "env": {
            "MISP_URL": "${MISP_URL}",
            "MISP_API_KEY": "${MISP_API_KEY}",
            "CYBERAU_DATA_DIR": f"{home}/plugin-data/cyber-au",
        },
        "tools": {"include": list(READ_TOOLS)},
        "enabled": False,
        "lazy": True,
        "trust": "untrusted",
        "upstream": {
            "repository": PIN_REPO,
            "commit": PIN_COMMIT,
            "launcher": PINNED_LAUNCHER,
            "vendored": False,
        },
    }


def apply_profile_update(current: dict | None, rendered: dict) -> dict:
    """Keep a user-owned enabled flag. Never copy a literal secret."""
    merged = {key: value for key, value in rendered.items() if key != "env"}
    merged["env"] = dict(rendered.get("env") or {})
    if isinstance(current, dict) and isinstance(current.get("enabled"), bool):
        merged["enabled"] = current["enabled"]
    if isinstance(current, dict) and isinstance(current.get("env"), dict):
        for name, value in current["env"].items():
            if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                merged["env"][name] = value
    return merged


def connector() -> Connector:
    return _MispConnector()


class _MispConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="misp",
            server_name="misp",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec("search_attributes", "Search MISP attributes.", search_attributes),
                ToolSpec("get_event", "One MISP event, including galaxies.", get_event),
                ToolSpec("search_events", "Recent MISP events, including galaxies.", search_events),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            text = _snapshot_text()
            payload = None if text is None else _load(text)
            if not payload:
                return Probe(self.key, False, "MISP snapshot was not usable")
            problem = schema_drift(payload)
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        probes = (
            ("/events/restSearch", _recent_body(1, 7, True), "search_events"),
            ("/attributes/restSearch", _attribute_body(None, None, None, 1), "search_attributes"),
        )
        for path, body, kind in probes:
            payload, cache, warning = _fetch(path, body, force_live=True)
            if warning:
                return Probe(self.key, False, warning)
            if cache != "miss":
                detail = f"MISP answer was served from cache ({cache}), not live"
                return Probe(self.key, False, detail)
            if payload is None:
                return Probe(self.key, False, "MISP payload was not usable")
            problem = schema_drift(payload)
            if problem:
                return Probe(self.key, False, problem)
            if kind == "search_events":
                records, problem = _events_from(payload)
            else:
                records, problem = _attributes_from(payload, None, None, None)
            if problem:
                return Probe(self.key, False, problem)
            problem = _check_response(kind, records)
            if problem:
                return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict) -> str | None:
    if not isinstance(payload, dict) or "response" not in payload:
        return "MISP payload has no response"
    events = _iter_events(payload)
    attributes = _iter_attributes(payload)
    if events is None or attributes is None:
        return "MISP payload has no response"
    for event in events:
        if "info" not in event:
            return "MISP schema drift, missing info"
    for attribute in attributes:
        if "type" not in attribute or "value" not in attribute:
            return "MISP schema drift, missing type or value"
    return None


def tool_request(server: str = "misp") -> None:
    """Budget for one tool call, keyed by server name."""
    RateLimiter(_data_dir() / "rate_limit.sqlite").acquire(
        server,
        rate=RATE,
        burst=BURST,
        window="rolling",
    )


def _fetch(path: str, body: dict, *, force_live: bool = False) -> tuple[dict | None, str, str]:
    if force_live:
        problem = _config_problem()
        if problem:
            return None, "snapshot", problem
        return _live(path, body, offline=False)
    if os.environ.get("CYBERAU_MISP_SNAPSHOT"):
        return _from_snapshot()
    offline = os.environ.get("CYBERAU_OFFLINE") == "1"
    if offline and _config_problem() == "":
        payload, cache, warning = _live(path, body, offline=True)
        if payload is None:
            return _from_snapshot()
        return payload, cache, warning
    if offline or (lookup("MISP_URL") is None and lookup("MISP_API_KEY") is None):
        return _from_snapshot()
    problem = _config_problem()
    if problem:
        return None, "snapshot", problem
    return _live(path, body, offline=False)


def _from_snapshot() -> tuple[dict | None, str, str]:
    text = _snapshot_text()
    if text is None:
        return None, "snapshot", "unavailable: no MISP snapshot or cache"
    payload = _load(text)
    if payload is None:
        return None, "snapshot", "MISP payload was not usable"
    warning = _document_warning(payload)
    if warning:
        return None, "snapshot", warning
    return payload, "snapshot", ""


def _config_problem() -> str:
    missing = []
    if lookup("MISP_URL") is None:
        missing.append("MISP_URL")
    if lookup("MISP_API_KEY") is None:
        missing.append("MISP_API_KEY")
    if missing:
        return "Set " + " and ".join(missing) + ". Use a read-only MISP_API_KEY."
    _base, problem = _parse_base(lookup("MISP_URL") or "")
    del _base
    return problem


def _live(path: str, body: dict, *, offline: bool) -> tuple[dict | None, str, str]:
    base, problem = _parse_base(lookup("MISP_URL") or "")
    secret = lookup("MISP_API_KEY")
    if problem or not base or not secret:
        return None, "snapshot", problem or "Set MISP_URL and MISP_API_KEY."
    try:
        tool_request("misp")
    except RateLimited:
        return None, "snapshot", "unavailable: MISP tool budget is exhausted for this profile"
    host = urlsplit(base).hostname or ""
    client = HttpClient(
        "misp",
        policy=EgressPolicy(_runtime_allowlist(host), "misp", resolver=_RESOLVER),
        cache=HttpCache(_data_dir() / "http_cache.sqlite"),
        limiter=RateLimiter(_data_dir() / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=RATE,
        burst=BURST,
        window="rolling",
        auth_scope="keyed",
        timeout=30,
        offline=offline,
        transport=_TRANSPORT,
        sleeper=_SLEEPER,
    )
    try:
        response = client.post_json(
            base + path,
            body,
            headers={"Authorization": secret, "Accept": "application/json"},
            ttl=TTL,
            cache_key_extra=_key_scope(secret),
        )
    except (HttpError, EgressDenied, TimeoutError, OSError) as exc:
        return None, "snapshot", _clean(exc, secret)
    finally:
        client.close()
    if response.status in (401, 403):
        return None, response.cache, _auth_message(response.status)
    if response.status == 429:
        return (
            None,
            response.cache,
            "MISP returned 429. Retry-After was honoured and the limit still held.",
        )
    if response.status >= 400:
        return None, response.cache, f"MISP returned HTTP {response.status}."
    payload = _load(response.body.decode("utf-8", errors="replace"))
    if payload is None:
        return None, response.cache, "MISP payload was not usable"
    warning = _document_warning(payload)
    if warning:
        return None, response.cache, warning
    return payload, response.cache, ""


def _attributes_from(payload, value, attribute_type, category) -> tuple[list[dict], str]:
    if payload is None:
        return [], "MISP payload was not usable"
    drift = schema_drift(payload)
    if drift:
        return [], drift
    rows = []
    seen: set[tuple[str, str, str]] = set()
    for raw, event_id in _loose_attributes(payload):
        raw_value = str(raw.get("value") or "")
        if value and value.lower() not in raw_value.lower():
            continue
        if attribute_type and str(raw.get("type") or "") != attribute_type:
            continue
        if category and str(raw.get("category") or "") != category:
            continue
        row = _normalise_attribute(raw, event_id)
        identity = (row["id"], row["type"], raw_value)
        if identity in seen:
            continue
        seen.add(identity)
        rows.append(row)
    return rows, ""


def _events_from(payload) -> tuple[list[dict], str]:
    if payload is None:
        return [], "MISP payload was not usable"
    drift = schema_drift(payload)
    if drift:
        return [], drift
    events = _iter_events(payload) or []
    return [_normalise_event(item) for item in events], ""


def _loose_attributes(payload: dict) -> list[tuple[dict, str]]:
    found: list[tuple[dict, str]] = []
    response = payload.get("response")
    if isinstance(response, dict):
        for item in response.get("Attribute") or []:
            if isinstance(item, dict) and "type" in item and "value" in item:
                found.append((item, str(item.get("event_id") or "")))
    for event in _iter_events(payload) or []:
        event_id = str(event.get("id") or "")
        for item in event.get("Attribute") or []:
            if isinstance(item, dict) and "type" in item and "value" in item:
                found.append((item, event_id))
    return found


def _iter_events(payload: dict) -> list[dict] | None:
    response = payload.get("response")
    if isinstance(response, list):
        found = []
        for item in response:
            if not isinstance(item, dict):
                return None
            event = item.get("Event", item)
            if not isinstance(event, dict):
                return None
            found.append(event)
        return found
    if isinstance(response, dict):
        event = response.get("Event")
        if isinstance(event, dict):
            return [event]
        if isinstance(event, list):
            if all(isinstance(item, dict) for item in event):
                return event
            return None
        if "Attribute" in response:
            return []
    return None


def _iter_attributes(payload: dict) -> list[dict] | None:
    events = _iter_events(payload)
    if events is None:
        return None
    found: list[dict] = []
    response = payload.get("response")
    if isinstance(response, dict) and "Attribute" in response:
        raw = response.get("Attribute")
        if not isinstance(raw, list):
            return None
        for item in raw:
            if not isinstance(item, dict):
                return None
            found.append(item)
    for event in events:
        raw = event.get("Attribute", [])
        if not isinstance(raw, list):
            return None
        for item in raw:
            if not isinstance(item, dict):
                return None
            found.append(item)
    return found


def _normalise_event(raw: dict) -> dict:
    tags = _tag_names(raw)
    org = ""
    orgc = raw.get("orgc")
    if isinstance(orgc, dict):
        org = str(orgc.get("name") or "")
    event_id = str(raw.get("id") or "")
    attributes = [
        _normalise_attribute(item, event_id)
        for item in raw.get("Attribute") or []
        if isinstance(item, dict) and "type" in item and "value" in item
    ]
    return {
        "id": event_id,
        "uuid": str(raw.get("uuid") or ""),
        "info": _text(raw.get("info")),
        "timestamp": str(raw.get("timestamp") or ""),
        "published": _published(raw.get("published")),
        "org": _text(org),
        "tlp": _most_restrictive([_tlp(tags), *(item["tlp"] for item in attributes)]),
        "distribution": str(raw.get("distribution") or ""),
        "sharing_group": _sharing_group(raw),
        "tags": [_text(tag) for tag in tags],
        "attributes": attributes,
        "galaxies": _galaxies(raw),
    }


def _normalise_attribute(raw: dict, event_id: str) -> dict:
    return {
        "id": str(raw.get("id") or ""),
        "event_id": str(raw.get("event_id") or event_id),
        "type": str(raw.get("type") or ""),
        "category": str(raw.get("category") or ""),
        "value": _text(raw.get("value")),
        "comment": _text(raw.get("comment")),
        "to_ids": _published(raw.get("to_ids")),
        "tlp": _tlp(_tag_names(raw)),
        "distribution": str(raw.get("distribution") or ""),
        "sharing_group": _sharing_group(raw),
    }


def _galaxies(raw: dict) -> list[dict]:
    galaxies = []
    for galaxy in raw.get("Galaxy") or []:
        if not isinstance(galaxy, dict):
            continue
        clusters = []
        for cluster in galaxy.get("GalaxyCluster") or []:
            if not isinstance(cluster, dict):
                continue
            clusters.append(
                {
                    "value": _text(cluster.get("value")),
                    "description": _text(cluster.get("description")),
                }
            )
        galaxies.append(
            {
                "name": str(galaxy.get("name") or ""),
                "type": str(galaxy.get("type") or ""),
                "clusters": clusters,
            }
        )
    return galaxies


def _tag_names(raw: dict) -> list[str]:
    names = []
    for tag in raw.get("Tag") or []:
        if isinstance(tag, dict):
            name = str(tag.get("name") or "")
        else:
            name = str(tag or "")
        if name:
            names.append(name)
    return names


def _tlp(tags: list[str]) -> str | None:
    markings = []
    for tag in tags:
        lower = tag.lower()
        if "tlp:" in lower:
            markings.append(lower.split("tlp:", 1)[1].strip().strip("\"'"))
    return _most_restrictive(markings)


def _most_restrictive(markings: list[str | None]) -> str | None:
    """The strictest TLP marking. An unknown marking outranks every known one."""
    found = [item for item in markings if item]
    if not found:
        return None
    return max(found, key=lambda item: _TLP_RANK.get(item, max(_TLP_RANK.values()) + 1))


def _restricted(record: dict) -> bool:
    marking = record.get("tlp")
    if marking and _TLP_RANK.get(marking, _RESTRICTED_RANK) >= _RESTRICTED_RANK:
        return True
    return str(record.get("distribution") or "") in _LIMITED_DISTRIBUTION


def _sharing_group(raw: dict) -> str:
    group = raw.get("SharingGroup")
    if isinstance(group, dict) and group.get("name"):
        return _text(group["name"])
    return ""


def _handling(records: list[dict]) -> tuple[str, ...]:
    if not any(_restricted(item) for item in records):
        return ()
    return (
        "Some records are TLP:AMBER or above, or limited to an organisation or sharing group. "
        "Keep them inside this profile and do not pass them outside the marking.",
    )


def _published(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes"}


def _text(value) -> str:
    if value is None:
        return ""
    cleaned = str(value).strip()
    if not cleaned:
        return ""
    return untrusted_text(cleaned, "misp")


def _attribute_body(value, attribute_type, category, limit: int) -> dict:
    body: dict = {
        "returnFormat": "json",
        "limit": limit,
        "includeEventUuid": 1,
        "includeEventTags": 1,
    }
    if value:
        body["value"] = value
    if attribute_type:
        body["type"] = attribute_type
    if category:
        body["category"] = category
    return body


def _event_body(event_id: str) -> dict:
    return {
        "returnFormat": "json",
        "eventid": event_id,
        "includeGalaxy": 1,
        "limit": 1,
    }


def _recent_body(limit: int, days: int, published_only: bool) -> dict:
    body: dict = {
        "returnFormat": "json",
        "limit": limit,
        "last": f"{days}d",
        "includeGalaxy": 1,
        "order": "timestamp desc",
    }
    if published_only:
        body["published"] = 1
    return body


def _document_warning(payload: dict) -> str | None:
    if "response" in payload:
        return None
    text = " ".join(str(payload.get(name) or "") for name in ("message", "errors", "name"))
    if "403" in text or "Forbidden" in text:
        return _auth_message(403)
    if "401" in text or "Unauthorized" in text:
        return _auth_message(401)
    return None


def _auth_message(status: int) -> str:
    return f"MISP returned {status}. Check MISP_API_KEY (a read-only key is enough) and MISP_URL."


def _clean(exc: BaseException, secret: str | None) -> str:
    message = redact(str(exc))
    if secret and secret in message:
        message = message.replace(secret, "[REDACTED]")
    lowered = message.lower()
    kept = ("not allowlisted", "only https", "ip literal", "blocked address", "userinfo")
    if any(part in lowered for part in kept):
        return message
    return "unavailable: MISP could not be reached and no cached copy exists"


def _check_bound(value: int, cap: int, label: str) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= cap:
        return f"{label} must be between 1 and {cap}"
    return ""


def _check_response(kind: str, records: list[dict]) -> str | None:
    if not records:
        return None
    schema = json.loads((_SCHEMA / f"{kind}.response.json").read_text(encoding="utf-8"))
    try:
        jsonschema.validate(records[0], schema)
    except jsonschema.ValidationError as exc:
        return f"MISP response schema: {exc.message}"
    return None


def _parse_base(raw: str) -> tuple[str | None, str]:
    try:
        parts = urlsplit(raw.strip())
        port = parts.port
    except ValueError:
        return None, "MISP_URL is not a valid URL."
    if parts.username or parts.password:
        return None, "MISP_URL must not contain userinfo."
    if parts.scheme.lower() != "https" or not parts.hostname:
        return None, "MISP_URL must be an https URL with a host."
    host = parts.hostname.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        literal = False
    else:
        literal = True
    if literal or not _HOST.fullmatch(host) or ".." in host:
        return None, "MISP_URL must be a hostname. IP literals are not allowed."
    port = f":{port}" if port else ""
    path = parts.path.rstrip("/")
    return f"https://{host}{port}{path}", ""


def _runtime_allowlist(host: str) -> Path:
    directory = _data_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "misp-egress.yaml"
    hosts: list[str] = []
    for item in [*_static_hosts(), host]:
        if item and item not in hosts:
            hosts.append(item)
    lines = ["connectors:", "  misp:", "    hosts:", *[f"      - {item}" for item in hosts]]
    lines.extend(["    allow_ip_literals: false", "    allow_http_loopback: false", ""])
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _static_hosts() -> list[str]:
    path = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    spec = (data.get("connectors") or {}).get("misp") or {}
    found = []
    for item in spec.get("hosts") or []:
        text = str(item).strip().lower().rstrip(".")
        if _HOST.fullmatch(text) and ".." not in text and text not in found:
            found.append(text)
    return found


def _urls(path: str) -> list[str]:
    raw = lookup("MISP_URL")
    if not raw:
        return [PIN_REPO]
    base, problem = _parse_base(raw)
    if problem or not base:
        return [PIN_REPO]
    return [base + path]


def _as_of(events: list[dict]) -> str | None:
    stamps = [str(item.get("timestamp") or "") for item in events]
    digits = [item for item in stamps if item.isdigit()]
    if not digits:
        return None
    newest = max(digits, key=int)
    return datetime.fromtimestamp(int(newest), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _key_scope(secret: str) -> str:
    """Cache scope for one API key, so a different key never reads another key's answers."""
    return "key:" + hashlib.sha256(secret.encode()).hexdigest()


def _persist(records: list[dict]) -> None:
    if "CYBERAU_DATA_DIR" not in os.environ:
        records = [item for item in records if not _restricted(item)]
    if not records:
        return
    directory = _data_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "misp-events.jsonl"
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def _snapshot_text() -> str | None:
    snapshot = os.environ.get("CYBERAU_MISP_SNAPSHOT")
    path = Path(snapshot) if snapshot else _DEFAULT_SNAPSHOT
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _load(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _envelope(
    data,
    cache: str,
    *,
    urls: list[str] | None = None,
    as_of: str | None = None,
    warnings: tuple[str, ...] = (),
) -> dict:
    return envelope(
        "misp",
        data,
        urls=urls or [PIN_REPO],
        cache=cache,
        data_as_of=as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-misp"))


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("misp", connector)
