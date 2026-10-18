"""Read-only GraphQL client for a user-supplied OpenCTI instance."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy, normalise_host
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable

ATTRIBUTION = (
    "OpenCTI Community Edition is Apache-2.0. Enterprise Edition has its own licence. "
    "Data in your instance stays under the terms you agreed with its sources. "
    "This connector is not endorsed by Filigran."
)
DOCTOR_LINE = "off by default: licence terms"
DOCTOR_DOCS = "docs/connectors/opencti.md"
# Client ceiling. HttpClient calls RateLimiter.acquire on each attempt.
RATE = 2.0
BURST = 10
_PACKAGE = Path(__file__).resolve().parents[2]
_LABEL = "OpenCTI"
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_TYPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_.:-]{1,40}$")
_WHEN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9:.]{4,24}Z?$")
_AUTH_WORDS = ("auth", "token", "logged", "forbidden", "permission", "unauthorised", "unauthorized")
_TRANSPORT = None
_SLEEPER = None
_RNG = None
_RESOLVER = None

SEARCH_QUERY = """
query SearchEntities($search: String!, $types: [String], $first: Int!, $after: ID) {
  stixCoreObjects(search: $search, types: $types, first: $first, after: $after) {
    pageInfo { endCursor hasNextPage globalCount }
    edges {
      node {
        id
        entity_type
        representative { main }
        ... on AttackPattern { name description }
        ... on Campaign { name description }
        ... on CourseOfAction { name description }
        ... on Incident { name description }
        ... on Indicator { name description pattern pattern_type x_opencti_score }
        ... on Individual { name description }
        ... on IntrusionSet { name description aliases }
        ... on Malware { name description aliases }
        ... on Report { name description }
        ... on Tool { name description }
        ... on Vulnerability { name description }
      }
    }
  }
}
""".strip()

INDICATOR_QUERY = """
query IndicatorContext($search: String!, $first: Int!) {
  indicators(search: $search, first: $first) {
    edges {
      node {
        id
        entity_type
        name
        description
        pattern
        pattern_type
        x_opencti_score
        representative { main }
        stixCoreRelationships(first: 25) {
          edges {
            node {
              id
              relationship_type
              description
              from { ... on StixCoreObject { id entity_type representative { main } } }
              to { ... on StixCoreObject { id entity_type representative { main } } }
            }
          }
        }
        stixSightingRelationships(first: 15) {
          edges {
            node {
              id
              description
              first_seen
              last_seen
            }
          }
        }
      }
    }
  }
}
""".strip()


def opencti_search_entities(query: str, types: list[str] | None = None) -> dict:
    """Actors, malware, indicators and reports."""
    return _search(query, types, first=20, max_pages=3, force_live=False)


def opencti_get_indicator_context(value: str) -> dict:
    """Relationships and sightings for an indicator."""
    return _indicator(value, first=5, force_live=False)


def connector() -> Connector:
    return _OpenCTIConnector()


class _OpenCTIConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="opencti",
            server_name="opencti",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "opencti_search_entities",
                    "Search actors, malware, indicators and reports on your OpenCTI instance.",
                    opencti_search_entities,
                ),
                ToolSpec(
                    "opencti_get_indicator_context",
                    "Relationships and sightings for an indicator on your OpenCTI instance.",
                    opencti_get_indicator_context,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        # A live probe never checks the test fixtures. It checks the live answers below.
        if check_schema and (not live or os.environ.get("CYBERAU_OPENCTI_SNAPSHOT")):
            problem = _fixture_drift()
            if problem:
                return Probe(self.key, False, problem)
            if not live:
                return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        missing = [name for name in ("OPENCTI_URL", "OPENCTI_TOKEN") if not lookup(name)]
        if missing:
            return Probe(self.key, False, f"live probe needs {' and '.join(missing)} to be set")
        found = _search("health", None, first=1, max_pages=1, force_live=True)
        problem = _live_problem("opencti_search_entities", found)
        if problem:
            return Probe(self.key, False, problem)
        context = _indicator("health.example", first=1, force_live=True)
        problem = _live_problem("opencti_get_indicator_context", context)
        if problem:
            return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict, kind: str) -> str | None:
    """Return a drift message when the GraphQL shape is not the one we parse."""
    if not isinstance(payload, dict):
        return "OpenCTI payload was not usable"
    if kind == "search" and isinstance(payload.get("pages"), list):
        if not payload["pages"] or not isinstance(payload["pages"][0], dict):
            return "OpenCTI payload was not usable"
        payload = payload["pages"][0]
    data = payload.get("data")
    if not isinstance(data, dict):
        return "OpenCTI payload has no data object"
    key = "stixCoreObjects" if kind == "search" else "indicators"
    root = data.get(key)
    if not isinstance(root, dict) or not isinstance(root.get("edges"), list):
        return f"OpenCTI schema drift, missing {key}.edges"
    for edge in root["edges"]:
        node = edge.get("node") if isinstance(edge, dict) else None
        if not isinstance(node, dict) or "id" not in node or "entity_type" not in node:
            return "OpenCTI schema drift, missing entity_type"
        if kind == "indicator" and "stixCoreRelationships" in node:
            rels = node["stixCoreRelationships"]
            if not isinstance(rels, dict) or not isinstance(rels.get("edges"), list):
                return "OpenCTI schema drift, missing stixCoreRelationships.edges"
    return None


def render_mcp_server(existing: dict | None = None) -> dict:
    """Render the profile server block. A fresh install stays off.

    `enabled` is kept when the user has already set it. The API token is never
    copied into the rendered block.
    """
    enabled = False
    if isinstance(existing, dict) and isinstance(existing.get("enabled"), bool):
        enabled = existing["enabled"]
    return {
        "command": "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp",
        "args": ["serve", "opencti"],
        "env": {
            "CYBERAU_DATA_DIR": "<PROFILE_HOME>/plugin-data/cyber-au",
            "OPENCTI_URL": "${OPENCTI_URL}",
            "OPENCTI_TOKEN": "${OPENCTI_TOKEN}",
        },
        "lazy": True,
        "timeout": 120,
        "trust": "untrusted",
        "supports_parallel_tool_calls": True,
        "enabled": enabled,
    }


def _search(
    query: str,
    types: list[str] | None,
    *,
    first: int,
    max_pages: int,
    force_live: bool,
) -> dict:
    problem = _clean_search(query, types)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    cleaned = [_type_name(item) for item in (types or [])]
    records: list[dict] = []
    after = None
    state = "hit"
    endpoint = ""
    for _page in range(max_pages):
        variables: dict = {"search": query.strip(), "first": first}
        if cleaned:
            variables["types"] = cleaned
        if after:
            variables["after"] = after
        payload, page_state, warning, url = _graphql(SEARCH_QUERY, variables, force_live=force_live)
        state = _combine(state, page_state)
        endpoint = url or endpoint
        if warning:
            return _envelope([], state, urls=_urls(endpoint), warnings=(warning,))
        drifted = schema_drift(payload or {}, "search")
        if drifted:
            return _envelope([], state, urls=_urls(endpoint), warnings=(drifted,))
        page = payload or {}
        if isinstance(page.get("pages"), list):
            page = page["pages"][0]
        root = page["data"]["stixCoreObjects"]
        records.extend(_entities(root.get("edges") or []))
        info = root.get("pageInfo") if isinstance(root.get("pageInfo"), dict) else {}
        if page_state in {"stale", "snapshot"} or not info.get("hasNextPage"):
            break
        cursor = info.get("endCursor")
        if not isinstance(cursor, str) or not cursor:
            break
        after = cursor
    return _envelope(records, state, urls=_urls(endpoint), warnings=_provenance(state))


def _indicator(value: str, *, first: int, force_live: bool) -> dict:
    text = value.strip()
    if len(text) < 1:
        return _envelope([], "snapshot", warnings=("value is required",))
    if len(text) > 200:
        return _envelope([], "snapshot", warnings=("value is too long",))
    payload, state, warning, url = _graphql(
        INDICATOR_QUERY,
        {"search": text, "first": first},
        force_live=force_live,
    )
    if warning:
        return _envelope([], state, urls=_urls(url), warnings=(warning,))
    drifted = schema_drift(payload or {}, "indicator")
    if drifted:
        return _envelope([], state, urls=_urls(url), warnings=(drifted,))
    root = (payload or {})["data"]["indicators"]
    records = []
    for edge in root.get("edges") or []:
        node = edge.get("node") if isinstance(edge, dict) else None
        if isinstance(node, dict):
            record = _indicator_record(node)
            if record:
                records.append(record)
    return _envelope(records, state, urls=_urls(url), warnings=_provenance(state))


def _graphql(
    query: str,
    variables: dict,
    *,
    force_live: bool,
) -> tuple[dict | None, str, str, str]:
    snapshot = os.environ.get("CYBERAU_OPENCTI_SNAPSHOT")
    if snapshot and not force_live:
        payload = _read_json(Path(snapshot))
        if payload is None:
            return None, "snapshot", "OpenCTI payload was not usable", ""
        return payload, "snapshot", "", ""
    url = lookup("OPENCTI_URL")
    token = lookup("OPENCTI_TOKEN")
    if not url:
        return None, "snapshot", unavailable(_LABEL, "OPENCTI_URL is not set"), ""
    if not token:
        return None, "snapshot", unavailable(_LABEL, "OPENCTI_TOKEN is not set"), ""
    endpoint, problem = _endpoint(url)
    if problem:
        return None, "snapshot", problem, ""
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    data_dir = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-opencti"))
    try:
        policy = _policy(endpoint)
    except EgressDenied as exc:
        return None, "snapshot", str(exc), endpoint
    client = HttpClient(
        "opencti",
        policy=policy,
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=RATE,
        burst=BURST,
        window="rolling",
        timeout=30,
        transport=_TRANSPORT,
        sleeper=_SLEEPER,
        rng=_RNG,
        auth_scope=hashlib.sha256(token.encode()).hexdigest(),
        offline=offline,
    )
    try:
        response = client.post_json(
            endpoint,
            {"query": query, "variables": variables},
            headers={"authorization": f"Bearer {token}"},
            ttl=0,
        )
    except EgressDenied as exc:
        return None, "snapshot", str(exc), endpoint
    except HttpError as exc:
        message = _safe(str(exc), token)
        if "offline and no cache" in message:
            message = "offline and no cached OpenCTI response exists"
        return None, "snapshot", unavailable(_LABEL, message), endpoint
    except Exception as exc:
        return None, "snapshot", unavailable(_LABEL, _safe(str(exc), token)), endpoint
    finally:
        client.close()
    if response.status in (401, 403):
        return (
            None,
            "miss",
            unavailable(
                _LABEL,
                f"OpenCTI refused the request (HTTP {response.status}). Check OPENCTI_TOKEN",
            ),
            endpoint,
        )
    if response.status == 429:
        reason = "OpenCTI rate limited the request (HTTP 429)"
        return None, "miss", unavailable(_LABEL, reason), endpoint
    if response.status >= 400:
        reason = f"OpenCTI returned HTTP {response.status}"
        return None, "miss", unavailable(_LABEL, reason), endpoint
    payload = _load_bytes(response.body)
    if payload is None:
        return None, response.cache, "OpenCTI payload was not usable", endpoint
    graphql_error = _graphql_error(payload)
    if graphql_error:
        return None, response.cache, _safe(graphql_error, token), endpoint
    return payload, response.cache, "", endpoint


def _policy(url: str) -> EgressPolicy:
    policy = EgressPolicy(_allowlist(), "opencti", resolver=_RESOLVER)
    host = urlsplit(url).hostname or ""
    if host:
        policy.hosts.add(normalise_host(host))
    return policy


def _endpoint(raw: str) -> tuple[str, str]:
    text = raw.strip()
    parts = urlsplit(text)
    if parts.username or parts.password:
        return "", "OPENCTI_URL must not contain userinfo"
    if parts.scheme.lower() != "https" or not parts.hostname:
        return "", "OPENCTI_URL must be an https URL"
    base = text.rstrip("/")
    if base.endswith("/graphql"):
        return base, ""
    return base + "/graphql", ""


def _entities(edges: list) -> list[dict]:
    records = []
    for edge in edges:
        node = edge.get("node") if isinstance(edge, dict) else None
        if not isinstance(node, dict):
            continue
        record = _entity(node)
        if record:
            records.append(record)
    return records


def _entity(node: dict) -> dict | None:
    ident = _ident(node.get("id"))
    kind = _type_name(node.get("entity_type"))
    if not ident or not kind:
        return None
    aliases = []
    for alias in node.get("aliases") or []:
        text = _text(alias)
        if text:
            aliases.append(text)
    raw_representative = node.get("representative")
    representative = raw_representative if isinstance(raw_representative, dict) else {}
    return {
        "id": ident,
        "entity_type": kind,
        "name": _text(node.get("name") or representative.get("main")),
        "description": _text(node.get("description")),
        "aliases": aliases,
    }


def _indicator_record(node: dict) -> dict | None:
    base = _entity(node)
    if base is None:
        return None
    base.pop("aliases", None)
    ident = base["id"]
    relationships = []
    rel_root = node.get("stixCoreRelationships")
    rel_edges = rel_root.get("edges") if isinstance(rel_root, dict) else []
    for edge in rel_edges or []:
        item = edge.get("node") if isinstance(edge, dict) else None
        if isinstance(item, dict):
            parsed = _relationship(item, ident)
            if parsed:
                relationships.append(parsed)
    sightings = []
    sight_root = node.get("stixSightingRelationships")
    sight_edges = sight_root.get("edges") if isinstance(sight_root, dict) else []
    for edge in sight_edges or []:
        item = edge.get("node") if isinstance(edge, dict) else None
        if isinstance(item, dict):
            parsed = _sighting(item)
            if parsed:
                sightings.append(parsed)
    base.update(
        {
            "pattern": _text(node.get("pattern")),
            "pattern_type": _token(node.get("pattern_type")),
            "score": _score(node.get("x_opencti_score")),
            "relationships": relationships,
            "sightings": sightings,
        }
    )
    return base


def _relationship(node: dict, indicator_id: str) -> dict | None:
    ident = _ident(node.get("id"))
    kind = _token(node.get("relationship_type"))
    if not ident or not kind:
        return None
    target = node.get("to") if isinstance(node.get("to"), dict) else {}
    other = node.get("from") if isinstance(node.get("from"), dict) else {}
    if target.get("id") == indicator_id or not target.get("id"):
        target = other
    target_id = _ident(target.get("id")) or ""
    target_type = _token(target.get("entity_type"))
    representative = (
        target.get("representative") if isinstance(target.get("representative"), dict) else {}
    )
    return {
        "id": ident,
        "relationship_type": kind,
        "description": _text(node.get("description")),
        "target_id": target_id,
        "target_type": target_type,
        "target_name": _text(target.get("name") or representative.get("main")),
    }


def _sighting(node: dict) -> dict | None:
    ident = _ident(node.get("id"))
    if not ident:
        return None
    count = node.get("attribute_count")
    return {
        "id": ident,
        "description": _text(node.get("description")),
        "first_seen": _when(node.get("first_seen")),
        "last_seen": _when(node.get("last_seen")),
        "count": count if isinstance(count, int) else None,
    }


def _clean_search(query: str, types: list[str] | None) -> str:
    if not isinstance(query, str) or len(query.strip()) < 2:
        return "query must be at least 2 characters"
    if len(query.strip()) > 200:
        return "query is too long"
    if types is None:
        return ""
    if not isinstance(types, list) or any(not _type_name(item) for item in types):
        return "types must be OpenCTI entity type names"
    return ""


def _graphql_error(payload: dict) -> str:
    errors = payload.get("errors")
    if not errors:
        return ""
    messages = []
    if isinstance(errors, list):
        for item in errors:
            if isinstance(item, dict) and item.get("message"):
                messages.append(str(item["message"]))
    raw = "; ".join(messages)
    text = _text(raw) or "OpenCTI returned an error"
    if any(word in raw.lower() for word in _AUTH_WORDS):
        return f"{text} Check OPENCTI_TOKEN."
    return text


def _fixture_drift() -> str | None:
    override = os.environ.get("CYBERAU_OPENCTI_SNAPSHOT")
    if override:
        payload = _read_json(Path(override))
        if payload is None:
            return "OpenCTI payload was not usable"
        kind = "indicator" if _looks_like_indicator(payload) else "search"
        return schema_drift(payload, kind)
    fixtures = _PACKAGE / "tests" / "fixtures"
    search = schema_drift(_read_json(fixtures / "paginated.json") or {}, "search")
    if search:
        return search
    return schema_drift(_read_json(fixtures / "indicator_graphql.json") or {}, "indicator")


def _looks_like_indicator(payload: dict) -> bool:
    data = payload.get("data")
    return isinstance(data, dict) and "indicators" in data


def _live_problem(tool: str, payload: dict) -> str:
    if payload.get("cache") == "snapshot" and not payload.get("data") and payload.get("warnings"):
        # The empty unavailable envelope also carries cache "snapshot". Report why.
        return str(payload["warnings"][0])
    if payload.get("cache") in {"stale", "snapshot"}:
        return f"{tool} was answered from a {payload['cache']} copy, not a live fetch"
    if payload.get("warnings"):
        return str(payload["warnings"][0])
    return _validate_data(tool, payload.get("data")) or ""


def _validate_data(tool: str, data) -> str | None:
    schema = json.loads((_PACKAGE / "schema" / f"{tool}.response.json").read_text(encoding="utf-8"))
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        return f"response schema: {exc.message}"[:300]
    return None


def _envelope(data, cache: str, *, urls: list[str] | None = None, warnings: tuple[str, ...] = ()):
    if cache not in {"hit", "miss", "stale", "snapshot"}:
        cache = "snapshot"
    return envelope(
        "opencti",
        data,
        urls=urls or [],
        cache=cache,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _provenance(state: str) -> tuple[str, ...]:
    """Say so when a result did not come from a live fetch of the user's instance."""
    if state == "snapshot":
        return (
            "Served from the operator-supplied snapshot file in CYBERAU_OPENCTI_SNAPSHOT, "
            "not a live fetch of your instance.",
        )
    if state == "stale":
        return ("Served from a cached OpenCTI response, not a live fetch.",)
    return ()


def _urls(endpoint: str) -> list[str]:
    return [endpoint] if endpoint else []


def _combine(current: str, new: str) -> str:
    rank = {"hit": 0, "miss": 1, "stale": 2, "snapshot": 3}
    if new not in rank:
        return current
    if current not in rank or rank[new] >= rank[current]:
        return new
    return current


def _text(value) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    # A value must not be able to close or reopen the wrapper markers.
    neutral = re.sub(r">(?=>)", "> ", re.sub(r"<(?=<)", "< ", value))
    return untrusted_text(neutral, "opencti")


def _ident(value) -> str:
    if isinstance(value, str) and _ID.match(value):
        return value
    return ""


def _type_name(value) -> str:
    if isinstance(value, str) and _TYPE.match(value):
        return value
    return ""


def _token(value) -> str:
    if isinstance(value, str) and _TOKEN.match(value):
        return value
    return ""


def _when(value) -> str:
    if isinstance(value, str) and _WHEN.match(value):
        return value
    return ""


def _score(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _safe(message: str, token: str) -> str:
    cleaned = redact(message)
    if token and token in cleaned:
        cleaned = cleaned.replace(token, "[REDACTED]")
    return cleaned


def _read_json(path: Path) -> dict | None:
    try:
        return _load_bytes(path.read_bytes())
    except OSError:
        return None


def _load_bytes(body: bytes) -> dict | None:
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _allowlist() -> Path:
    override = os.environ.get("CYBERAU_EGRESS_ALLOWLIST")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("opencti", connector)
