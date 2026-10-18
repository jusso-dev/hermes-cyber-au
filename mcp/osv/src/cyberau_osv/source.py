"""Read-only OSV.dev open source vulnerabilities."""

import json
import os
import re
from pathlib import Path
from typing import Annotated

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError, Response
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable
from pydantic import Field

API = "https://api.osv.dev/v1"
QUERY_URL = f"{API}/query"
BATCH_URL = f"{API}/querybatch"
VULN_URL = f"{API}/vulns"
ATTRIBUTION = (
    "OSV.dev. Data is aggregated from many vulnerability databases; each record's "
    "database_specific source and licence fields are kept."
)
PROBE_ID = "GHSA-jfh8-c2jp-5v3q"
RECORD_TTL = 24 * 3600
QUERY_TTL = 6 * 3600
_TRANSPORT = None
LABEL = "OSV.dev"
SNAPSHOT_NOTE = (
    "served the operator-supplied OSV snapshot file (CYBERAU_OSV_SNAPSHOT), not a live fetch"
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ECOSYSTEM = re.compile(r"^[A-Za-z][A-Za-z0-9._:+-]{0,63}$")
_KEY = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
_MAX_DEPTH = 12
_TOKEN = re.compile(r"^[A-Za-z0-9._:/@+~=%?&#,;()\[\]-]{1,500}$")
_Id = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]
_Ecosystem = Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9._:+-]{0,63}$")]
_Package = Annotated[str, Field(min_length=1, max_length=214)]
_Version = Annotated[str, Field(min_length=1, max_length=128)]
_Queries = Annotated[list[dict], Field(min_length=1, max_length=100)]


def osv_query(ecosystem: _Ecosystem, package: _Package, version: _Version | None = None) -> dict:
    problem = _validate_query(ecosystem, package, version)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    body = _query_body(ecosystem, package, version)
    payload, cache, warning = _fetch("query", "POST", QUERY_URL, body, ttl=QUERY_TTL)
    if warning:
        return _envelope([], cache, warnings=(warning,))
    drift = schema_drift(payload or {}) if payload is not None else "OSV query was not usable"
    if drift:
        return _envelope([], cache, warnings=(drift,))
    vulns = payload.get("vulns") or []
    warnings: list[str] = []
    if cache == "snapshot":
        warnings.append(SNAPSHOT_NOTE)
        vulns = [item for item in vulns if _affects(item, ecosystem, package)]
        if version:
            warnings.append("offline snapshot is not filtered by version")
        if not vulns:
            warnings.append("no matching record in the offline snapshot or cache")
    if payload.get("next_page_token"):
        warnings.append("OSV has more results than one page; narrow the query with a version")
    try:
        rows = [_record(item) for item in vulns]
    except (AttributeError, TypeError):
        return _envelope([], cache, warnings=("OSV record was not usable",))
    _persist(rows)
    return _envelope(rows, cache, urls=[QUERY_URL], warnings=tuple(warnings))


def osv_get(id: _Id) -> dict:
    if not id or _ID.match(id) is None:
        return _envelope(None, "snapshot", warnings=("id is not an OSV identifier",))
    url = f"{VULN_URL}/{id}"
    payload, cache, warning = _fetch("vuln", "GET", url, None, ttl=RECORD_TTL)
    if warning:
        return _envelope(None, cache, urls=[url], warnings=(warning,))
    drift = schema_drift(payload or {}) if payload is not None else "OSV record was not usable"
    if drift:
        return _envelope(None, cache, urls=[url], warnings=(drift,))
    notes = (SNAPSHOT_NOTE,) if cache == "snapshot" else ()
    if "id" not in payload or (cache == "snapshot" and not _same_id(payload["id"], id)):
        return _envelope(
            None,
            cache,
            urls=[url],
            warnings=("no matching record in the offline snapshot or cache", *notes),
        )
    try:
        row = _record(payload)
    except (AttributeError, TypeError):
        return _envelope(None, cache, urls=[url], warnings=("OSV record was not usable",))
    _persist([row])
    return _envelope(row, cache, urls=[url], warnings=notes)


def osv_batch(queries: _Queries) -> dict:
    problem = _validate_batch(queries)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    body = {
        "queries": [_query_body(q["ecosystem"], q["package"], q.get("version")) for q in queries]
    }
    payload, cache, warning = _fetch("batch", "POST", BATCH_URL, body, ttl=QUERY_TTL)
    if warning:
        return _envelope([], cache, warnings=(warning,))
    warnings: list[str] = []
    if cache == "snapshot":
        warnings.append(SNAPSHOT_NOTE)
        pool = _load(_snapshot_text())
        problem = schema_drift(pool) if pool is not None else "snapshot is not JSON"
        if problem:
            return _envelope([], cache, warnings=(problem,))
        payload = _snapshot_batch(queries, pool)
        if any(q.get("version") for q in queries):
            warnings.append("offline snapshot is not filtered by version")
        if not any(result["vulns"] for result in payload["results"]):
            warnings.append("no matching record in the offline snapshot or cache")
    drift = schema_drift(payload or {}) if payload is not None else "OSV batch was not usable"
    if drift:
        return _envelope([], cache, warnings=(drift,))
    results = payload.get("results")
    if not isinstance(results, list):
        return _envelope([], cache, warnings=("OSV batch response has no results list",))
    if len(results) != len(queries):
        warnings.append(f"OSV returned {len(results)} results for {len(queries)} queries")
    rows = []
    for index, (query, result) in enumerate(zip(queries, results, strict=False)):
        vulns = [
            {"id": _token(v["id"]), "modified": _token(v.get("modified", ""))}
            for v in result.get("vulns") or []
        ]
        if result.get("next_page_token"):
            warnings.append(f"query {index} has more results than one page")
        rows.append(
            {
                "index": index,
                "ecosystem": _token(query["ecosystem"]),
                "package": _token(query["package"]),
                "version": _token(query["version"]) if query.get("version") else "",
                "count": len(vulns),
                "vulns": vulns,
            }
        )
    _persist_ids([item for row in rows for item in row["vulns"]])
    return _envelope(rows, cache, urls=[BATCH_URL], warnings=tuple(warnings))


def connector() -> Connector:
    return _OsvConnector()


class _OsvConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="osv",
            server_name="osv",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec("osv_query", "Vulnerabilities affecting a package version.", osv_query),
                ToolSpec("osv_get", "One OSV record by id.", osv_get),
                ToolSpec("osv_batch", "Up to 100 package queries in one call.", osv_batch),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            if not os.environ.get("CYBERAU_OSV_SNAPSHOT"):
                return Probe(self.key, True, "schema ok, no local copy to check")
            payload = _load(_snapshot_text())
            problem = schema_drift(payload) if payload is not None else "snapshot is not JSON"
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        url = f"{VULN_URL}/{PROBE_ID}"
        payload, _cache, warning = _fetch("vuln", "GET", url, None, ttl=60, force_live=True)
        if warning:
            return Probe(self.key, False, warning)
        problem = schema_drift(payload or {}) if payload is not None else "no record"
        if problem or not payload or payload.get("id") != PROBE_ID:
            return Probe(self.key, False, problem or "live record probe returned another id")
        body = {"queries": [_query_body("PyPI", "jinja2", "2.4.1")]}
        payload, _cache, warning = _fetch("batch", "POST", BATCH_URL, body, ttl=60, force_live=True)
        if warning:
            return Probe(self.key, False, warning)
        problem = schema_drift(payload or {}) if payload is not None else "no batch result"
        if problem or not isinstance(payload.get("results"), list) or len(payload["results"]) != 1:
            return Probe(self.key, False, problem or "live batch probe returned no results")
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return "OSV payload is not an object"
    if "results" in payload:
        results = payload["results"]
        if not isinstance(results, list):
            return "OSV batch response has no results list"
        for result in results:
            if not isinstance(result, dict):
                return "OSV batch result is not an object"
            problem = _vulns_drift(result.get("vulns") or [])
            if problem:
                return problem
        return None
    if "vulns" in payload:
        return _vulns_drift(payload["vulns"])
    if not payload:
        return None
    if "id" not in payload:
        return "OSV schema drift, missing id"
    if "modified" not in payload:
        return "OSV schema drift, missing modified"
    return None


def _vulns_drift(vulns) -> str | None:
    if not isinstance(vulns, list):
        return "OSV payload has no vulns list"
    for item in vulns:
        if not isinstance(item, dict) or "id" not in item:
            return "OSV schema drift, missing id"
    return None


def _fetch(
    kind: str,
    method: str,
    url: str,
    body: dict | None,
    *,
    ttl: int,
    force_live: bool = False,
) -> tuple[dict | None, str, str]:
    if os.environ.get("CYBERAU_OSV_SNAPSHOT") and not force_live:
        return _load(_snapshot_text()), "snapshot", ""
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    data_dir = _data_dir()
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    client = HttpClient(
        "osv",
        policy=EgressPolicy(allowlist, "osv"),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=10,
        burst=10,
        window="rolling",
        offline=offline,
        transport=_TRANSPORT,
    )
    try:
        if method == "POST":
            response = client.post_json(url, body or {}, ttl=ttl, skip_cache=force_live)
        else:
            response = client.get(url, ttl=ttl, skip_cache=force_live)
    except (HttpError, EgressDenied, TimeoutError) as exc:
        if offline:
            return None, "snapshot", unavailable(LABEL, "offline mode and no cached copy")
        if force_live:
            return None, "snapshot", "OSV unavailable: " + redact(str(exc))
        return None, "snapshot", unavailable(LABEL, f"the live fetch failed ({redact(str(exc))})")
    finally:
        client.close()
    warning = _status_warning(response)
    if warning:
        return None, response.cache, warning
    return _load(response.body.decode("utf-8", "replace")), response.cache, ""


def _status_warning(response: Response) -> str:
    status = response.status
    if status < 400:
        return ""
    if status in (401, 403):
        return (
            f"OSV refused the request with status {status}. This connector sends no "
            "credentials and OSV needs no API key, so there is no environment variable to set; "
            "check the network path to api.osv.dev."
        )
    if status == 404:
        return "OSV has no record with that id"
    if status == 429:
        return "OSV rate limited the request (429) after retries that honoured Retry-After"
    return f"OSV returned status {status}"


def _record(item: dict) -> dict:
    database = item.get("database_specific")
    affected = [_affected(entry) for entry in item.get("affected") or [] if isinstance(entry, dict)]
    source, licence = _source_and_licence(database, item.get("affected") or [])
    return {
        "id": _token(item["id"]),
        "aliases": [_token(alias) for alias in item.get("aliases") or []],
        "summary": _text(item.get("summary")),
        "details": _text(item.get("details"), 2000),
        "published": _token(item.get("published", "")),
        "modified": _token(item.get("modified", "")),
        "withdrawn": _token(item.get("withdrawn", "")),
        "severity": [
            {"type": _token(s.get("type", "")), "score": _token(s.get("score", ""))}
            for s in item.get("severity") or []
            if isinstance(s, dict)
        ],
        "affected": affected,
        "references": [
            {"type": _token(ref.get("type", "")), "url": _token(ref.get("url", ""))}
            for ref in item.get("references") or []
            if isinstance(ref, dict)
        ],
        "source": source,
        "licence": licence,
        "database_specific": _wrap_tree(database),
    }


def _affected(entry: dict) -> dict:
    package = entry.get("package") or {}
    introduced, fixed = [], []
    for span in entry.get("ranges") or []:
        for event in span.get("events") or []:
            if "introduced" in event:
                introduced.append(_token(event["introduced"]))
            if "fixed" in event:
                fixed.append(_token(event["fixed"]))
    return {
        "ecosystem": _token(package.get("ecosystem", "")),
        "package": _token(package.get("name", "")),
        "introduced": introduced,
        "fixed": fixed,
        "versions": [_token(version) for version in (entry.get("versions") or [])[:50]],
        "database_specific": _wrap_tree(entry.get("database_specific")),
    }


def _source_and_licence(database, affected: list) -> tuple[str, str]:
    places = [database] + [e.get("database_specific") for e in affected if isinstance(e, dict)]
    source = licence = ""
    for place in places:
        if not isinstance(place, dict):
            continue
        source = source or _first(place, ("source",))
        licence = licence or _first(place, ("license", "licence"))
    return source, licence


def _first(place: dict, names: tuple[str, ...]) -> str:
    for name in names:
        value = place.get(name)
        if isinstance(value, str) and value:
            return untrusted_text(value, "osv", 500)
    return ""


def _wrap_tree(value, depth: int = 0):
    if isinstance(value, str):
        return untrusted_text(value, "osv", 500)
    if depth >= _MAX_DEPTH:
        return None
    if isinstance(value, dict):
        return {_key(key): _wrap_tree(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [_wrap_tree(item, depth + 1) for item in value[:50]]
    return value


def _key(key) -> str:
    text = str(key)
    if _KEY.match(text):
        return text
    return untrusted_text(text, "osv", 100)


def _snapshot_batch(queries: list, pool: dict) -> dict:
    vulns = pool.get("vulns") or []
    return {
        "results": [
            {
                "vulns": [
                    {"id": v["id"], "modified": v.get("modified", "")}
                    for v in vulns
                    if _affects(v, q["ecosystem"], q["package"])
                ]
            }
            for q in queries
        ]
    }


def _text(value, limit: int = 4000) -> str:
    if not value:
        return ""
    return untrusted_text(str(value), "osv", limit)


def _token(value) -> str:
    text = str(value)
    if not text or _TOKEN.match(text):
        return text
    return untrusted_text(text, "osv", 500)


def _affects(item: dict, ecosystem: str, package: str) -> bool:
    for entry in item.get("affected") or []:
        pkg = entry.get("package") or {}
        same_name = str(pkg.get("name", "")).lower() == package.lower()
        same_ecosystem = str(pkg.get("ecosystem", "")).lower() == ecosystem.lower()
        if same_name and same_ecosystem:
            return True
    return False


def _same_id(found, wanted: str) -> bool:
    return str(found).lower() == wanted.lower()


def _query_body(ecosystem: str, package: str, version: str | None) -> dict:
    body: dict = {"package": {"ecosystem": ecosystem, "name": package}}
    if version:
        body["version"] = version
    return body


def _validate_query(ecosystem: str, package: str, version: str | None) -> str:
    if not ecosystem or _ECOSYSTEM.match(ecosystem) is None:
        return "ecosystem is required, for example PyPI, npm, Maven, Go or crates.io"
    if not package or len(package) > 214:
        return "package is required"
    if version is not None and not 1 <= len(version) <= 128:
        return "version must be 1 to 128 characters"
    return ""


def _validate_batch(queries) -> str:
    if not isinstance(queries, list) or not queries:
        return "queries is required"
    if len(queries) > 100:
        return "batch at most 100 queries"
    for index, query in enumerate(queries):
        if not isinstance(query, dict):
            return f"query {index} must be an object"
        fields = (query.get("ecosystem"), query.get("package"), query.get("version"))
        if any(f is not None and not isinstance(f, str) for f in fields):
            return f"query {index}: ecosystem, package and version must be strings"
        problem = _validate_query(
            query.get("ecosystem") or "", query.get("package") or "", fields[2]
        )
        if problem:
            return f"query {index}: {problem}"
    return ""


def _persist(rows: list[dict]) -> None:
    _persist_ids(
        [{"id": row["id"], "modified": row["modified"], "aliases": row["aliases"]} for row in rows]
    )


def _persist_ids(items: list[dict]) -> None:
    if not items:
        return
    directory = _data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "osv-observations.jsonl").open("a", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, sort_keys=True) + "\n")


def _snapshot_text() -> str:
    """Read the operator-supplied snapshot. Nothing shipped in the repo is read."""
    return Path(os.environ["CYBERAU_OSV_SNAPSHOT"]).read_text(encoding="utf-8")


def _load(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-osv"))


def _envelope(
    data,
    cache: str,
    urls: list[str] | None = None,
    warnings: tuple[str, ...] = (),
) -> dict:
    return envelope(
        "osv",
        data,
        urls=urls or [API],
        cache=cache,
        data_as_of=_as_of(data),
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _as_of(data) -> str | None:
    rows = data if isinstance(data, list) else [data]
    stamps = [
        row["modified"]
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("modified"), str) and row["modified"]
    ]
    return max(stamps) if stamps else None


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("osv", connector)
