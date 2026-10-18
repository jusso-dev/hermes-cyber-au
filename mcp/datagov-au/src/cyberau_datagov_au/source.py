"""Read-only data.gov.au CKAN catalogue."""

import json
import os
import re
from pathlib import Path
from typing import Annotated

import jsonschema
from cyberau_common import GOV_AU_USER_AGENT as USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

SEARCH = "https://data.gov.au/data/api/3/action/package_search"
SHOW = "https://data.gov.au/data/api/3/action/package_show"
ATTRIBUTION = (
    "data.gov.au. Each dataset keeps its own licence (license_id). "
    "Datasets with no licence are flagged."
)
_REQUIRED = ("id", "title", "resources")
_NO_LICENCE = {"", "notspecified", "not specified", "not-specified", "none", "null"}
_PACKAGE = Path(__file__).resolve().parents[2]
_PLAIN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~:-]{0,199}")
_PLAIN_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/:-]{0,63}")
_PLAIN_URL = re.compile(r"https?://[^\s<>\"']{1,2000}")
_Query = Annotated[str, Field(min_length=2)]
_Limit = Annotated[int, Field(ge=1, le=50)]
_TRANSPORT = None
_SLEEP = None
_CLOCK = None


def datagov_search(query: _Query, limit: _Limit = 10) -> dict:
    problem = _validate_search(query, limit)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,), url=SEARCH)
    text = query.strip()
    payload, cache, warning = _fetch(SEARCH, {"q": text, "rows": str(limit)})
    if warning:
        return _envelope([], cache, warnings=(warning,), url=SEARCH)
    if payload is None:
        return _envelope([], cache, warnings=("data.gov.au payload was not usable",), url=SEARCH)
    rows, problem = _collect(payload, cache=cache, query=text, limit=limit, detail=False)
    if problem and not rows:
        return _envelope([], cache, warnings=(problem,), url=SEARCH)
    _persist(rows, cache)
    warnings = _provenance(cache) + _licence_warnings(rows)
    if problem:
        warnings.insert(0, problem)
    return _envelope(rows, cache, warnings=tuple(warnings), url=SEARCH)


def datagov_get_package(id: str) -> dict:
    if not isinstance(id, str) or not id.strip():
        return _envelope(None, "snapshot", warnings=("id is required",), url=SHOW)
    identifier = id.strip()
    payload, cache, warning = _fetch(SHOW, {"id": identifier})
    if warning:
        return _envelope(None, cache, warnings=(warning,), url=SHOW)
    if payload is None:
        return _envelope(None, cache, warnings=("data.gov.au payload was not usable",), url=SHOW)
    rows, problem = _collect(payload, cache=cache, identifier=identifier, detail=True)
    if problem and not rows:
        return _envelope(None, cache, warnings=(problem,), url=SHOW)
    _persist(rows, cache)
    warnings = _provenance(cache) + _licence_warnings(rows)
    if problem:
        warnings.insert(0, problem)
    data = rows[0] if rows else None
    return _envelope(data, cache, warnings=tuple(warnings), url=SHOW)


def connector() -> Connector:
    return _DatagovConnector()


class _DatagovConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="datagov-au",
            server_name="datagov",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "datagov_search",
                    "Packages with title, publisher, licence and resource links.",
                    datagov_search,
                ),
                ToolSpec(
                    "datagov_get_package",
                    "One package with its resources.",
                    datagov_get_package,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            payload = _load(_snapshot_text())
            problem = schema_drift(payload or {})
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        payload, cache, warning = _fetch(
            SEARCH,
            {"q": "data", "rows": "1"},
            force_live=True,
        )
        if warning:
            return Probe(self.key, False, warning)
        if cache != "miss":
            return Probe(self.key, False, f"live probe was answered from {cache}, not live")
        problem = schema_drift(payload or {})
        if problem:
            return Probe(self.key, False, problem)
        packages = _packages(payload or {})
        if not packages:
            return Probe(self.key, False, "live probe returned no packages")
        summary = _record(packages[0], detail=False)
        detail = _record(packages[0], detail=True)
        problem = _response_problem([summary], "datagov_search.response.json")
        if problem:
            return Probe(self.key, False, problem)
        problem = _response_problem([detail], "datagov_get_package.response.json")
        if problem:
            return Probe(self.key, False, problem)
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return "data.gov.au payload was not an object"
    if payload.get("success") is False:
        return None
    if "result" not in payload:
        return "data.gov.au payload is missing result"
    result = payload.get("result")
    if isinstance(result, dict) and isinstance(result.get("results"), list):
        packages = [item for item in result["results"] if isinstance(item, dict)]
        if not packages:
            return None
    elif isinstance(result, dict) and any(name in result for name in ("id", "title", "name")):
        packages = [result]
    else:
        return "data.gov.au schema drift, result is not a package"
    for package in packages:
        missing = [name for name in _REQUIRED if name not in package]
        if missing:
            return "data.gov.au schema drift, missing " + ", ".join(missing)
        if not isinstance(package.get("resources"), list):
            return "data.gov.au schema drift, resources is not a list"
    return None


class _JsonCache(HttpCache):
    """Only keeps bodies that parse as a successful CKAN object.

    A 200 maintenance page must not replace a good cached copy for 24 hours.
    """

    def put(self, key, *, status, headers, body, ttl):
        try:
            decoded = _load(body.decode("utf-8"))
        except UnicodeDecodeError:
            return
        if decoded is None or decoded.get("success") is False:
            return
        super().put(key, status=status, headers=headers, body=body, ttl=ttl)


def _fetch(url: str, params: dict, *, force_live: bool = False) -> tuple[dict | None, str, str]:
    snapshot = os.environ.get("CYBERAU_DATAGOV_SNAPSHOT")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if snapshot and not force_live:
        path = Path(snapshot)
        if not path.is_file():
            return None, "snapshot", "data.gov.au is unavailable"
        return _parsed(path.read_text(encoding="utf-8"), "snapshot")
    data_dir = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-datagov-au"))
    cache = _JsonCache(data_dir / "http_cache.sqlite")
    key = cache.key("GET", url, params, b"", "anonymous")
    cached = cache.get(key)
    if cached and not force_live and (offline or cache.fresh(cached)):
        state = "stale" if offline or not cache.fresh(cached) else "hit"
        return _parsed(cached.body.decode("utf-8"), state)
    if offline:
        shipped = _PACKAGE / "data" / "package_search.json"
        if shipped.is_file():
            return _parsed(shipped.read_text(encoding="utf-8"), "snapshot")
        return None, "snapshot", "data.gov.au is unavailable"
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    client = _client(data_dir, allowlist, cache)
    try:
        response = client.get(url, params=params, ttl=24 * 3600, skip_cache=force_live)
    except Exception as exc:
        message = _failure_message(exc)
        if force_live or isinstance(exc, EgressDenied):
            return None, "snapshot", message
        cached = cache.get(key)
        if cached is not None:
            return _parsed(cached.body.decode("utf-8"), "stale")
        return None, "snapshot", message
    finally:
        client.close()
    if response.status in (401, 403):
        return None, response.cache, _refused(response.status)
    if response.status >= 400:
        if not force_live:
            cached = cache.get(key)
            if cached is not None:
                return _parsed(cached.body.decode("utf-8"), "stale")
        return None, response.cache, f"upstream status {response.status}"
    text = _decode(response.body)
    if text is None:
        return None, response.cache, _UNUSABLE
    return _parsed(text, response.cache)


_UNUSABLE = "data.gov.au payload was not usable"


def _parsed(text: str, cache: str) -> tuple[dict | None, str, str]:
    payload = _load(text)
    if payload is None:
        return None, cache, _UNUSABLE
    return payload, cache, ""


def _client(data_dir: Path, allowlist: Path, cache: HttpCache) -> HttpClient:
    limiter_kwargs = {}
    client_kwargs = {}
    if _SLEEP is not None:
        limiter_kwargs["sleeper"] = _SLEEP
        client_kwargs["sleeper"] = _SLEEP
    if _CLOCK is not None:
        limiter_kwargs["clock"] = _CLOCK
    return HttpClient(
        "datagov-au",
        policy=EgressPolicy(allowlist, "datagov-au"),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", **limiter_kwargs),
        user_agent=USER_AGENT,
        rate=1,
        burst=1,
        window="rolling",
        transport=_TRANSPORT,
        **client_kwargs,
    )


def _collect(
    payload: dict,
    *,
    cache: str,
    detail: bool,
    query: str | None = None,
    limit: int = 10,
    identifier: str | None = None,
) -> tuple[list[dict], str]:
    failed = _ckan_error(payload)
    if failed:
        return [], failed
    problem = schema_drift(payload)
    if problem:
        return [], problem
    packages = _packages(payload)
    if identifier is not None:
        chosen = _select(packages, identifier)
        if chosen is None:
            if cache == "snapshot":
                return [], "no matching package in the offline snapshot or cache"
            return [], "data.gov.au has no package with that id"
        return [_record(chosen, detail=True)], ""
    if cache == "snapshot" and query is not None:
        packages = [item for item in packages if _matches(item, query)]
    rows = [_record(item, detail=detail) for item in packages][:limit]
    if not rows and cache == "snapshot" and _packages(payload):
        return [], "no matching package in the offline snapshot or cache"
    return rows, ""


def _packages(payload: dict) -> list[dict]:
    result = payload.get("result")
    if not isinstance(result, dict):
        return []
    rows = result.get("results")
    if isinstance(rows, list):
        return [item for item in rows if isinstance(item, dict)]
    if "id" in result or "name" in result:
        return [result]
    return []


def _select(packages: list[dict], identifier: str) -> dict | None:
    wanted = identifier.strip()
    for package in packages:
        if str(package.get("id") or "") == wanted or str(package.get("name") or "") == wanted:
            return package
    return None


def _matches(package: dict, query: str) -> bool:
    haystack = " ".join(
        [
            str(package.get("title") or ""),
            str(package.get("notes") or ""),
            str(package.get("name") or ""),
            _publisher(package),
        ]
    ).lower()
    return query.lower() in haystack


def _record(package: dict, *, detail: bool) -> dict:
    resources = []
    for item in package.get("resources") or []:
        if not isinstance(item, dict):
            continue
        resources.append(
            {
                "id": _plain(item.get("id"), _PLAIN_ID),
                "name": _as_text(item.get("name") or ""),
                "format": _plain(item.get("format"), _PLAIN_TOKEN),
                "url": _plain(item.get("url"), _PLAIN_URL),
            }
        )
    licence = package.get("license_id")
    row = {
        "id": _plain(package.get("id"), _PLAIN_ID),
        "name": _plain(package.get("name"), _PLAIN_ID),
        "title": _as_text(package.get("title") or ""),
        "publisher": _as_text(_publisher(package)),
        "licence": _plain(licence, _PLAIN_TOKEN),
        "licence_title": _as_text(package.get("license_title") or ""),
        "licence_missing": _licence_missing(licence),
        "modified": _plain(package.get("metadata_modified"), _PLAIN_TOKEN),
        "resources": resources,
    }
    if detail:
        row["notes"] = _as_text(package.get("notes") or "")
    return row


def _publisher(package: dict) -> str:
    org = package.get("organization")
    if isinstance(org, dict):
        title = org.get("title") or org.get("name") or ""
        if title:
            return str(title)
    return str(package.get("author") or "")


def _licence_missing(licence) -> bool:
    if licence is None:
        return True
    return str(licence).strip().lower() in _NO_LICENCE


def _licence_warnings(rows: list[dict]) -> list[str]:
    missing = [row["id"] or row["name"] or "unknown" for row in rows if row["licence_missing"]]
    if not missing:
        return []
    return ["dataset has no licence: " + ", ".join(missing)]


def _plain(value, pattern: re.Pattern) -> str:
    """Pass through short plain values. Anything else is upstream free text, so wrap it."""
    if value is None:
        return ""
    text = str(value).strip()
    if not text or pattern.fullmatch(text):
        return text
    return _as_text(text)


def _provenance(cache: str) -> list[str]:
    if cache == "stale":
        return ["answered from a stale cached copy, not a live result"]
    if cache != "snapshot":
        return []
    if os.environ.get("CYBERAU_DATAGOV_SNAPSHOT"):
        return ["answered from the CYBERAU_DATAGOV_SNAPSHOT file, not a live result"]
    return [
        "answered from the synthetic sample snapshot shipped with this connector, "
        "not live data from data.gov.au"
    ]


def _as_text(value) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    if not value.strip():
        return ""
    return untrusted_text(value, "datagov-au")


def _ckan_error(payload: dict) -> str:
    if payload.get("success") is not False:
        return ""
    error = payload.get("error")
    message = ""
    if isinstance(error, dict):
        message = str(error.get("message") or "")
    elif isinstance(error, str):
        message = error
    if not message:
        return "data.gov.au request failed"
    return untrusted_text(message, "datagov-au", max_len=300)


def _validate_search(query: str, limit: int) -> str:
    if not isinstance(query, str) or len(query.strip()) < 2:
        return "query must be at least 2 characters"
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        return "limit must be between 1 and 50"
    return ""


def _persist(rows: list[dict], cache: str) -> None:
    if not rows or cache == "snapshot":
        return
    directory = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-datagov-au"))
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "datagov-observations.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(
                json.dumps(
                    {
                        "id": row["id"],
                        "name": row["name"],
                        "title": row["title"],
                        "licence": row["licence"],
                        "licence_missing": row["licence_missing"],
                        "modified": row["modified"],
                    },
                    sort_keys=True,
                )
                + "\n"
            )


def _snapshot_text() -> str:
    snapshot = os.environ.get("CYBERAU_DATAGOV_SNAPSHOT")
    path = Path(snapshot) if snapshot else _PACKAGE / "data" / "package_search.json"
    return path.read_text(encoding="utf-8")


def _response_problem(records: list[dict], name: str) -> str | None:
    schema = json.loads((_PACKAGE / "schema" / name).read_text(encoding="utf-8"))
    for record in records:
        try:
            jsonschema.validate(record, schema)
        except jsonschema.ValidationError as exc:
            return f"{name}: {exc.message}"
    return None


def _failure_message(exc: Exception) -> str:
    if isinstance(exc, EgressDenied):
        return redact(str(exc))
    text = redact(str(exc))
    lowered = text.lower()
    if "timeout" in lowered or "timed out" in lowered:
        return "data.gov.au timed out"
    if "upstream status" in lowered:
        return text
    return "data.gov.au is unavailable"


def _refused(status: int) -> str:
    return (
        f"data.gov.au refused the request ({status}). "
        "This connector has no API key. Set CYBERAU_OFFLINE to answer from cache."
    )


def _envelope(data, cache: str, *, warnings: tuple[str, ...] | list[str] = (), url: str) -> dict:
    return envelope(
        "datagov-au",
        data,
        urls=[url],
        cache=cache,
        data_as_of=_as_of(data),
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _as_of(data) -> str | None:
    if isinstance(data, dict):
        modified = data.get("modified")
        return str(modified) if modified else None
    if isinstance(data, list):
        dates = [
            str(row.get("modified"))
            for row in data
            if isinstance(row, dict) and row.get("modified")
        ]
        return max(dates) if dates else None
    return None


def _load(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _decode(body: bytes) -> str | None:
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("datagov-au", connector)
