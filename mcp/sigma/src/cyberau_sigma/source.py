"""Read-only SigmaHQ detection rules."""

import hashlib
import io
import json
import os
import re
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, NamedTuple

import yaml
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

RELEASES_LATEST = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"
PACKAGES = (
    ("sigma_core.zip", "core"),
    ("sigma_core+.zip", "core+"),
    ("sigma_emerging_threats_addon.zip", "emerging-threats"),
)
ATTRIBUTION = (
    "Sigma rules by SigmaHQ are under the Detection Rule License (DRL) 1.1. "
    "Keep the rule id and author. "
    "https://github.com/SigmaHQ/Detection-Rule-License"
)
LEVELS = ("informational", "low", "medium", "high", "critical")
TARGETS = ("kusto", "splunk", "elasticsearch")
_Level = Literal["informational", "low", "medium", "high", "critical"]
_Target = Literal["kusto", "splunk", "elasticsearch"]
_Limit = Annotated[int, Field(ge=1, le=50)]
_RuleYaml = Annotated[str, Field(max_length=20000)]
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_TECHNIQUE = re.compile(r"(?i)^(?:attack\.)?(t\d{4}(?:\.\d{3})?)$")
_ATTACK_TAG = re.compile(r"(?i)^attack\.(t\d{4}(?:\.\d{3})?)$")
_TAG = re.compile(r"^[A-Za-z0-9._+-]+$")
_PACKAGE = Path(__file__).resolve().parents[2]
_INDEX: dict[str, list[dict]] = {}
_TRANSPORT = None
_SLEEP = time.sleep


class _Loaded(NamedTuple):
    rules: list[dict] | None
    cache: str
    warning: tuple[str, ...]
    tag: str
    as_of: str | None
    urls: list[str]


def sigma_search(
    query: str | None = None,
    technique_id: str | None = None,
    product: str | None = None,
    service: str | None = None,
    level: _Level | None = None,
    limit: _Limit = 10,
) -> dict:
    checked, problem = _filters(query, technique_id, product, service, level, limit)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    loaded = _corpus()
    if loaded.rules is None:
        warnings = loaded.warning or ("Sigma rules are unavailable",)
        return _envelope([], loaded.cache, loaded.urls, loaded.as_of, warnings)
    rows = [_public(rule) for rule in loaded.rules if _matches(rule, checked)]
    rows.sort(key=lambda row: row["id"])
    warnings = list(loaded.warning)
    if not rows:
        warnings.append("no rules match")
    return _envelope(
        rows[: checked["limit"]],
        loaded.cache,
        loaded.urls,
        loaded.as_of,
        tuple(warnings),
    )


def sigma_get(rule_id: str) -> dict:
    normalised = _uuid(rule_id)
    if not normalised:
        return _envelope(None, "snapshot", warnings=("rule_id is not a UUID",))
    loaded = _corpus()
    if loaded.rules is None:
        warnings = loaded.warning or ("Sigma rules are unavailable",)
        return _envelope(None, loaded.cache, loaded.urls, loaded.as_of, warnings)
    match = next((rule for rule in loaded.rules if rule["id"] == normalised), None)
    if match is None:
        return _envelope(
            None,
            loaded.cache,
            loaded.urls,
            loaded.as_of,
            loaded.warning + (f"no rule matches {normalised}",),
        )
    return _envelope(
        _public(match, include_yaml=True),
        loaded.cache,
        loaded.urls,
        loaded.as_of,
        loaded.warning,
    )


def sigma_convert(
    target: _Target,
    rule_id: str | None = None,
    rule_yaml: _RuleYaml | None = None,
) -> dict:
    if target not in TARGETS:
        return _envelope(None, "snapshot", warnings=("target is not a known value",))
    if isinstance(rule_yaml, str) and len(rule_yaml) > 20000:
        return _envelope(None, "snapshot", warnings=("rule_yaml is longer than 20000 characters",))
    supplied = rule_yaml.strip() if isinstance(rule_yaml, str) else ""
    warnings: list[str] = []
    cache = "snapshot"
    urls = [RELEASES_LATEST]
    as_of = None
    release = None
    if supplied and rule_id:
        warnings.append("rule_yaml was converted and rule_id was ignored")
    if not supplied:
        normalised = _uuid(rule_id) if isinstance(rule_id, str) else ""
        if not isinstance(rule_id, str) or not rule_id.strip():
            return _envelope(None, "snapshot", warnings=("provide rule_id or rule_yaml",))
        if not normalised:
            return _envelope(None, "snapshot", warnings=("rule_id is not a UUID",))
        loaded = _corpus()
        cache, urls, as_of, release = loaded.cache, loaded.urls, loaded.as_of, loaded.tag or None
        warnings.extend(loaded.warning)
        if loaded.rules is None:
            warnings.append("Sigma rules are unavailable")
            return _envelope(None, cache, urls, as_of, tuple(warnings))
        match = next((rule for rule in loaded.rules if rule["id"] == normalised), None)
        if match is None:
            warnings.append(f"no rule matches {normalised}")
            return _envelope(None, cache, urls, as_of, tuple(warnings))
        supplied = match["yaml"]
        release = match["release"] or release
    queries, problem, meta = _convert(supplied, target)
    if problem:
        warnings.append(problem)
        return _envelope(None, cache, urls, as_of, tuple(warnings))
    data = {
        "id": meta["id"],
        "author": untrusted_text(meta["author"], "sigma"),
        "target": target,
        "queries": [untrusted_text(query, "sigma") for query in queries],
        "release": release,
    }
    return _envelope(data, cache, urls, as_of, tuple(warnings))


def connector() -> Connector:
    return _SigmaConnector()


class _SigmaConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="sigma",
            server_name="sigma",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "sigma_search",
                    "Search Sigma rules by keyword, ATT&CK technique, log source or level.",
                    sigma_search,
                ),
                ToolSpec("sigma_get", "One Sigma rule by id, as YAML.", sigma_get),
                ToolSpec(
                    "sigma_convert",
                    "Convert a stored rule or supplied YAML to Kusto, Splunk or Elasticsearch.",
                    sigma_convert,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            payload = _loads(_release_text(_root()))
            problem = schema_drift(payload)
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        payload, _cache, warning = _release(force_live=True)
        if warning:
            return Probe(self.key, False, warning[0])
        problem = schema_drift(payload)
        if problem:
            return Probe(self.key, False, problem)
        if not _known_package(payload):
            return Probe(
                self.key,
                False,
                "Sigma release has no core, core+ or emerging threats package",
            )
        return Probe(self.key, True, "live ok")


def schema_drift(payload) -> str | None:
    if not isinstance(payload, dict):
        return "Sigma payload is not an object"
    missing = [name for name in ("tag_name", "assets") if name not in payload]
    if missing:
        return "Sigma schema drift, missing " + ", ".join(missing)
    if not isinstance(payload.get("tag_name"), str) or not payload["tag_name"].strip():
        return "Sigma schema drift, missing tag_name"
    assets = payload.get("assets")
    if not isinstance(assets, list):
        return "Sigma schema drift, missing assets"
    if not assets:
        return None
    first = assets[0]
    if not isinstance(first, dict):
        return "Sigma schema drift, missing name"
    missing_asset = [name for name in ("name", "browser_download_url") if name not in first]
    if missing_asset:
        return "Sigma schema drift, missing " + ", ".join(missing_asset)
    return None


def _filters(query, technique_id, product, service, level, limit) -> tuple[dict | None, str]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        return None, "limit must be between 1 and 50"
    chosen = {
        "query": "",
        "technique": "",
        "product": "",
        "service": "",
        "level": "",
        "limit": limit,
    }
    if query is not None:
        if not isinstance(query, str):
            return None, "query must be a string"
        text = query.strip()
        if text and len(text) < 2:
            return None, "query must be at least 2 characters"
        chosen["query"] = text.casefold()
    if technique_id is not None and str(technique_id).strip():
        match = _TECHNIQUE.fullmatch(str(technique_id).strip())
        if not match:
            return None, "technique_id is not an ATT&CK technique id"
        chosen["technique"] = match.group(1).upper()
    if product is not None and str(product).strip():
        chosen["product"] = str(product).strip().casefold()
    if service is not None and str(service).strip():
        chosen["service"] = str(service).strip().casefold()
    if level is not None:
        if not isinstance(level, str) or level.lower() not in LEVELS:
            return None, "level is not a known value"
        chosen["level"] = level.lower()
    if not any(chosen[name] for name in ("query", "technique", "product", "service", "level")):
        return None, "provide a query, technique_id, product, service, or level"
    return chosen, ""


def _matches(rule: dict, chosen: dict) -> bool:
    if chosen["product"] and rule["product"].casefold() != chosen["product"]:
        return False
    if chosen["service"] and rule["service"].casefold() != chosen["service"]:
        return False
    if chosen["level"] and rule["level"] != chosen["level"]:
        return False
    if chosen["technique"] and not _technique_hit(rule["techniques"], chosen["technique"]):
        return False
    if chosen["query"]:
        haystack = " ".join(
            (
                rule["id"],
                rule["title"],
                rule["description"],
                rule["author"],
                rule["product"],
                rule["service"],
                rule["category"],
                " ".join(rule["tags"]),
                " ".join(rule["techniques"]),
            )
        ).casefold()
        if chosen["query"] not in haystack:
            return False
    return True


def _technique_hit(techniques: list[str], wanted: str) -> bool:
    prefix = wanted + "."
    return any(item == wanted or item.startswith(prefix) for item in techniques)


def _corpus(*, force_live: bool = False) -> _Loaded:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    pinned = bool(os.environ.get("CYBERAU_SIGMA_SNAPSHOT")) and not force_live
    if offline or pinned:
        return _snapshot_corpus()
    payload, cache, warning = _release(force_live=force_live)
    problem = schema_drift(payload)
    if problem or not isinstance(payload, dict):
        fallback = _snapshot_corpus()
        notes = warning + ((problem,) if problem else ()) + fallback.warning
        if fallback.rules is None:
            return fallback._replace(warning=notes or ("Sigma rules are unavailable",))
        state = "stale" if cache == "stale" else fallback.cache
        return fallback._replace(cache=state, warning=notes)
    blobs, blob_cache, blob_warning = _packages(payload, force_live=force_live)
    notes = warning + blob_warning
    tag = str(payload.get("tag_name") or "").strip()
    if not blobs:
        fallback = _snapshot_corpus()
        notes = notes + fallback.warning
        if fallback.rules is None:
            return _Loaded(
                None,
                "snapshot",
                notes or ("Sigma rules are unavailable",),
                tag,
                _as_of(payload),
                _urls(payload),
            )
        state = "stale" if "stale" in {cache, blob_cache} else fallback.cache
        return fallback._replace(cache=state, warning=notes)
    rules = _index(tag, blobs)
    if not rules:
        notes = notes + ("rule packages contained no rules",)
        return _Loaded(None, blob_cache, notes, tag, _as_of(payload), _urls(payload))
    state = "stale" if "stale" in {cache, blob_cache} else blob_cache
    return _Loaded(rules, state, notes, tag, _as_of(payload), _urls(payload))


def _snapshot_corpus() -> _Loaded:
    root = _root()
    text = _release_text(root)
    payload = _loads(text)
    problem = schema_drift(payload) if text is not None else "Sigma release snapshot is missing"
    if text is not None and payload is None:
        problem = "Sigma release payload was not usable"
    tag = ""
    if isinstance(payload, dict) and isinstance(payload.get("tag_name"), str):
        tag = payload["tag_name"].strip()
    zip_path = root / "rules_subset.zip"
    urls = _urls(payload) if isinstance(payload, dict) else [RELEASES_LATEST]
    if not zip_path.is_file():
        note = problem or "Sigma rules are unavailable"
        return _Loaded(None, "snapshot", (note,), tag, _as_of(payload), urls)
    try:
        rules = _index(tag or "snapshot", [("core", zip_path.read_bytes())])
    except (OSError, zipfile.BadZipFile):
        return _Loaded(
            None,
            "snapshot",
            ("Sigma rule snapshot was not usable",),
            tag,
            _as_of(payload),
            urls,
        )
    if not rules:
        return _Loaded(
            None,
            "snapshot",
            ("Sigma rule snapshot contained no rules",),
            tag,
            _as_of(payload),
            urls,
        )
    notes = (problem,) if problem else ()
    return _Loaded(rules, "snapshot", notes, tag, _as_of(payload), urls)


def _release(*, force_live: bool) -> tuple[object, str, tuple[str, ...]]:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    pinned = bool(os.environ.get("CYBERAU_SIGMA_SNAPSHOT")) and not force_live
    if offline or pinned:
        text = _release_text(_root())
        if text is None:
            return None, "snapshot", ("Sigma release snapshot is missing",)
        payload = _loads(text)
        if payload is None:
            return None, "snapshot", ("Sigma release payload was not usable",)
        return payload, "snapshot", ()
    body, cache, warning = _http(RELEASES_LATEST, api=True, ttl=12 * 3600, skip_cache=force_live)
    if body is None:
        message = _github_warning(warning or "live fetch failed")
        if force_live:
            return None, "snapshot", (message,)
        text = _release_text(_root())
        payload = _loads(text) if text else None
        if payload is None:
            return None, "snapshot", (message or "Sigma rules are unavailable",)
        return payload, "snapshot", (message,)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None, cache, ("Sigma release payload was not UTF-8",)
    payload = _loads(text)
    if payload is None:
        return None, cache, ("Sigma release payload was not usable",)
    return payload, cache, (warning,) if warning else ()


def _packages(
    payload: dict, *, force_live: bool
) -> tuple[list[tuple[str, bytes]], str, tuple[str, ...]]:
    tag = _safe_tag(str(payload.get("tag_name") or ""))
    by_name = {}
    for asset in payload.get("assets") or []:
        if isinstance(asset, dict) and isinstance(asset.get("name"), str):
            by_name[asset["name"]] = asset
    blobs: list[tuple[str, bytes]] = []
    warnings: list[str] = []
    cache = "miss"
    for name, package in PACKAGES:
        asset = by_name.get(name)
        if not isinstance(asset, dict):
            continue
        url = asset.get("browser_download_url")
        saved = _saved_zip(tag, name) if tag else None
        if saved is not None and not force_live:
            blobs.append((package, saved))
            cache = "hit" if cache != "stale" else cache
            continue
        if not isinstance(url, str) or not url.startswith("https://"):
            warnings.append(f"{name} has no download URL")
            continue
        body, state, warning = _http(url, api=True, ttl=7 * 86400, skip_cache=force_live)
        if body is None or not zipfile.is_zipfile(io.BytesIO(body)):
            if saved is not None:
                blobs.append((package, saved))
                warnings.append(warning or f"{name} fetch failed; served saved copy")
                cache = "stale"
                continue
            warnings.append(warning or f"{name} download failed")
            continue
        if tag:
            path = _data_dir() / tag / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        blobs.append((package, body))
        if state == "stale":
            cache = "stale"
        elif cache not in {"stale", "hit"}:
            cache = state
    if not blobs and not warnings:
        warnings.append("Sigma release has no core, core+ or emerging threats package")
    return blobs, cache, tuple(warnings)


def _http(url: str, *, api: bool, ttl: int, skip_cache: bool) -> tuple[bytes | None, str, str]:
    secret = lookup("GITHUB_TOKEN") if api else None
    headers = {"accept": "application/vnd.github+json"} if "api.github.com" in url else {}
    if secret:
        headers["authorization"] = f"Bearer {secret}"
    data_dir = _data_dir()
    client = HttpClient(
        "sigma",
        policy=EgressPolicy(_allowlist(), "sigma"),
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
        auth_scope="github" if secret else "anonymous",
    )
    try:
        _acquire()
        response = client.get(
            url,
            headers=headers,
            ttl=ttl,
            stale_if_error=7 * 86400,
            skip_cache=skip_cache,
        )
    except Exception as exc:
        return None, "snapshot", _clean(exc, secret)
    finally:
        client.close()
    if response.status in {401, 403}:
        return (
            None,
            response.cache,
            (
                f"GitHub refused the request ({response.status}). "
                "Set GITHUB_TOKEN to raise the rate limit."
            ),
        )
    if response.status == 429:
        return (
            None,
            response.cache,
            "GitHub rate limit returned 429. Set GITHUB_TOKEN to raise the limit.",
        )
    if response.status >= 400:
        return None, response.cache, f"upstream status {response.status}"
    warning = "served from cache after the live fetch failed" if response.cache == "stale" else ""
    return response.body, response.cache, warning


def _index(tag: str, blobs: list[tuple[str, bytes]]) -> list[dict]:
    digest = hashlib.sha256()
    for package, blob in blobs:
        digest.update(package.encode())
        digest.update(hashlib.sha256(blob).digest())
    key = f"{tag}:{digest.hexdigest()}"
    cached = _INDEX.get(key)
    if cached is not None:
        return cached
    found: list[dict] = []
    seen: set[str] = set()
    for package, blob in blobs:
        for rule in _rules_from_zip(blob, package, tag):
            if rule["id"] in seen:
                continue
            seen.add(rule["id"])
            found.append(rule)
    _INDEX[key] = found
    return found


def _rules_from_zip(blob: bytes, package: str, tag: str) -> list[dict]:
    found: list[dict] = []
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        for info in archive.infolist():
            if not _yaml_name(info.filename):
                continue
            try:
                text = archive.read(info).decode("utf-8")
            except (UnicodeDecodeError, RuntimeError, zipfile.BadZipFile):
                continue
            found.extend(_rules_from_yaml(text, package, tag))
    return found


def _rules_from_yaml(text: str, package: str, tag: str) -> list[dict]:
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return []
    found = []
    for document in documents:
        items = document if isinstance(document, list) else [document]
        for item in items:
            rule = _rule(item, package, tag)
            if rule is not None:
                found.append(rule)
    return found


def _rule(item, package: str, tag: str) -> dict | None:
    if not isinstance(item, dict):
        return None
    rule_id = _uuid(item.get("id"))
    if not rule_id:
        return None
    logsource = item.get("logsource") if isinstance(item.get("logsource"), dict) else {}
    tags = _tag_list(item.get("tags"))
    return {
        "id": rule_id,
        "title": str(item.get("title") or ""),
        "author": str(item.get("author") or ""),
        "description": str(item.get("description") or ""),
        "level": str(item.get("level") or "").lower(),
        "product": str(logsource.get("product") or ""),
        "service": str(logsource.get("service") or ""),
        "category": str(logsource.get("category") or ""),
        "tags": tags,
        "techniques": _techniques(tags),
        "yaml": yaml.safe_dump(item, sort_keys=False, allow_unicode=True),
        "package": package,
        "release": tag,
    }


def _convert(text: str, target: str) -> tuple[list[str] | None, str, dict]:
    meta = _meta(text)
    try:
        from sigma.collection import SigmaCollection

        collection = SigmaCollection.from_yaml(text)
        queries = [str(item) for item in _backend(target).convert(collection)]
    except ImportError:
        return None, "conversion backend is not installed", meta
    except Exception as exc:
        return None, "conversion failed: " + _short(exc), meta
    if not queries:
        return None, "conversion produced no query", meta
    return queries, "", meta


def _backend(target: str):
    if target == "kusto":
        from sigma.backends.kusto import KustoBackend

        return KustoBackend()
    if target == "splunk":
        from sigma.backends.splunk import SplunkBackend

        return SplunkBackend()
    from sigma.backends.elasticsearch import LuceneBackend

    return LuceneBackend()


def _meta(text: str) -> dict:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        document = None
    if not isinstance(document, dict):
        return {"id": "", "author": ""}
    return {"id": _uuid(document.get("id")), "author": str(document.get("author") or "")}


def _public(rule: dict, *, include_yaml: bool = False) -> dict:
    row = {
        "id": rule["id"],
        "title": untrusted_text(rule["title"], "sigma"),
        "author": untrusted_text(rule["author"], "sigma"),
        "description": untrusted_text(rule["description"], "sigma") if rule["description"] else "",
        "level": rule["level"],
        "product": rule["product"],
        "service": rule["service"],
        "category": rule["category"],
        "techniques": rule["techniques"],
        "tags": rule["tags"],
        "package": rule["package"],
        "release": rule["release"],
    }
    if include_yaml:
        row["yaml"] = untrusted_text(rule["yaml"], "sigma")
    return row


def _techniques(tags: list[str]) -> list[str]:
    found = []
    for tag in tags:
        match = _ATTACK_TAG.fullmatch(tag.strip())
        if match:
            found.append(match.group(1).upper())
    return found


def _tag_list(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None]


def _uuid(value) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not _UUID.fullmatch(text):
        return ""
    return text.lower()


def _yaml_name(name: str) -> bool:
    if not name.endswith((".yml", ".yaml")):
        return False
    parts = PurePosixPath(name).parts
    return bool(parts) and ".." not in parts and not name.startswith("/")


def _known_package(payload) -> bool:
    if not isinstance(payload, dict):
        return False
    names = {
        asset.get("name")
        for asset in payload.get("assets") or []
        if isinstance(asset, dict)
    }
    return any(name in names for name, _package in PACKAGES)


def _as_of(payload) -> str | None:
    if isinstance(payload, dict):
        published = payload.get("published_at")
        if isinstance(published, str) and published.strip():
            return published.strip()
        tag = payload.get("tag_name")
        if isinstance(tag, str) and tag.strip():
            return tag.strip()
    return None


def _urls(payload) -> list[str]:
    urls = [RELEASES_LATEST]
    if not isinstance(payload, dict):
        return urls
    wanted = {name for name, _package in PACKAGES}
    for asset in payload.get("assets") or []:
        if not isinstance(asset, dict) or asset.get("name") not in wanted:
            continue
        url = asset.get("browser_download_url")
        if isinstance(url, str) and url.startswith("https://"):
            urls.append(url)
    return urls


def _saved_zip(tag: str, name: str) -> bytes | None:
    path = _data_dir() / tag / name
    if not path.is_file():
        return None
    blob = path.read_bytes()
    if not zipfile.is_zipfile(io.BytesIO(blob)):
        return None
    return blob


def _safe_tag(tag: str) -> str:
    text = tag.strip()
    if not _TAG.fullmatch(text):
        return ""
    return text


def _release_text(root: Path) -> str | None:
    for name in ("release_latest.json", "release.json"):
        path = root / name
        if path.is_file():
            return path.read_text(encoding="utf-8")
    return None


def _loads(text: str | None):
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _root() -> Path:
    override = os.environ.get("CYBERAU_SIGMA_SNAPSHOT")
    return Path(override) if override else _PACKAGE / "data"


def _github_warning(message: str) -> str:
    if any(code in message for code in ("401", "403")) and "GITHUB_TOKEN" not in message:
        return f"{message} Set GITHUB_TOKEN to raise the rate limit."
    return message


def _clean(exc: Exception, secret: str | None) -> str:
    message = redact(str(exc))
    if secret:
        message = message.replace(secret, "[REDACTED]")
    return _github_warning(message)


def _short(exc: Exception) -> str:
    message = " ".join(str(exc).split())
    if len(message) > 300:
        message = message[:300]
    return message or exc.__class__.__name__


def _acquire() -> None:
    RateLimiter(_data_dir() / "rate_limit.sqlite", sleeper=_SLEEP).acquire(
        "sigma:github",
        rate=10 / 3600,
        burst=10,
        window="rolling",
        timeout=60,
    )


def _envelope(data, cache: str, urls=None, data_as_of: str | None = None, warnings=()):
    if isinstance(urls, str):
        urls = [urls]
    return envelope(
        "sigma",
        data,
        urls=list(urls or [RELEASES_LATEST]),
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-sigma"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("sigma", connector)
