"""Read-only assessments from a ThreatSieve instance the operator already runs.

The only upstream call is ``POST /v1/assess`` from ThreatSieve ``docs/api.md``.
The JSON body field is ``observable``. Uploads, feedback, and other mutations
are not implemented.
"""

import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector

DEFAULT_BASE = "http://127.0.0.1:8787"
ASSESS_PATH = "/v1/assess"
# Stay under ThreatSieve's 5 requests a second deployment ceiling.
RATE = 4.0
BURST = 4
TTL = 15 * 60
ATTRIBUTION = (
    "ThreatSieve. Assessments come from the operator's own ThreatSieve instance "
    "under ThreatSieve's licence. Actor associations are not verified attribution."
)
_PACKAGE = Path(__file__).resolve().parents[2]
_RESPONSE_SCHEMA = _PACKAGE / "schema" / "threatsieve_assess.response.json"
_TRANSPORT = None
_SLEEPER = None
_RNG = None
_MAX_INDICATOR = 8192


def threatsieve_assess(indicator: str) -> dict:
    """Assessment for an indicator from a ThreatSieve instance."""
    text = "" if indicator is None else str(indicator).strip()
    if not text:
        return _envelope([], "snapshot", warnings=("indicator is required",))
    if len(text) > _MAX_INDICATOR:
        return _envelope(
            [],
            "snapshot",
            warnings=(f"indicator is longer than {_MAX_INDICATOR} characters",),
        )
    payload, cache, warning = _fetch(text)
    if payload is None:
        return _envelope([], cache, warnings=(warning or "ThreatSieve response was not usable",))
    problem = schema_drift(payload)
    if problem:
        return _envelope([], cache, warnings=(problem,))
    if not _matches(payload, text):
        note = (
            "no matching assessment in the offline snapshot or cache"
            if cache == "snapshot"
            else "ThreatSieve returned a different observable"
        )
        return _envelope([], cache, payload, warnings=(note,))
    record = _record(payload)
    persist_warning = _persist([record])
    warnings = tuple(item for item in (warning, persist_warning) if item)
    return _envelope([record], cache, payload, warnings=warnings)


def connector() -> Connector:
    return _ThreatSieveConnector()


class _ThreatSieveConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="threatsieve",
            server_name="threatsieve",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "threatsieve_assess",
                    "Assessment for an indicator from a ThreatSieve instance.",
                    threatsieve_assess,
                )
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            try:
                payload = _load_text(_snapshot_text())
            except OSError:
                return Probe(self.key, False, "ThreatSieve is unavailable")
            if payload is None:
                return Probe(self.key, False, "snapshot was not usable")
            problem = schema_drift(payload)
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        payload, _cache, warning = _fetch("example.com", force_live=True)
        if warning or payload is None:
            return Probe(self.key, False, warning or "ThreatSieve is unavailable")
        problem = schema_drift(payload)
        if problem:
            return Probe(self.key, False, problem)
        if not _matches(payload, "example.com"):
            return Probe(self.key, False, "live probe returned a different observable")
        return Probe(self.key, True, "live ok")


def schema_drift(payload: dict) -> str | None:
    """Return a drift message when the payload misses the stored response schema."""
    if not isinstance(payload, dict):
        return "ThreatSieve payload was not an object"
    try:
        schema = json.loads(_RESPONSE_SCHEMA.read_text(encoding="utf-8"))
        errors = sorted(
            jsonschema.Draft202012Validator(schema).iter_errors(payload),
            key=lambda err: [str(part) for part in err.path],
        )
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as exc:
        return "ThreatSieve schema drift, " + redact(str(exc))
    if not errors:
        return None
    return "ThreatSieve schema drift, " + errors[0].message


def request_cache_key(indicator: str) -> str:
    """Cache key for one assess call. The key does not contain the API secret."""
    secret = lookup("THREATSIEVE_API_KEY")
    data_dir = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-threatsieve"))
    cache = HttpCache(data_dir / "http_cache.sqlite")
    return cache.key("POST", _assess_url(), None, _key_body(indicator), _auth_scope(secret))


def _fetch(indicator: str, *, force_live: bool = False) -> tuple[dict | None, str, str]:
    snapshot = os.environ.get("CYBERAU_THREATSIEVE_SNAPSHOT")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if snapshot and not force_live:
        payload, problem = _read_snapshot()
        return payload, "snapshot", problem
    data_dir = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-threatsieve"))
    secret = lookup("THREATSIEVE_API_KEY")
    cache = HttpCache(data_dir / "http_cache.sqlite")
    key = request_cache_key(indicator)
    cached = cache.get(key)
    if cached and not force_live and (offline or cache.fresh(cached)):
        state = "hit" if cache.fresh(cached) else "stale"
        return _load_text(cached.body.decode("utf-8")), state, ""
    if offline:
        payload, problem = _read_snapshot()
        return payload, "snapshot", problem
    if not secret:
        return None, "snapshot", "Set THREATSIEVE_API_KEY to a ThreatSieve scoped API key"
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    client = HttpClient(
        "threatsieve",
        policy=EgressPolicy(allowlist, "threatsieve"),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=RATE,
        burst=BURST,
        window="rolling",
        auth_scope=_auth_scope(secret),
        transport=_TRANSPORT,
        sleeper=_SLEEPER,
        rng=_RNG,
    )
    try:
        response = client.post_json(
            _assess_url(),
            _body(indicator),
            headers={"authorization": f"Bearer {secret}"},
            ttl=TTL,
            skip_cache=force_live,
        )
    except EgressDenied as exc:
        return None, "snapshot", _safe(str(exc), secret)
    except (HttpError, TimeoutError) as exc:
        if force_live:
            return None, "snapshot", "ThreatSieve is unavailable"
        cached = cache.get(key)
        if cached:
            return _load_text(cached.body.decode("utf-8")), "stale", ""
        return None, "snapshot", "ThreatSieve is unavailable: " + _safe(str(exc), secret)
    finally:
        client.close()
    if response.status in (401, 403):
        return None, "snapshot", _auth_warning(response.status, _error_code(response))
    if response.status == 429:
        if force_live:
            return None, "snapshot", "ThreatSieve rate limit exceeded"
        cached = cache.get(key)
        if cached:
            return _load_text(cached.body.decode("utf-8")), "stale", ""
        return None, "snapshot", "ThreatSieve rate limit exceeded"
    if response.status >= 400:
        code = _error_code(response)
        detail = f"{response.status} {code}".strip()
        return None, "snapshot", f"ThreatSieve rejected the indicator ({detail})"
    return _load_text(response.body.decode("utf-8")), response.cache, ""


def _read_snapshot() -> tuple[dict | None, str]:
    try:
        return _load_text(_snapshot_text()), ""
    except OSError:
        return None, "ThreatSieve is unavailable"


def _snapshot_text() -> str:
    snapshot = os.environ.get("CYBERAU_THREATSIEVE_SNAPSHOT")
    path = Path(snapshot) if snapshot else _PACKAGE / "data" / "assess_domain.json"
    return path.read_text(encoding="utf-8")


def _assess_url() -> str:
    raw = (lookup("THREATSIEVE_URL") or DEFAULT_BASE).strip() or DEFAULT_BASE
    if "://" not in raw:
        raw = "http://" + raw
    parts = urlsplit(raw)
    host = parts.hostname
    scheme = (parts.scheme or "http").lower()
    if not host or scheme not in {"http", "https"}:
        parts = urlsplit(DEFAULT_BASE)
        host = parts.hostname or "127.0.0.1"
        scheme = "http"
    port = f":{parts.port}" if parts.port else ""
    return f"{scheme}://{host}{port}{ASSESS_PATH}"


def _body(indicator: str) -> dict:
    return {"observable": indicator}


def _key_body(indicator: str) -> bytes:
    encoded = json.dumps(_body(indicator), separators=(",", ":"), sort_keys=True).encode()
    return encoded + b"\n"


def _auth_scope(secret: str | None) -> str:
    if not secret:
        return "anonymous"
    return hashlib.sha256(secret.encode()).hexdigest()


def _matches(payload: dict, indicator: str) -> bool:
    observable = payload.get("observable")
    if not isinstance(observable, dict):
        return False
    wanted = indicator.casefold()
    for field in ("value", "normalizedValue"):
        value = observable.get(field)
        if isinstance(value, str) and value.casefold() == wanted:
            return True
    return False


def _record(payload: dict) -> dict:
    observable = payload.get("observable") if isinstance(payload.get("observable"), dict) else {}
    malicious = payload.get("malicious") if isinstance(payload.get("malicious"), dict) else {}
    role = payload.get("role") if isinstance(payload.get("role"), dict) else {}
    customer = payload.get("customer") if isinstance(payload.get("customer"), dict) else {}
    return {
        "assessment_id": payload.get("assessment_id"),
        "schema_version": payload.get("schema_version"),
        "observable_type": observable.get("type"),
        "observable": untrusted_text(str(observable.get("value") or ""), "threatsieve"),
        "classification": malicious.get("classification"),
        "probability": malicious.get("probability"),
        "role": role.get("value"),
        "severity": payload.get("severity"),
        "confidence": payload.get("confidence"),
        "attack": [
            item.get("techniqueId")
            for item in payload.get("attack") or []
            if isinstance(item, dict) and item.get("techniqueId")
        ],
        "actors": [
            {
                "id": item.get("id"),
                "name": untrusted_text(str(item.get("name") or ""), "threatsieve"),
                "association_probability": item.get("association_probability"),
            }
            for item in payload.get("actors") or []
            if isinstance(item, dict)
        ],
        "customer_priority": customer.get("priority"),
        "recommended_actions": [
            item.get("action")
            for item in payload.get("recommended_actions") or []
            if isinstance(item, dict) and item.get("action")
        ],
        "evidence": [
            untrusted_text(_evidence_text(item), "threatsieve")
            for item in payload.get("evidence") or []
            if isinstance(item, dict) and _evidence_text(item)
        ],
        "status": payload.get("status"),
        "demo": payload.get("demo"),
        "created_at": payload.get("created_at"),
    }


def _evidence_text(item: dict) -> str:
    parts: list[str] = []
    _strings(item.get("data"), parts)
    source = item.get("sourceName")
    if isinstance(source, str) and source.strip():
        parts.append(source.strip())
    if not parts and item.get("type"):
        parts.append(str(item["type"]))
    return " ".join(parts)


def _strings(value, found: list[str]) -> None:
    if isinstance(value, str):
        if value.strip():
            found.append(value.strip())
        return
    if isinstance(value, dict):
        for item in value.values():
            _strings(item, found)
    elif isinstance(value, list):
        for item in value:
            _strings(item, found)


def _persist(rows: list[dict]) -> str:
    if not rows:
        return ""
    try:
        directory = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-threatsieve"))
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "threatsieve-observations.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    except OSError:
        return "ThreatSieve history could not be written"
    return ""


def _envelope(
    data,
    cache: str,
    payload: dict | None = None,
    warnings: tuple[str, ...] = (),
) -> dict:
    as_of = None
    if isinstance(payload, dict) and payload.get("created_at"):
        as_of = str(payload["created_at"])
    return envelope(
        "threatsieve",
        data,
        urls=[_assess_url()],
        cache=cache,
        data_as_of=as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _load_text(text: str | None) -> dict | None:
    if text is None:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _error_code(response) -> str:
    payload = _load_text(response.body.decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        return ""
    error = payload.get("error")
    if isinstance(error, dict) and error.get("code"):
        return str(error["code"])
    return ""


def _auth_warning(status: int, code: str) -> str:
    detail = f"{status} {code}".strip()
    return f"ThreatSieve refused the request ({detail}). Check THREATSIEVE_API_KEY."


def _safe(text: str, secret: str | None) -> str:
    cleaned = redact(text)
    if secret:
        cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("threatsieve", connector)
