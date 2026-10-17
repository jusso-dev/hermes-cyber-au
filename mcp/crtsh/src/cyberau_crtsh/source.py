"""Read-only crt.sh certificate transparency search."""

import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector

API = "https://crt.sh/"
ATTRIBUTION = "Public certificate transparency data from crt.sh."
# One request every 5 seconds is the public ceiling. Burst 1 does not run ahead of it.
RATE = 1 / 5
BURST = 1
TIMEOUT = 90
RETRIES = 1
# The tool timeout is 120 s. The retried request may read for up to 90 s, so a 429 is retried
# only when Retry-After is short enough to leave room for it. A longer wait is not retried.
RETRY_WAIT_CAP = 15
CACHE_TTL = 24 * 3600
REQUIRED = (
    "serial_number",
    "common_name",
    "name_value",
    "issuer_name",
    "not_before",
    "not_after",
    "id",
)
# crt.sh dropped entry_timestamp from its JSON. It is used when present, else the id orders rows.
_HOST = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_SERIAL = re.compile(r"[0-9a-f]{1,128}")
_PACKAGE = Path(__file__).resolve().parents[2]
_TRANSPORT = None
_SLEEP = time.sleep
_CLOCK = time.monotonic
_RESPONSE_SCHEMA: dict | None = None


def crtsh_certs(
    domain: str,
    include_subdomains: bool = True,
    include_expired: bool = False,
) -> dict:
    host = _hostname(domain)
    if host is None:
        return _envelope([], "snapshot", warnings=("domain must be a hostname",))
    if not isinstance(include_subdomains, bool) or not isinstance(include_expired, bool):
        return _envelope([], "snapshot", warnings=("include flags must be booleans",))
    params = _params(
        host,
        include_subdomains=include_subdomains,
        include_expired=include_expired,
    )
    payload, cache, warning = _fetch(params)
    if not isinstance(payload, list):
        return _envelope([], cache, warnings=(warning or "crt.sh payload was not usable",))
    rows, problem, skipped = _rows(
        payload,
        domain=host,
        include_subdomains=include_subdomains,
        include_expired=include_expired,
    )
    warnings: list[str] = []
    if warning:
        warnings.append(warning)
    if skipped:
        warnings.append(f"{skipped} crt.sh rows skipped, serial number was not hexadecimal")
    if problem:
        warnings.append(problem)
        return _envelope([], cache, warnings=tuple(warnings))
    if not rows and cache == "snapshot":
        warnings.append("no matching certificate in the offline snapshot or cache")
    _persist(host, rows)
    newest = (rows[0]["logged_at"] or None) if rows else None
    return _envelope(rows, cache, warnings=tuple(warnings), data_as_of=newest)


def connector() -> Connector:
    return _CrtshConnector()


class _CrtshConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="crtsh",
            server_name="crtsh",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "crtsh_certs",
                    "Certificates for a domain, deduplicated.",
                    crtsh_certs,
                )
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            text = _snapshot_text()
            if text is None:
                return Probe(self.key, False, "crt.sh snapshot is missing")
            problem = schema_drift(_load(text))
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        params = _params("example.com", include_subdomains=False, include_expired=False)
        payload, _cache, warning = _fetch(params, force_live=True)
        if not isinstance(payload, list):
            return Probe(self.key, False, warning or "crt.sh payload was not usable")
        problem = schema_drift(payload)
        if problem:
            return Probe(self.key, False, problem)
        rows, row_problem, _skipped = _rows(
            payload,
            domain="example.com",
            include_subdomains=False,
            include_expired=False,
        )
        if row_problem:
            return Probe(self.key, False, row_problem)
        if not rows:
            return Probe(self.key, False, "live probe returned no certificates")
        mismatch = _schema_mismatch(rows)
        if mismatch:
            return Probe(self.key, False, mismatch)
        return Probe(self.key, True, "live ok")


def schema_drift(payload) -> str | None:
    if not isinstance(payload, list):
        return "crt.sh payload has no certificate list"
    if not payload:
        return None
    for row in payload:
        if not isinstance(row, dict):
            return "crt.sh schema drift, row is not an object"
        missing = [name for name in REQUIRED if name not in row]
        if missing:
            return "crt.sh schema drift, missing " + ", ".join(missing)
    return None


def _fetch(params: dict, *, force_live: bool = False) -> tuple[list | None, str, str]:
    snapshot = os.environ.get("CYBERAU_CRTSH_SNAPSHOT")
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    data_dir = _data_dir()
    cache = HttpCache(data_dir / "http_cache.sqlite")
    key = cache.key("GET", API, params, b"", "anonymous")
    if not force_live and not snapshot:
        cached = cache.get(key)
        if cached and (offline or cache.fresh(cached)):
            payload = _decode(cached.body)
            state = "hit" if cache.fresh(cached) else "stale"
            if not isinstance(payload, list):
                return None, state, "crt.sh cache entry was not usable"
            return payload, state, ""
    if offline or (snapshot and not force_live):
        text = _snapshot_text()
        if text is None:
            return None, "snapshot", "crt.sh is unavailable and no cache or snapshot matches"
        payload = _load(text)
        if not isinstance(payload, list):
            return None, "snapshot", "crt.sh payload was not usable"
        return payload, "snapshot", ""
    client = HttpClient(
        "crtsh",
        policy=EgressPolicy(_allowlist_path(), "crtsh"),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", clock=_CLOCK, sleeper=_SLEEP),
        user_agent=USER_AGENT,
        rate=RATE,
        burst=BURST,
        window="rolling",
        timeout=TIMEOUT,
        retries=RETRIES,
        max_retry_wait=RETRY_WAIT_CAP,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
    )
    try:
        try:
            response = client.get(API, params=params, ttl=CACHE_TTL, skip_cache=force_live)
        except EgressDenied as exc:
            return _failed(cache, key, force_live, redact(str(exc)), warn_with_cache=True)
        except Exception as exc:
            return _failed(cache, key, force_live, redact(str(exc)), warn_with_cache=False)
        if response.status in (401, 403):
            return _failed(
                cache,
                key,
                force_live,
                _auth_warning(response.status),
                warn_with_cache=True,
            )
        if response.status >= 400:
            return _failed(
                cache,
                key,
                force_live,
                f"upstream status {response.status}",
                warn_with_cache=False,
            )
        payload = _decode(response.body)
        if not isinstance(payload, list):
            return _failed(
                cache,
                key,
                force_live,
                "crt.sh payload was not usable",
                warn_with_cache=True,
            )
        return payload, response.cache, ""
    finally:
        client.close()


def _rows(
    payload: list,
    *,
    domain: str,
    include_subdomains: bool,
    include_expired: bool,
) -> tuple[list[dict], str | None, int]:
    problem = schema_drift(payload)
    if problem:
        return [], problem, 0
    # A serial is unique only within one issuer, so a second CA cannot hide a certificate
    # by reusing its serial.
    grouped: dict[tuple[str, str], list[dict]] = {}
    skipped = 0
    for row in payload:
        serial = _serial(row.get("serial_number"))
        if not serial:
            skipped += 1
            continue
        issuer = str(row.get("issuer_name") or "").strip().lower()
        grouped.setdefault((issuer, serial), []).append(row)
    now = _now()
    records = []
    for (_issuer, serial), group in grouped.items():
        best = max(group, key=_stamp)
        names = _merged_names(group)
        common = str(best.get("common_name") or "").strip()
        if not _matches(names, common, domain, include_subdomains):
            continue
        expired = _is_expired(str(best.get("not_after") or ""), now)
        if expired is True and not include_expired:
            continue
        ident = _crtsh_id(best.get("id"))
        if ident is None:
            return [], "crt.sh schema drift, id is not an integer", skipped
        records.append(
            {
                "serial_number": serial,
                "common_name": untrusted_text(common, "crtsh"),
                "names": [untrusted_text(name, "crtsh") for name in names],
                "issuer": untrusted_text(str(best.get("issuer_name") or ""), "crtsh"),
                "not_before": _timestamp(best.get("not_before")),
                "not_after": _timestamp(best.get("not_after")),
                "logged_at": _timestamp(best.get("entry_timestamp")),
                "crtsh_id": ident,
                "expired": expired is True,
            }
        )
    records.sort(key=lambda row: (row["logged_at"], row["crtsh_id"]), reverse=True)
    return records, None, skipped


def _params(domain: str, *, include_subdomains: bool, include_expired: bool) -> dict[str, str]:
    query = f"%.{domain}" if include_subdomains else domain
    params = {"q": query, "output": "json"}
    if not include_expired:
        params["exclude"] = "expired"
    return params


def _hostname(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().rstrip(".").lower()
    if _HOST.fullmatch(text) is None:
        return None
    return text


def _serial(value) -> str:
    if not isinstance(value, str):
        return ""
    text = value.replace(":", "").replace(" ", "").lower()
    return text if _SERIAL.fullmatch(text) else ""


def _timestamp(value) -> str:
    """Pass a timestamp through only when it parses, so upstream text cannot ride in a date."""
    if not isinstance(value, str) or _parse_time(value) is None:
        return ""
    return value.strip()


def _crtsh_id(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _stamp(row: dict) -> tuple[str, int]:
    return str(row.get("entry_timestamp") or ""), _crtsh_id(row.get("id")) or 0


def _merged_names(group: list[dict]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for row in sorted(group, key=_stamp, reverse=True):
        for name in _split_names(row.get("name_value")):
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            found.append(name)
    return found


def _split_names(value) -> list[str]:
    if not isinstance(value, str):
        return []
    names = []
    for part in value.replace(",", "\n").splitlines():
        name = part.strip().rstrip(".")
        if name:
            names.append(name)
    return names


def _matches(names: list[str], common: str, domain: str, include_subdomains: bool) -> bool:
    candidates = list(names)
    if common:
        candidates.append(common)
    return any(_name_matches(name, domain, include_subdomains) for name in candidates)


def _name_matches(name: str, domain: str, include_subdomains: bool) -> bool:
    text = name.strip().rstrip(".").lower()
    wildcard = text.startswith("*.")
    host = text[2:] if wildcard else text
    if host == domain and not wildcard:
        return True
    if include_subdomains and (host == domain or host.endswith("." + domain)):
        return True
    return False


def _is_expired(value: str, now: datetime) -> bool | None:
    parsed = _parse_time(value)
    if parsed is None:
        return None
    return parsed < now


def _parse_time(value: str) -> datetime | None:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1]
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _now() -> datetime:
    override = os.environ.get("CYBERAU_TODAY")
    if override:
        parsed = _parse_time(override)
        if parsed is not None:
            return parsed
    return datetime.now(UTC)


def _persist(domain: str, rows: list[dict]) -> None:
    if not rows:
        return
    directory = _data_dir()
    path = directory / "crtsh-observations.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            record = {"domain": domain, **row}
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def _failed(cache, key: str, force_live: bool, message: str, *, warn_with_cache: bool):
    if not force_live:
        cached = cache.get(key)
        if cached is not None:
            payload = _decode(cached.body)
            if isinstance(payload, list):
                return payload, "stale", message if warn_with_cache else ""
    return None, "snapshot", message


def _schema_mismatch(rows: list[dict]) -> str | None:
    validator = jsonschema.Draft202012Validator(_response_schema())
    for row in rows:
        errors = list(validator.iter_errors(row))
        if errors:
            return "crt.sh response schema mismatch: " + errors[0].message
    return None


def _response_schema() -> dict:
    global _RESPONSE_SCHEMA
    if _RESPONSE_SCHEMA is None:
        path = _PACKAGE / "schema" / "crtsh_certs.response.json"
        _RESPONSE_SCHEMA = json.loads(path.read_text(encoding="utf-8"))
    return _RESPONSE_SCHEMA


def _snapshot_text() -> str | None:
    snapshot = os.environ.get("CYBERAU_CRTSH_SNAPSHOT")
    path = Path(snapshot) if snapshot else _PACKAGE / "data" / "certs.json"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _load(text: str):
    cleaned = text.lstrip("\ufeff").strip()
    if not cleaned:
        return None
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def _decode(body: bytes):
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return _load(text)


def _auth_warning(status: int) -> str:
    return (
        f"crt.sh refused the request ({status}). "
        "No API key is sent; this connector has no credential env var."
    )


def _envelope(
    data,
    cache: str,
    warnings: tuple[str, ...] = (),
    data_as_of: str | None = None,
) -> dict:
    return envelope(
        "crtsh",
        data,
        urls=[API],
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-crtsh"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _allowlist_path() -> Path:
    override = os.environ.get("CYBERAU_EGRESS_ALLOWLIST")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("crtsh", connector)
