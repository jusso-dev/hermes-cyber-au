"""Cloudflare URL Scanner. Submits are Unlisted and approval-gated."""

import hashlib
import json
import os
import random
import re
import secrets
import sqlite3
import time
from pathlib import Path
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

DOCS = "https://developers.cloudflare.com/radar/investigate/url-scanner/"
API_ROOT = "https://api.cloudflare.com/client/v4/accounts"
ATTRIBUTION = (
    "Cloudflare URL Scanner. Successful scans are kept for 12 months. "
    "This connector only submits Unlisted scans, which are left out of the recent scans list. "
    "Not affiliated with Cloudflare."
)
_VISIBILITY = "Unlisted"
_PACKAGE = Path(__file__).resolve().parents[2]
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_ACCOUNT = re.compile(r"^[0-9a-fA-F]{32}$")
_LABEL = re.compile(r"[A-Za-z]{1,20}")
PROBE_SCAN_ID = "00000000-0000-4000-8000-000000000001"
RATE = 1 / 10
BURST = 4
RESULT_TTL = 365 * 24 * 3600
SUBMIT_TTL = 24 * 3600
_APPROVAL = "approval token is not valid for this URL"
_UNAVAILABLE = "unavailable: no cached or snapshot Cloudflare URL Scanner record"
_NO_MATCH = "no matching scan in the offline snapshot or cache"
_TRANSPORT = None
_RESOLVER = None
_SLEEP = time.sleep
_RNG = None


def urlscan_submit_unlisted(url: str, approval_token: str) -> dict:
    problem = _validate_url(url)
    if problem:
        return _fail(problem)
    problem = _approval_status(url, approval_token, consume=False)
    if problem:
        return _fail(problem)
    try:
        body = _submit_body(url)
    except RuntimeError as exc:
        return _fail(str(exc))
    if _offline():
        problem = _approval_status(url, approval_token, consume=True)
        if problem:
            return _fail(problem)
        return _offline_submit(url, body)
    creds = _credentials()
    if isinstance(creds, str):
        return _fail(creds)
    token, account = creds
    problem = _approval_status(url, approval_token, consume=True)
    if problem:
        return _fail(problem)
    return _live_submit(url, body, token, account)


def urlscan_get_result(scan_id: str) -> dict:
    problem = _validate_scan_id(scan_id)
    if problem:
        return _fail(problem)
    if _offline():
        return _offline_get(scan_id)
    creds = _credentials()
    if isinstance(creds, str):
        return _fail(creds)
    token, account = creds
    return _live_get(scan_id, token, account, force_live=False)


def issue_unlisted_approval(url: str, *, ttl_seconds: int = 900) -> str:
    """Issue a one-time token after a person approves an Unlisted scan of this URL."""
    problem = _validate_url(url)
    if problem:
        raise ValueError(problem)
    if ttl_seconds < 0:
        raise ValueError("ttl_seconds must be zero or greater")
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    with _approvals() as conn:
        conn.execute(
            """
            INSERT INTO approvals (token_hash, url, expires_at, used)
            VALUES (?, ?, ?, 0)
            """,
            (digest, url, time.time() + ttl_seconds),
        )
    return token


def render_mcp_enabled(previous: bool | None) -> bool:
    """Fresh installs stay off. A profile update keeps the user's enabled flag.

    Both Cloudflare variables are read so a future edit cannot treat "key present"
    as a reason to turn the server on. The values are ignored on purpose.
    """
    lookup("CLOUDFLARE_URLSCAN_API_TOKEN")
    lookup("CLOUDFLARE_ACCOUNT_ID")
    if previous is None:
        return False
    return bool(previous)


def connector() -> Connector:
    return _CfscanConnector()


class _CfscanConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="cloudflare-urlscanner",
            server_name="cfscan",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "urlscan_submit_unlisted",
                    "Submit a URL with Unlisted visibility, after human approval.",
                    urlscan_submit_unlisted,
                ),
                ToolSpec(
                    "urlscan_get_result",
                    "Poll and return verdict, final URL, IPs and ASNs.",
                    urlscan_get_result,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            document = _snapshot_document()
            if document is None:
                return Probe(self.key, False, "snapshot is missing")
            problem = schema_drift(document)
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        creds = _credentials()
        if isinstance(creds, str):
            return Probe(self.key, False, creds)
        token, account = creds
        status, payload, _cache, warning = _exchange(
            "GET",
            _result_url(account, PROBE_SCAN_ID),
            token,
            _scope(account),
            body=None,
            ttl=60,
            force_live=True,
        )
        if status in (401, 403):
            return Probe(self.key, False, warning or _auth_message(status))
        if status is None:
            return Probe(self.key, False, warning or "live probe failed")
        if status == 200 and isinstance(payload, dict):
            problem = schema_drift(payload)
            if problem:
                return Probe(self.key, False, problem)
            problem = _check_records(
                "urlscan_get_result",
                [_result_record(PROBE_SCAN_ID, payload, token)],
            )
            if problem:
                return Probe(self.key, False, problem)
        if status in (200, 404):
            return Probe(self.key, True, "live ok")
        return Probe(
            self.key,
            False,
            warning or f"Cloudflare URL Scanner returned {status}.",
        )


def schema_drift(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return "URL Scanner payload was not an object"
    target = payload.get("result") if isinstance(payload.get("result"), dict) else payload
    if not isinstance(target, dict):
        return "URL Scanner payload was not an object"
    if any(name in target for name in ("page", "verdicts", "lists")):
        page = target.get("page")
        verdicts = target.get("verdicts")
        if not isinstance(page, dict) or not isinstance(verdicts, dict):
            return "URL Scanner schema drift, missing page or verdicts"
        return None
    if "uuid" in payload or "uuid" in target:
        found = payload.get("uuid") if isinstance(payload.get("uuid"), str) else target.get("uuid")
        if not isinstance(found, str) or not found:
            return "URL Scanner schema drift, missing uuid"
        return None
    return "URL Scanner payload was not usable"


def _submit_body(url: str) -> dict:
    body = {"url": url, "visibility": _VISIBILITY}
    if body.get("visibility") != "Unlisted":
        raise RuntimeError("refusing to submit a scan that is not Unlisted")
    return body


def _live_submit(url: str, body: dict, token: str, account: str) -> dict:
    status, payload, cache, warning = _exchange(
        "POST",
        _scan_url(account),
        token,
        _scope(account),
        body=body,
        ttl=SUBMIT_TTL,
        force_live=False,
    )
    if status != 200 or warning:
        detail = warning or f"Cloudflare URL Scanner returned {status}."
        return _envelope([], cache, warnings=(detail,))
    if not isinstance(payload, dict):
        return _envelope([], cache, warnings=("Cloudflare URL Scanner payload was not usable",))
    return _finish_submit(url, payload, cache, token)


def _live_get(scan_id: str, token: str, account: str, *, force_live: bool) -> dict:
    status, payload, cache, warning = _exchange(
        "GET",
        _result_url(account, scan_id),
        token,
        _scope(account),
        body=None,
        ttl=RESULT_TTL,
        force_live=force_live,
    )
    if status is None or status in (401, 403, 429) or (warning and status != 404):
        detail = warning or "Cloudflare URL Scanner payload was not usable"
        return _envelope([], cache, warnings=(detail,))
    return _finish_result(scan_id, payload, cache, status or 0, token)


def _offline_submit(url: str, body: dict) -> dict:
    creds = _credentials()
    if not isinstance(creds, str):
        token, account = creds
        payload, state = _read_cache(
            "POST",
            _scan_url(account),
            _post_material(body),
            _scope(account),
        )
        if payload is not None:
            return _finish_submit(url, payload, state, token)
    snapshot = _snapshot_submit()
    if snapshot is not None and snapshot.get("url") == url:
        return _finish_submit(url, snapshot, "snapshot", "")
    if _snapshot_path() is None:
        return _fail(_UNAVAILABLE)
    return _fail(_NO_MATCH)


def _offline_get(scan_id: str) -> dict:
    creds = _credentials()
    if not isinstance(creds, str):
        token, account = creds
        payload, state = _read_cache(
            "GET",
            _result_url(account, scan_id),
            b"",
            _scope(account),
        )
        if payload is not None:
            return _finish_result(scan_id, payload, state, 200, token)
    snapshot = _snapshot_result()
    if snapshot is not None and _result_id(snapshot) == scan_id:
        return _finish_result(scan_id, snapshot, "snapshot", 200, "")
    if _snapshot_path() is None:
        return _fail(_UNAVAILABLE)
    return _fail(_NO_MATCH)


def _finish_submit(url: str, payload: dict, cache: str, token: str) -> dict:
    scan_id = payload.get("uuid")
    if not isinstance(scan_id, str) or not scan_id:
        return _envelope([], cache, warnings=("URL Scanner schema drift, missing uuid",))
    shown = str(payload.get("visibility") or "")
    if shown.lower() not in {"", "unlisted"}:
        label = shown if _LABEL.fullmatch(shown) else "other"
        return _envelope(
            [],
            cache,
            warnings=(
                f"Cloudflare reported visibility {label} for scan {scan_id}. "
                "This connector only sends Unlisted.",
            ),
        )
    message = str(payload.get("message") or "")
    record = {
        "scan_id": scan_id,
        "url": str(payload.get("url") or url),
        "visibility": "Unlisted",
        "api": str(payload.get("api") or ""),
        "message": _public_text(message, token) if message else "",
    }
    problem = _check_records("urlscan_submit_unlisted", [record])
    if problem:
        return _envelope([], cache, warnings=(problem,))
    _persist({"kind": "submit", **record})
    account = _account_or_blank()
    urls = [_scan_url(account)] if account else [DOCS]
    return _envelope([record], cache, urls=urls)


def _finish_result(scan_id: str, payload: dict | None, cache: str, status: int, token: str) -> dict:
    if status == 404:
        return _envelope(
            [_in_progress(scan_id)],
            cache,
            warnings=("Scan is still running. Poll again in 10 to 30 seconds.",),
        )
    if not isinstance(payload, dict):
        return _envelope([], cache, warnings=("Cloudflare URL Scanner payload was not usable",))
    problem = schema_drift(payload)
    if problem:
        return _envelope([], cache, warnings=(problem,))
    record = _result_record(scan_id, payload, token)
    if _empty_result(record):
        return _envelope([], cache, warnings=("scan result was empty",))
    problem = _check_records("urlscan_get_result", [record])
    if problem:
        return _envelope([], cache, warnings=(problem,))
    _persist({"kind": "result", **record})
    account = _account_or_blank()
    urls = [_result_url(account, scan_id)] if account else [DOCS]
    return _envelope([record], cache, urls=urls, as_of=_as_of(payload))


def _result_record(scan_id: str, payload: dict, token: str) -> dict:
    page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
    lists = payload.get("lists") if isinstance(payload.get("lists"), dict) else {}
    verdicts = payload.get("verdicts") if isinstance(payload.get("verdicts"), dict) else {}
    overall = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else {}
    flag = overall.get("malicious")
    if flag is True:
        verdict = "malicious"
    elif flag is False:
        verdict = "benign"
    else:
        verdict = "unknown"
    ips = _strings(lists.get("ips"))
    page_ip = str(page.get("ip") or "")
    if page_ip and page_ip not in ips:
        ips.append(page_ip)
    asns = _strings(lists.get("asns"))
    page_asn = str(page.get("asn") or "")
    if page_asn and page_asn not in asns:
        asns.append(page_asn)
    title = str(page.get("title") or "")
    categories = _strings(overall.get("categories"))
    return {
        "scan_id": scan_id,
        "status": "finished",
        "verdict": verdict,
        "final_url": str(page.get("url") or ""),
        "ips": ips,
        "asns": asns,
        "title": _public_text(title, token) if title else "",
        "categories": _public_text(", ".join(categories), token) if categories else "",
    }


def _in_progress(scan_id: str) -> dict:
    return {
        "scan_id": scan_id,
        "status": "in_progress",
        "verdict": "unknown",
        "final_url": "",
        "ips": [],
        "asns": [],
        "title": "",
        "categories": "",
    }


def _empty_result(record: dict) -> bool:
    return (
        record["verdict"] == "unknown"
        and not record["final_url"]
        and not record["ips"]
        and not record["asns"]
        and not record["title"]
        and not record["categories"]
    )


def _exchange(
    method: str,
    url: str,
    token: str,
    scope: str,
    *,
    body: dict | None,
    ttl: int,
    force_live: bool,
) -> tuple[int | None, dict | None, str, str]:
    client = _client(scope)
    headers = {"authorization": f"Bearer {token}"}
    try:
        if method == "POST":
            response = client.post_json(url, body or {}, headers=headers, ttl=ttl)
        else:
            response = client.get(
                url,
                headers=headers,
                ttl=ttl,
                skip_cache=force_live,
            )
    except (HttpError, EgressDenied, TimeoutError, RateLimited) as exc:
        return None, None, "snapshot", _safe(str(exc), token)
    finally:
        client.close()
    payload = _load_bytes(response.body)
    warning = ""
    if response.status in (401, 403):
        warning = _auth_message(response.status)
    elif response.status == 429:
        warning = (
            "Cloudflare URL Scanner returned 429. "
            "Honour the Retry-After delay before calling again."
        )
    elif response.status >= 400 and response.status != 404:
        warning = f"Cloudflare URL Scanner returned {response.status}."
    elif payload is None and response.status != 404:
        warning = "Cloudflare URL Scanner payload was not usable"
    return response.status, payload, response.cache, _safe(warning, token)


def _client(scope: str) -> HttpClient:
    data_dir = _data_dir()
    return HttpClient(
        "cloudflare-urlscanner",
        policy=EgressPolicy(
            _allowlist(),
            "cloudflare-urlscanner",
            resolver=_RESOLVER,
        ),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", sleeper=_SLEEP),
        user_agent=USER_AGENT,
        rate=RATE,
        burst=BURST,
        window="rolling",
        timeout=30,
        retries=3,
        auth_scope=scope,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
        rng=_RNG or random.random,
    )


def _approval_status(url: str, token: str, *, consume: bool) -> str:
    if not isinstance(token, str) or not token.strip():
        return _APPROVAL
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()
    with _approvals() as conn:
        row = conn.execute(
            "SELECT url, expires_at, used FROM approvals WHERE token_hash = ?",
            (digest,),
        ).fetchone()
        if row is None or row[0] != url or row[2] or row[1] <= now:
            return _APPROVAL
        if not consume:
            return ""
        updated = conn.execute(
            "UPDATE approvals SET used = 1 WHERE token_hash = ? AND used = 0",
            (digest,),
        )
        if updated.rowcount != 1:
            return _APPROVAL
    return ""


def _approvals() -> sqlite3.Connection:
    path = _data_dir() / "cfscan-approvals.sqlite"
    conn = sqlite3.connect(path, timeout=5)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS approvals (
            token_hash TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            expires_at REAL NOT NULL,
            used INTEGER NOT NULL
        )
        """
    )
    return conn


def _credentials() -> tuple[str, str] | str:
    token = lookup("CLOUDFLARE_URLSCAN_API_TOKEN")
    account = lookup("CLOUDFLARE_ACCOUNT_ID")
    missing = []
    if not token:
        missing.append("CLOUDFLARE_URLSCAN_API_TOKEN")
    if not account:
        missing.append("CLOUDFLARE_ACCOUNT_ID")
    if missing:
        return "Set " + " and ".join(missing) + " before calling Cloudflare URL Scanner."
    if not _ACCOUNT.fullmatch(account or ""):
        return "CLOUDFLARE_ACCOUNT_ID must be a 32 character account id."
    return token or "", account or ""


def _auth_message(status: int) -> str:
    return (
        f"Cloudflare URL Scanner returned {status}. "
        "Check CLOUDFLARE_URLSCAN_API_TOKEN and CLOUDFLARE_ACCOUNT_ID."
    )


def _validate_url(url: str) -> str:
    if not isinstance(url, str) or not url:
        return "url must be an absolute http or https URL"
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return "url must be an absolute http or https URL"
    if parts.username or parts.password:
        return "url must not contain userinfo"
    return ""


def _validate_scan_id(scan_id: str) -> str:
    if not isinstance(scan_id, str) or _UUID.fullmatch(scan_id) is None:
        return "scan_id must be a UUID"
    return ""


def _scan_url(account_id: str) -> str:
    return f"{API_ROOT}/{account_id}/urlscanner/v2/scan"


def _result_url(account_id: str, scan_id: str) -> str:
    return f"{API_ROOT}/{account_id}/urlscanner/v2/result/{scan_id}"


def _scope(account_id: str) -> str:
    return hashlib.sha256(account_id.encode()).hexdigest()


def _post_material(body: dict) -> bytes:
    encoded = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    return encoded + b"\n"


def _read_cache(method: str, url: str, material: bytes, scope: str) -> tuple[dict | None, str]:
    cache = HttpCache(_data_dir() / "http_cache.sqlite")
    key = cache.key(method, url, None, material, scope)
    item = cache.get(key)
    if item is None:
        return None, ""
    try:
        payload = _load(item.body.decode("utf-8"))
    except UnicodeDecodeError:
        return None, ""
    if payload is None:
        return None, ""
    state = "hit" if cache.fresh(item) else "stale"
    return payload, state


def _snapshot_path() -> Path | None:
    override = os.environ.get("CYBERAU_CFSCAN_SNAPSHOT")
    if override:
        path = Path(override)
        return path if path.is_file() else None
    bundled = _PACKAGE / "data" / "snapshot.json"
    return bundled if bundled.is_file() else None


def _snapshot_document() -> dict | None:
    path = _snapshot_path()
    if path is None:
        return None
    return _load(path.read_text(encoding="utf-8"))


def _snapshot_submit() -> dict | None:
    document = _snapshot_document()
    if not isinstance(document, dict):
        return None
    submit = document.get("submit")
    if isinstance(submit, dict):
        return submit
    if "uuid" in document and "page" not in document:
        return document
    return None


def _snapshot_result() -> dict | None:
    document = _snapshot_document()
    if not isinstance(document, dict):
        return None
    result = document.get("result")
    if isinstance(result, dict):
        return result
    if "page" in document or "verdicts" in document:
        return document
    return None


def _result_id(payload: dict) -> str:
    task = payload.get("task") if isinstance(payload.get("task"), dict) else {}
    return str(task.get("uuid") or payload.get("uuid") or "")


def _as_of(payload: dict) -> str | None:
    task = payload.get("task") if isinstance(payload.get("task"), dict) else {}
    value = str(task.get("time") or "")
    if value and len(value) <= 40 and "\n" not in value:
        return value
    return None


def _persist(row: dict) -> None:
    path = _data_dir() / "cfscan-observations.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def _check_records(name: str, records: list[dict]) -> str:
    schema = json.loads((_PACKAGE / "schema" / f"{name}.response.json").read_text(encoding="utf-8"))
    for record in records:
        try:
            jsonschema.validate(record, schema)
        except jsonschema.ValidationError as exc:
            return "response schema: " + exc.message
    return ""


def _public_text(value: str, token: str) -> str:
    cleaned = value.replace(token, "[REDACTED]") if token and token in value else value
    return untrusted_text(cleaned, "cloudflare-urlscanner")


def _safe(text: str, token: str) -> str:
    cleaned = redact(text)
    if token and token in cleaned:
        cleaned = cleaned.replace(token, "[REDACTED]")
    return cleaned


def _strings(value) -> list[str]:
    if not isinstance(value, list):
        return []
    found = []
    for item in value:
        if item is None:
            continue
        text = str(item).strip()
        if text and text not in found:
            found.append(text)
    return found


def _account_or_blank() -> str:
    account = lookup("CLOUDFLARE_ACCOUNT_ID") or ""
    if _ACCOUNT.fullmatch(account):
        return account
    return ""


def _offline() -> bool:
    return os.environ.get("CYBERAU_OFFLINE") == "1"


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-cfscan"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _allowlist() -> Path:
    override = os.environ.get("CYBERAU_EGRESS_ALLOWLIST")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


def _envelope(
    data,
    cache: str,
    *,
    warnings: tuple[str, ...] = (),
    urls: list[str] | None = None,
    as_of: str | None = None,
) -> dict:
    return envelope(
        "cloudflare-urlscanner",
        data,
        urls=urls or [DOCS],
        cache=cache,
        data_as_of=as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _fail(message: str) -> dict:
    return _envelope([], "snapshot", warnings=(message,))


def _load(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _load_bytes(body: bytes) -> dict | None:
    try:
        return _load(body.decode("utf-8"))
    except UnicodeDecodeError:
        return None


register_connector("cloudflare-urlscanner", connector)
