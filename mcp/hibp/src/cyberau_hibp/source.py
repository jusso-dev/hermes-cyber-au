"""Read-only, pinned wrap of the official Have I Been Pwned MCP server.

Each tool is one `tools/call` to the official server. Nothing here reimplements an HIBP endpoint.
"""

import hashlib
import hmac
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector

MCP_URL = "https://haveibeenpwned.com/mcp"
ATTRIBUTION = (
    "Breach data from Have I Been Pwned (https://haveibeenpwned.com), licensed CC BY 4.0. "
    "Pwned Passwords range data from Have I Been Pwned."
)
PUBLIC_TOOLS = ("hibp_list_breaches", "hibp_get_breach", "hibp_get_pwned_passwords_range")
GATED_TOOLS = ("hibp_get_breached_account", "hibp_get_breached_domain")
TEST_ACCOUNT = "account-exists@hibp-integration-tests.com"

_PACKAGE = Path(__file__).resolve().parents[2]
_HEADERS = {"accept": "application/json, text/event-stream"}
_PREFIX = re.compile(r"^[0-9A-Fa-f]{5}$")
_ACCOUNT = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")
_DOMAIN = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_RESULT_KEYS = ("breaches", "breach", "matches", "breachesByAlias")
_BREACH_KEYS = ("Name", "Title", "BreachDate", "PwnCount", "DataClasses")
_TRANSPORT = None
_SLEEPER = None
_RESOLVER = None


class _PublicCache(HttpCache):
    """Never stores an error or an unreadable reply, so a 429 is not served for a day."""

    def put(self, key, *, status, headers, body, ttl):
        if not _usable(body):
            return
        super().put(key, status=status, headers=headers, body=body, ttl=ttl)


class _NoCache(HttpCache):
    """Account and domain results are personal information. Nothing touches the disk."""

    def __init__(self):
        pass

    def get(self, key):
        return None

    def put(self, key, **_kwargs):
        return None

    def touch(self, key):
        return None


def hibp_list_breaches(
    domain: str | None = None,
    is_spam_list: bool | None = None,
    include_unverified: bool = True,
    limit: int = 25,
    offset: int = 0,
) -> dict:
    problem = _page_problem(limit, offset) or _domain_problem(domain)
    if problem:
        return _envelope([], "snapshot", warnings=(problem,))
    arguments: dict = {"includeUnverified": include_unverified, "limit": limit, "offset": offset}
    if domain:
        arguments["domain"] = domain
    if is_spam_list is not None:
        arguments["isSpamList"] = is_spam_list
    payload, cache, warning = _fetch_public("hibp_list_breaches", arguments, ttl=24 * 3600)
    if warning or payload is None:
        return _envelope([], cache, warnings=(warning or "HIBP breach list was not usable",))
    drift = schema_drift("hibp_list_breaches", payload)
    if drift:
        return _envelope([], cache, warnings=(drift,))
    rows = [_breach(row) for row in payload["breaches"]]
    _observe(rows, cache)
    warnings = _snapshot_note(cache)
    return _envelope(
        {"breaches": rows, "total_count": payload.get("totalCount", len(rows)), **_page(payload)},
        cache,
        payload,
        warnings=warnings,
    )


def hibp_get_breach(name: str) -> dict:
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._ -]{1,80}", name):
        return _envelope(None, "snapshot", warnings=("name is not a breach name",))
    payload, cache, warning = _fetch_public("hibp_get_breach", {"name": name}, ttl=24 * 3600)
    if warning or payload is None:
        return _envelope(None, cache, warnings=(warning or "HIBP breach was not usable",))
    drift = schema_drift("hibp_get_breach", payload)
    if drift:
        return _envelope(None, cache, warnings=(drift,))
    row = _breach(payload["breach"])
    _observe([row], cache)
    return _envelope(row, cache, payload, warnings=_snapshot_note(cache))


def hibp_get_pwned_passwords_range(prefix: str, limit: int = 25, offset: int = 0) -> dict:
    if not isinstance(prefix, str) or not _PREFIX.match(prefix):
        return _envelope(
            None,
            "snapshot",
            warnings=(
                "prefix must be exactly 5 hexadecimal characters of a SHA-1 hash. "
                "Never pass a password or a full hash.",
            ),
        )
    problem = _page_problem(limit, offset)
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,))
    arguments = {"prefix": prefix.upper(), "addPadding": True, "limit": limit, "offset": offset}
    payload, cache, warning = _fetch_public(
        "hibp_get_pwned_passwords_range", arguments, ttl=24 * 3600
    )
    if warning or payload is None:
        return _envelope(None, cache, warnings=(warning or "HIBP range was not usable",))
    drift = schema_drift("hibp_get_pwned_passwords_range", payload)
    if drift:
        return _envelope(None, cache, warnings=(drift,))
    data = {
        "prefix": prefix.upper(),
        "matches": [
            {"hash_suffix": row["hashSuffix"], "count": row["count"]} for row in payload["matches"]
        ],
        "total_count": payload.get("totalCount", payload.get("matchCount")),
        **_page(payload),
    }
    return _envelope(data, cache, payload, warnings=_snapshot_note(cache))


def hibp_get_breached_account(
    account: str,
    domain: str | None = None,
    include_unverified: bool = True,
    response_mode: Literal["full", "truncated", "names"] = "names",
    limit: int = 25,
    offset: int = 0,
    approval_token: str | None = None,
) -> dict:
    tool = "hibp_get_breached_account"
    if not isinstance(account, str) or not _ACCOUNT.match(account):
        return _envelope(None, "snapshot", warnings=("account is not an email address",))
    problem = _page_problem(limit, offset) or _domain_problem(domain)
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,))
    blocked = _guard(tool, account, approval_token)
    if blocked:
        return _envelope(None, "snapshot", warnings=(blocked,))
    arguments: dict = {
        "account": account,
        "includeUnverified": include_unverified,
        "responseMode": response_mode,
        "limit": limit,
        "offset": offset,
    }
    if domain:
        arguments["domain"] = domain
    payload, cache, warning = _fetch_gated(tool, arguments)
    if warning or payload is None:
        return _envelope(None, cache, warnings=(warning or "HIBP account result was not usable",))
    drift = schema_drift(tool, payload)
    if drift:
        return _envelope(None, cache, warnings=(drift,))
    data = {
        "account_sha256": _digest(account)[:16],
        "breaches": [_breach_or_name(row) for row in payload["breaches"]],
        "total_count": payload.get("totalCount", len(payload["breaches"])),
        **_page(payload),
    }
    return _envelope(data, cache, warnings=("not stored: contains personal information",))


def hibp_get_breached_domain(
    domain: str,
    limit: int = 25,
    offset: int = 0,
    approval_token: str | None = None,
) -> dict:
    tool = "hibp_get_breached_domain"
    if not isinstance(domain, str) or not _DOMAIN.match(domain):
        return _envelope(None, "snapshot", warnings=("domain is not a domain name",))
    problem = _page_problem(limit, offset)
    if problem:
        return _envelope(None, "snapshot", warnings=(problem,))
    blocked = _guard(tool, domain, approval_token)
    if blocked:
        return _envelope(None, "snapshot", warnings=(blocked,))
    arguments = {"domain": domain, "limit": limit, "offset": offset}
    payload, cache, warning = _fetch_gated(tool, arguments)
    if warning or payload is None:
        return _envelope(None, cache, warnings=(warning or "HIBP domain result was not usable",))
    drift = schema_drift(tool, payload)
    if drift:
        return _envelope(None, cache, warnings=(drift,))
    data = {
        "domain_sha256": _digest(domain)[:16],
        "alias_count": payload.get("aliasCount", len(payload["breachesByAlias"])),
        "aliases": [
            {"alias": untrusted_text(str(alias), "hibp", 200), "breaches": [str(n) for n in names]}
            for alias, names in payload["breachesByAlias"].items()
        ],
        "total_count": payload.get("totalCount"),
        **_page(payload),
    }
    return _envelope(data, cache, warnings=("not stored: contains personal information",))


def connector() -> Connector:
    return _HibpConnector()


class _HibpConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="hibp",
            server_name="hibp",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "hibp_list_breaches",
                    "List public Have I Been Pwned breaches, optionally for one domain.",
                    hibp_list_breaches,
                ),
                ToolSpec(
                    "hibp_get_breach",
                    "One public breach by its HIBP name, for example Adobe.",
                    hibp_get_breach,
                ),
                ToolSpec(
                    "hibp_get_pwned_passwords_range",
                    "Pwned Passwords k-anonymity range for a 5 character SHA-1 prefix. "
                    "Hash locally. Never pass a password.",
                    hibp_get_pwned_passwords_range,
                ),
                ToolSpec(
                    "hibp_get_breached_account",
                    "Breaches for one email address. Needs human approval and an HIBP "
                    "subscription. Results are not stored.",
                    hibp_get_breached_account,
                ),
                ToolSpec(
                    "hibp_get_breached_domain",
                    "Breached aliases on one verified domain. Needs human approval and an HIBP "
                    "subscription. Results are not stored.",
                    hibp_get_breached_domain,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            problem = _snapshot_drift(_load_snapshot())
            return Probe(self.key, problem is None, problem or "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        probes = [
            ("hibp_list_breaches", {"limit": 1, "includeUnverified": True}),
            (
                "hibp_get_pwned_passwords_range",
                {"prefix": "21BD1", "addPadding": True, "limit": 1},
            ),
        ]
        for tool, arguments in probes:
            payload, _cache, warning = _fetch_public(tool, arguments, ttl=60, force_live=True)
            if warning or payload is None:
                return Probe(self.key, False, f"{tool}: {warning or 'no payload'}")
            problem = schema_drift(tool, payload)
            if problem:
                return Probe(self.key, False, f"{tool}: {problem}")
        if lookup("HIBP_API_KEY"):
            arguments = {"account": TEST_ACCOUNT, "responseMode": "names", "limit": 1}
            payload, _cache, warning = _fetch_gated("hibp_get_breached_account", arguments)
            if warning or payload is None:
                return Probe(self.key, False, f"hibp_get_breached_account: {warning}")
            problem = schema_drift("hibp_get_breached_account", payload)
            if problem:
                return Probe(self.key, False, f"hibp_get_breached_account: {problem}")
        return Probe(self.key, True, "live ok")


def issue_approval_token(tool: str, subject: str, key: str) -> str:
    """Token the `pre_tool_call` guard issues once a human approves one lookup."""
    message = f"{tool}:{_digest(subject)}".encode()
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


def schema_drift(tool: str, payload: dict) -> str | None:
    """Name the first field the wrapped server no longer returns, or None."""
    if tool == "hibp_list_breaches":
        rows = payload.get("breaches")
        if not isinstance(rows, list):
            return "HIBP schema drift, no breaches list"
        return _missing(rows, _BREACH_KEYS)
    if tool == "hibp_get_breach":
        row = payload.get("breach")
        if not isinstance(row, dict):
            return "HIBP schema drift, no breach object"
        return _missing([row], _BREACH_KEYS)
    if tool == "hibp_get_pwned_passwords_range":
        rows = payload.get("matches")
        if not isinstance(rows, list):
            return "HIBP schema drift, no matches list"
        problem = _missing(rows, ("hashSuffix", "count"))
        if problem:
            return problem
        if any(not isinstance(row["count"], int) for row in rows):
            return "HIBP schema drift, count is not a number"
        return None
    if tool == "hibp_get_breached_account":
        rows = payload.get("breaches")
        if not isinstance(rows, list):
            return "HIBP schema drift, no breaches list"
        return _missing([row for row in rows if isinstance(row, dict)], ("Name",))
    if tool == "hibp_get_breached_domain":
        if not isinstance(payload.get("breachesByAlias"), dict):
            return "HIBP schema drift, no breachesByAlias object"
        return None
    return f"HIBP tool {tool} is not in the frozen list"


def _missing(rows: list, keys: tuple[str, ...]) -> str | None:
    for row in rows:
        if not isinstance(row, dict):
            return "HIBP schema drift, row is not an object"
        for key in keys:
            if key not in row:
                return f"HIBP schema drift, missing {key}"
    return None


def _guard(tool: str, subject: str, token: str | None) -> str:
    """Block a personal-information lookup unless a human approved this exact one."""
    key = lookup("CYBERAU_APPROVAL_KEY")
    approved = bool(
        key and token and hmac.compare_digest(token, issue_approval_token(tool, subject, key))
    )
    _audit("allowed" if approved else "blocked", tool, subject)
    if approved:
        return ""
    return (
        f"{tool} needs a human approval for this lookup. It was not sent. "
        "Ask the user to approve it in the guard prompt, then retry with the approval token."
    )


def _audit(event: str, tool: str, subject: str) -> None:
    """One line per decision. The subject is a truncated hash, never the address or domain."""
    line = {
        "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "connector": "hibp",
        "event": event,
        "tool": tool,
        "subject_sha256": _digest(subject)[:16],
    }
    path = _audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, separators=(",", ":")) + "\n")


def _digest(subject: str) -> str:
    return hashlib.sha256(subject.strip().lower().encode()).hexdigest()


def _fetch_public(
    tool: str,
    arguments: dict,
    *,
    ttl: int,
    force_live: bool = False,
) -> tuple[dict | None, str, str]:
    """Return the wrapped server's structured content, the cache state, and a warning."""
    if os.environ.get("CYBERAU_HIBP_SNAPSHOT") and not force_live:
        return _from_snapshot(tool, arguments)
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    cache = _NoCache() if force_live else _PublicCache(_data_dir() / "http_cache.sqlite")
    client = _client(cache, "hibp", rate=1.0, burst=5, offline=offline)
    try:
        response = client.post_json(MCP_URL, _rpc_body(tool, arguments), headers=_HEADERS, ttl=ttl)
    except Exception as exc:
        if offline:
            return _from_snapshot(tool, arguments)
        return None, "snapshot", f"HIBP is unavailable: {redact(str(exc))}"
    finally:
        client.close()
    payload, warning = _structured(tool, response.status, response.headers, response.body)
    return payload, response.cache, warning


def _fetch_gated(tool: str, arguments: dict) -> tuple[dict | None, str, str]:
    secret = lookup("HIBP_API_KEY")
    if not secret:
        return (
            None,
            "snapshot",
            (
                "HIBP_API_KEY is not set. Account and domain lookups need an HIBP OAuth bearer "
                "token with an active subscription. Public tools work without it."
            ),
        )
    if os.environ.get("CYBERAU_OFFLINE") == "1":
        return None, "snapshot", "unavailable offline: account and domain lookups are never cached"
    client = _client(_NoCache(), "hibp-keyed", rate=10 / 60, burst=1, offline=False)
    try:
        response = client.post_json(
            MCP_URL,
            _rpc_body(tool, arguments),
            headers={**_HEADERS, "authorization": f"Bearer {secret}"},
            ttl=0,
        )
    except Exception as exc:
        message = redact(str(exc)).replace(secret, "[REDACTED]")
        return None, "snapshot", f"HIBP is unavailable: {message}"
    finally:
        client.close()
    payload, warning = _structured(tool, response.status, response.headers, response.body)
    return payload, "miss", warning


def _client(cache: HttpCache, name: str, *, rate: float, burst: int, offline: bool) -> HttpClient:
    data_dir = _data_dir()
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_allowlist())))
    return HttpClient(
        name,
        policy=EgressPolicy(allowlist, "hibp", resolver=_RESOLVER),
        cache=cache,
        limiter=RateLimiter(data_dir / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=rate,
        burst=burst,
        window="rolling",
        timeout=60,
        offline=offline,
        transport=_TRANSPORT,
        sleeper=_SLEEPER,
    )


def _rpc_body(tool: str, arguments: dict) -> dict:
    arguments = {**arguments, "response_format": "json"}
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def _rpc(body: bytes) -> dict | None:
    text = body.decode("utf-8", "replace")
    for line in reversed(text.splitlines()):
        if line.startswith("data:"):
            text = line[5:]
            break
    try:
        message = json.loads(text)
    except ValueError:
        return None
    return message if isinstance(message, dict) else None


def _usable(body: bytes) -> bool:
    result = (_rpc(body) or {}).get("result")
    if not isinstance(result, dict) or result.get("isError"):
        return False
    content = result.get("structuredContent")
    return isinstance(content, dict) and any(key in content for key in _RESULT_KEYS)


def _structured(tool: str, status: int, headers: dict, body: bytes) -> tuple[dict | None, str]:
    """Turn one upstream reply into structured content or a clear warning."""
    if status in (401, 403):
        return None, (
            f"HIBP rejected the credential in HIBP_API_KEY (HTTP {status}). {tool} needs an "
            "HIBP OAuth bearer token for the hibp.mcp scope and an active subscription. "
            "Public tools still work without it."
        )
    if status == 429:
        wait = headers.get("retry-after", "unknown")
        return None, f"HIBP rate limited this call. Retry after {wait} seconds."
    if status >= 400:
        return None, f"HIBP returned HTTP {status}"
    message = _rpc(body)
    result = message.get("result") if message else None
    if not isinstance(result, dict) or not isinstance(result.get("structuredContent"), dict):
        return None, "HIBP reply was not usable: no structured content"
    content = result["structuredContent"]
    if result.get("isError"):
        code = content.get("statusCode")
        if code in (401, 403):
            return _structured(tool, int(code), headers, body)
        if code == 404:
            return None, "HIBP has no match for that request"
        if code == 429:
            wait = content.get("retryAfterSeconds", "unknown")
            return None, f"HIBP rate limited this call. Retry after {wait} seconds."
        return None, "HIBP returned an error: " + redact(str(content.get("message", code)))[:200]
    return content, ""


def _from_snapshot(tool: str, arguments: dict) -> tuple[dict | None, str, str]:
    payload = _snapshot_payload(tool, arguments)
    if payload is None:
        return None, "snapshot", "no matching record in the offline snapshot or cache"
    return payload, "snapshot", ""


def _snapshot_payload(tool: str, arguments: dict) -> dict | None:
    snapshot = _load_snapshot()
    if not snapshot:
        return None
    limit = int(arguments.get("limit", 25))
    offset = int(arguments.get("offset", 0))
    if tool == "hibp_list_breaches":
        rows = snapshot.get("breaches") or []
        domain = str(arguments.get("domain") or "").lower()
        if domain:
            rows = [row for row in rows if str(row.get("Domain", "")).lower() == domain]
        return _page_payload("breaches", rows, limit, offset)
    if tool == "hibp_get_breach":
        wanted = str(arguments.get("name", "")).lower()
        for row in snapshot.get("breaches") or []:
            if str(row.get("Name", "")).lower() == wanted:
                return {"breach": row}
        return None
    if tool == "hibp_get_pwned_passwords_range":
        rows = (snapshot.get("ranges") or {}).get(str(arguments.get("prefix", "")).upper())
        return None if rows is None else _page_payload("matches", rows, limit, offset)
    return None


def _page_payload(key: str, rows: list, limit: int, offset: int) -> dict:
    page = rows[offset : offset + limit]
    more = offset + limit < len(rows)
    payload = {
        key: page,
        "totalCount": len(rows),
        "returnedCount": len(page),
        "offset": offset,
        "limit": limit,
        "hasMore": more,
    }
    if more:
        payload["nextOffset"] = offset + limit
    return payload


def _load_snapshot() -> dict | None:
    override = os.environ.get("CYBERAU_HIBP_SNAPSHOT")
    path = Path(override) if override else _PACKAGE / "data" / "snapshot.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _snapshot_drift(snapshot: dict | None) -> str | None:
    if snapshot is None:
        return "HIBP snapshot is missing or unreadable"
    problem = schema_drift("hibp_list_breaches", {"breaches": snapshot.get("breaches")})
    if problem:
        return problem
    for rows in (snapshot.get("ranges") or {}).values():
        problem = schema_drift("hibp_get_pwned_passwords_range", {"matches": rows})
        if problem:
            return problem
    return None


def _snapshot_note(cache: str) -> tuple[str, ...]:
    if cache != "snapshot":
        return ()
    return ("offline snapshot: partial, not the full HIBP catalogue",)


def _breach(row: dict) -> dict:
    return {
        "name": row.get("Name"),
        "title": untrusted_text(str(row.get("Title", "")), "hibp", 200),
        "domain": row.get("Domain"),
        "breach_date": row.get("BreachDate"),
        "added_date": row.get("AddedDate"),
        "modified_date": row.get("ModifiedDate"),
        "pwn_count": row.get("PwnCount"),
        "data_classes": list(row.get("DataClasses") or []),
        "description": untrusted_text(str(row.get("Description", "")), "hibp"),
        "is_verified": row.get("IsVerified"),
        "is_sensitive": row.get("IsSensitive"),
        "is_spam_list": row.get("IsSpamList"),
        "is_fabricated": row.get("IsFabricated"),
        "is_retired": row.get("IsRetired"),
        "is_malware": row.get("IsMalware"),
    }


def _breach_or_name(row) -> dict:
    if isinstance(row, dict):
        return _breach(row)
    return {"name": str(row)}


def _page(payload: dict) -> dict:
    return {
        "returned_count": payload.get("returnedCount"),
        "offset": payload.get("offset"),
        "limit": payload.get("limit"),
        "has_more": payload.get("hasMore"),
        "next_offset": payload.get("nextOffset"),
    }


def _page_problem(limit: int, offset: int) -> str:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        return "limit must be between 1 and 100"
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        return "offset must be 0 or more"
    return ""


def _domain_problem(domain: str | None) -> str:
    if domain and not _DOMAIN.match(domain):
        return "domain is not a domain name"
    return ""


def _observe(rows: list[dict], cache: str) -> None:
    """Keep public breach metadata for history. Account and domain results never come here."""
    if cache != "miss":
        return
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = _data_dir() / "hibp-observations.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            record = {
                "observed_at": stamp,
                "name": row["name"],
                "modified_date": row["modified_date"],
                "pwn_count": row["pwn_count"],
            }
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")


def _envelope(
    data,
    cache: str,
    payload: dict | None = None,
    warnings: tuple[str, ...] = (),
) -> dict:
    return envelope(
        "hibp",
        data,
        urls=[MCP_URL],
        cache=cache,
        data_as_of=_data_as_of(payload, cache),
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _data_as_of(payload: dict | None, cache: str) -> str | None:
    if payload is None:
        return None
    if cache == "snapshot":
        snapshot = _load_snapshot() or {}
        return snapshot.get("data_as_of")
    rows = payload.get("breaches") or [payload.get("breach")]
    stamps = [
        row["ModifiedDate"] for row in rows if isinstance(row, dict) and row.get("ModifiedDate")
    ]
    return max(stamps) if stamps else None


def _data_dir() -> Path:
    return Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-hibp"))


def _audit_path() -> Path:
    override = os.environ.get("CYBERAU_HIBP_AUDIT_LOG")
    return Path(override) if override else _data_dir() / "hibp-audit.jsonl"


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("hibp", connector)
