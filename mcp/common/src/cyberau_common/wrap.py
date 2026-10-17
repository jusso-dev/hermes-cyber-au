"""Connectors that wrap an upstream MCP server instead of running local code.

A wrap is an entry in ``servers.yaml`` with ``kind: wrap``. Hermes connects to the upstream
server directly. This module renders that entry into Hermes ``mcp_servers`` config, filters the
upstream tool list, wraps results in the shared envelope, and probes the upstream for
``cyberau-mcp health``.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import os
from collections.abc import Awaitable, Callable, Iterable, Mapping
from pathlib import Path

import httpx
import jsonschema
import yaml

from cyberau_common.egress import EgressDenied, EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.secrets import redact
from cyberau_common.server import Probe

MCP_DIR = Path(__file__).resolve().parents[3]
FREE_TEXT_KEYS = frozenset({"description", "title", "notes", "comment"})

# Returns the upstream tool names and one payload per probe group.
Fetcher = Callable[[str, dict[str, str], list[dict], float], Awaitable[tuple[list[str], dict]]]


def load_servers(path: Path | None = None) -> dict:
    text = (path or MCP_DIR / "servers.yaml").read_text(encoding="utf-8")
    return (yaml.safe_load(text) or {}).get("servers") or {}


def find_wrap(connector: str, servers: Mapping[str, dict] | None = None) -> tuple[str, dict]:
    """Return the server name and entry for a wrap connector, or raise KeyError."""
    for name, entry in (servers if servers is not None else load_servers()).items():
        if entry.get("kind") == "wrap" and entry.get("connector") == connector:
            return name, entry
    raise KeyError(connector)


def render_entry(
    entry: Mapping,
    env: Mapping[str, str] | None = None,
    existing: Mapping | None = None,
) -> dict:
    """Render one wrap entry as a Hermes ``mcp_servers`` value.

    The token is only ever written as a ``${VAR}`` placeholder. ``existing`` is the user's
    current rendered entry: its ``enabled`` value is kept, so an update never switches a
    server on or off.
    """
    env = os.environ if env is None else env
    rendered: dict = {"url": entry["url"]}
    token_env = entry.get("token_env")
    if token_env and str(env.get(token_env) or "").strip():
        rendered["headers"] = {"Authorization": f"Bearer ${{{token_env}}}"}
    else:
        rendered["auth"] = entry.get("auth", "oauth")
    rendered["tools"] = {"include": list(entry["tools"]["include"])}
    if existing is not None and "enabled" in existing:
        rendered["enabled"] = bool(existing["enabled"])
    else:
        rendered["enabled"] = bool(entry.get("enabled_by_default", False))
    rendered["lazy"] = bool(entry.get("lazy", True))
    rendered["timeout"] = entry.get("timeout", 120)
    rendered["trust"] = entry.get("trust", "untrusted")
    return rendered


def filter_tools(names: Iterable[str], include: Iterable[str]) -> list[str]:
    patterns = list(include)
    return [name for name in names if any(fnmatch.fnmatchcase(name, pat) for pat in patterns)]


def unsafe_tools(tools: Iterable[Mapping]) -> list[str]:
    """Names of tools that are not read-only GET endpoints."""
    bad = []
    for tool in tools:
        hint = (tool.get("annotations") or {}).get("readOnlyHint")
        if not str(tool.get("name", "")).startswith("get_") or hint is False:
            bad.append(str(tool.get("name")))
    return bad


def read_expected(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def explain_http_error(status: int, headers: Mapping[str, str], token_env: str) -> str:
    if status in (401, 403):
        return (
            f"upstream refused the credential (HTTP {status}). Check {token_env} holds a token "
            "with Account > Radar > Read, or redo the OAuth grant."
        )
    if status == 429:
        wait = {key.lower(): value for key, value in headers.items()}.get("retry-after")
        suffix = f" Retry after {wait} seconds." if wait else ""
        return f"upstream rate limit reached (HTTP 429).{suffix}"
    return f"upstream answered HTTP {status}."


def wrap_result(
    source: str,
    payload,
    *,
    attribution: str,
    urls: Iterable[str] = (),
    cache: str = "miss",
    warnings: Iterable[str] = (),
) -> dict:
    """Put an upstream payload in the shared envelope. Never raises on a bad payload."""
    notes = list(warnings)
    data = None
    if not isinstance(payload, dict) or payload.get("success") is False or "result" not in payload:
        notes.append("upstream payload was not in the expected shape")
    else:
        data = _wrap_text(payload["result"], source)
        if not data:
            notes.append("no results")
    return envelope(
        source, data, urls=list(urls), cache=cache, attribution=attribution, warnings=notes
    )


def _wrap_text(value, source: str):
    if isinstance(value, dict):
        return {
            key: untrusted_text(item, source)
            if key in FREE_TEXT_KEYS and isinstance(item, str)
            else _wrap_text(item, source)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_wrap_text(item, source) for item in value]
    return value


def validate_response(schema_dir: Path, group: dict, payload) -> list[str]:
    """Return schema errors for one probe group payload. Empty means it matches."""
    schema = json.loads((schema_dir / group["schema"]).read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    return [
        f"{group['name']}: {'/'.join(map(str, error.path)) or '<root>'}: {error.message}"
        for error in validator.iter_errors(payload)
    ]


def run_wrap_health(
    connector: str,
    *,
    live: bool,
    check_schema: bool = False,
    servers: Mapping[str, dict] | None = None,
    root: Path | None = None,
    env: Mapping[str, str] | None = None,
    fetch: Fetcher | None = None,
    policy: EgressPolicy | None = None,
) -> Probe:
    try:
        name, entry = find_wrap(connector, servers)
    except KeyError:
        return Probe(connector, False, "unknown connector")
    package = (root or MCP_DIR) / connector
    probe = json.loads((package / "probe.json").read_text(encoding="utf-8"))
    schema_dir = package / "schema"
    if not entry.get("enabled_by_default", False):
        state = f"off by default: licence terms, see {entry['docs']}"
    else:
        state = "on"
    if not live:
        errors: list[str] = []
        if check_schema:
            for group in probe["groups"]:
                sample = json.loads((package / "tests" / group["fixture"]).read_text("utf-8"))
                errors += validate_response(schema_dir, group, sample)
        if errors:
            return Probe(connector, False, f"{state}; schema drift: {'; '.join(errors)}")
        return Probe(connector, True, f"{state}; offline ok")
    environ = os.environ if env is None else env
    if str(environ.get("CYBERAU_OFFLINE") or "").strip() in {"1", "true"}:
        return Probe(connector, True, f"{state}; unavailable: CYBERAU_OFFLINE is set")
    token_env = entry["token_env"]
    token = str(environ.get(token_env) or "").strip()
    if not token:
        return Probe(connector, True, f"{state}; live probe skipped: {token_env} is not set")
    try:
        (policy or _default_policy(connector)).check(entry["url"])
        names, payloads = asyncio.run(
            asyncio.wait_for(
                (fetch or _mcp_fetch)(
                    entry["url"],
                    {"Authorization": f"Bearer {token}"},
                    probe["groups"],
                    float(entry.get("timeout", 120)),
                ),
                timeout=float(entry.get("timeout", 120)) * (len(probe["groups"]) + 1),
            )
        )
    except EgressDenied as exc:
        return Probe(connector, False, f"egress refused: {exc}")
    except TimeoutError:
        return Probe(connector, False, f"{state}; unavailable: upstream timed out")
    except Exception as exc:  # noqa: BLE001 - probe reports every failure as text
        return Probe(connector, False, f"{state}; {_describe(exc, token_env)}")
    registered = filter_tools(names, entry["tools"]["include"])
    if not registered:
        return Probe(connector, False, f"{state}; upstream listed no tools matching the filter")
    expected = read_expected(package / "expected_tools.txt")
    missing = sorted(set(expected) - set(registered))
    unsafe = unsafe_tools({"name": n} for n in registered)
    if unsafe:
        return Probe(connector, False, f"{state}; non-GET tools matched: {', '.join(unsafe)}")
    errors = []
    for group in probe["groups"]:
        if group["name"] not in payloads:
            errors.append(f"{group['name']}: no response")
        else:
            errors += validate_response(schema_dir, group, payloads[group["name"]])
    if errors:
        return Probe(connector, False, f"{state}; schema drift: {'; '.join(errors)}")
    if missing:
        return Probe(connector, False, f"{state}; expected tools missing: {', '.join(missing)}")
    added = len(set(registered) - set(expected))
    note = f", {added} tools not in expected_tools.txt" if added else ""
    return Probe(connector, True, f"{state}; live ok, {len(registered)} tools{note}")


def _default_policy(connector: str) -> EgressPolicy:
    return EgressPolicy(MCP_DIR / "egress-allowlist.yaml", connector)


def _describe(exc: BaseException, token_env: str) -> str:
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    if isinstance(exc, httpx.HTTPStatusError):
        return explain_http_error(exc.response.status_code, dict(exc.response.headers), token_env)
    return redact(f"{type(exc).__name__}: {exc}")


async def _mcp_fetch(
    url: str, headers: dict[str, str], groups: list[dict], timeout: float
) -> tuple[list[str], dict]:
    """List upstream tools and make one cheap call per probe group over streamable HTTP."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    payloads: dict = {}
    async with streamablehttp_client(url, headers=headers, timeout=timeout) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            for group in groups:
                result = await session.call_tool(group["tool"], group["arguments"])
                payloads[group["name"]] = _parse_call(result)
    return [tool.name for tool in listed.tools], payloads


def _parse_call(result):
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    for item in getattr(result, "content", None) or []:
        text = getattr(item, "text", None)
        if text:
            try:
                return json.loads(text)
            except ValueError:
                return text
    return None
