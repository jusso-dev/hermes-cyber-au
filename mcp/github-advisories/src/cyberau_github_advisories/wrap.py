"""Pinned, read-only wrap of the GitHub MCP server `security_advisories` toolset.

The wrapped binary does the work. This module checks the `ghsa` entry and the vendor lock,
filters the tool list, detects schema drift, shapes tool output into the result envelope, and
runs the health probe. It does not call the GitHub API itself.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path

import yaml
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Probe

KEY = "github-advisories"
SERVER = "ghsa"
SOURCE = "ghsa"
TOKEN_ENV = "GITHUB_ADVISORY_TOKEN"
UPSTREAM_TOKEN_ENV = "GITHUB_PERSONAL_ACCESS_TOKEN"
TOOLSET = "security_advisories"
INCLUDE = ("get_global_security_advisory", "list_global_security_advisories")
ATTRIBUTION = "GitHub Advisory Database, CC BY 4.0. https://github.com/advisories"
ADVISORIES_URL = "https://github.com/advisories"
FREE_TEXT = ("summary", "description")

_PACKAGE = Path(__file__).resolve().parents[2]
_MCP = _PACKAGE.parent
_PLACEHOLDER = re.compile(r"^[A-Z][A-Z0-9_]*=\$\{[A-Z][A-Z0-9_]*\}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_VERSION = re.compile(r"^v\d+\.\d+\.\d+$")


def load_entry(path: Path | None = None) -> dict:
    data = yaml.safe_load((path or _MCP / "servers.yaml").read_text(encoding="utf-8"))
    return data["servers"][SERVER]


def load_lock(path: Path | None = None) -> dict:
    return yaml.safe_load((path or _MCP / "vendor" / "github-mcp-server.lock").read_text("utf-8"))


def check_entry(entry: dict, lock: dict) -> list[str]:
    """Return every way the entry or lock departs from the read-only, pinned shape."""
    problems: list[str] = []
    if entry.get("connector") != KEY:
        problems.append("connector must be github-advisories")
    if entry.get("wrap") is not True:
        problems.append("wrap must be true")
    if entry.get("trust") != "untrusted":
        problems.append("trust must be untrusted")
    args = list(entry.get("args") or [])
    if args[:1] != ["stdio"]:
        problems.append("args must start with stdio")
    if "--read-only" not in args:
        problems.append("--read-only is missing")
    if _flag_values(args, "--toolsets") != [TOOLSET]:
        problems.append(f"--toolsets must be exactly {TOOLSET}")
    if "--tools" in args or "--dynamic-toolsets" in args:
        problems.append("--tools and --dynamic-toolsets would widen the tool set")
    if tuple((entry.get("tools") or {}).get("include") or ()) != INCLUDE:
        problems.append(f"tools.include must be exactly {list(INCLUDE)}")
    if not str(entry.get("command", "")).startswith("<PROFILE_HOME>/mcp/vendor/"):
        problems.append("command must sit under <PROFILE_HOME>/mcp/vendor/")
    expected_env = f"{UPSTREAM_TOKEN_ENV}=${{{TOKEN_ENV}}}"
    if list(entry.get("env") or []) != [expected_env]:
        problems.append(f"env must be exactly [{expected_env}]")
    for item in entry.get("env") or []:
        if not _PLACEHOLDER.match(item):
            problems.append("env values must be ${VAR} placeholders")
    if lock.get("name") != "github-mcp-server":
        problems.append("lock name is wrong")
    if not _VERSION.match(str(lock.get("version", ""))):
        problems.append("lock version must be an exact release tag")
    if not _COMMIT.match(str(lock.get("commit", ""))):
        problems.append("lock commit must be a 40 character SHA")
    assets = lock.get("assets") or {}
    if not assets:
        problems.append("lock has no assets")
    for name, asset in assets.items():
        if not _SHA256.match(str(asset.get("sha256", ""))):
            problems.append(f"lock asset {name} needs a sha256")
    return problems


def filter_tools(tools: list[dict], include: tuple[str, ...] = INCLUDE) -> list[dict]:
    """Keep only named tools, in the order the upstream listed them."""
    return [tool for tool in tools if tool.get("name") in include]


def schema_drift(tools_list: dict, schema_dir: Path | None = None) -> list[str]:
    """Compare a recorded or live tools/list with the stored input schemas."""
    directory = schema_dir or _PACKAGE / "schema"
    seen = {tool["name"]: tool for tool in filter_tools(tools_list.get("tools") or [])}
    drift: list[str] = []
    for name in INCLUDE:
        tool = seen.get(name)
        if tool is None:
            drift.append(f"{name}: tool is missing upstream")
            continue
        if (tool.get("annotations") or {}).get("readOnlyHint") is not True:
            drift.append(f"{name}: upstream no longer marks the tool read-only")
        ours = json.loads((directory / f"{name}.input.json").read_text(encoding="utf-8"))
        theirs = tool.get("inputSchema") or {}
        our_props = ours.get("properties") or {}
        their_props = theirs.get("properties") or {}
        for prop in sorted(set(our_props) - set(their_props)):
            drift.append(f"{name}: property {prop} is gone upstream")
        for prop in sorted(set(their_props) - set(our_props)):
            drift.append(f"{name}: new upstream property {prop}")
        for prop in sorted(set(our_props) & set(their_props)):
            if our_props[prop].get("type") != their_props[prop].get("type"):
                drift.append(f"{name}: property {prop} changed type")
            if our_props[prop].get("enum") != their_props[prop].get("enum"):
                drift.append(f"{name}: property {prop} changed its allowed values")
        if sorted(ours.get("required") or []) != sorted(theirs.get("required") or []):
            drift.append(f"{name}: required properties changed")
    return drift


def normalise(tool: str, payload, *, cache: str = "miss", retrieved_at: str | None = None) -> dict:
    """Shape one tool result into the envelope, wrapping free text as untrusted."""
    warnings: list[str] = []
    if tool == "list_global_security_advisories":
        rows = payload if isinstance(payload, list) else None
    elif tool == "get_global_security_advisory":
        rows = [payload] if isinstance(payload, dict) else None
    else:
        raise ValueError(f"{tool} is not a wrapped tool")
    records: list[dict] = []
    if rows is None:
        warnings.append("malformed upstream payload: no advisories returned")
    for row in rows or []:
        if not isinstance(row, dict) or not isinstance(row.get("ghsa_id"), str):
            warnings.append("dropped an upstream record with no ghsa_id")
            continue
        records.append(_record(row))
    if rows is not None and not records and not warnings:
        warnings.append("no advisories matched")
    data = records if tool == "list_global_security_advisories" else (records or [None])[0]
    updated = [row["updated_at"] for row in records if row.get("updated_at")]
    urls = [ADVISORIES_URL] + [row["html_url"] for row in records if row.get("html_url")]
    return envelope(
        SOURCE,
        data,
        urls=list(dict.fromkeys(urls)),
        cache=cache,
        data_as_of=max(updated) if updated else None,
        warnings=warnings,
        attribution=ATTRIBUTION,
        retrieved_at=retrieved_at,
    )


def error_envelope(message: str, *, retry_after: int | None = None) -> dict:
    """Turn an upstream tool error into a warning that names what to fix."""
    lowered = message.lower()
    if "429" in lowered or "rate limit" in lowered:
        wait = f"Retry after {retry_after} seconds." if retry_after else "Retry later."
        warning = f"GitHub rate limit reached. {wait} Setting {TOKEN_ENV} raises the limit."
    elif any(mark in lowered for mark in ("401", "403", "bad credentials", "authentication")):
        warning = (
            f"GitHub rejected the credentials. Check {TOKEN_ENV}: use a fine-grained token "
            "with no repository permissions."
        )
    else:
        warning = "upstream error: " + redact(message)[:200]
    return envelope(SOURCE, None, cache="miss", warnings=[warning], attribution=ATTRIBUTION)


def resolve_command(entry: dict, env: dict[str, str] | None = None) -> Path:
    source = os.environ if env is None else env
    home = Path(source.get("CYBERAU_PROFILE_HOME") or _MCP.parent)
    return Path(str(entry["command"]).replace("<PROFILE_HOME>", str(home)))


def health(*, live: bool, check_schema: bool = False) -> Probe:
    entry, lock = load_entry(), load_lock()
    problems = check_entry(entry, lock)
    if problems:
        return Probe(KEY, False, "; ".join(problems))
    if check_schema or not live:
        recorded = json.loads(
            (_PACKAGE / "tests" / "fixtures" / "tools_list.json").read_text(encoding="utf-8")
        )
        drift = schema_drift(recorded)
        if drift:
            return Probe(KEY, False, "schema drift: " + "; ".join(drift))
        if not live:
            return Probe(KEY, True, f"offline ok, pinned {lock['version']}")
    return asyncio.run(live_probe(entry, lock))


async def live_probe(entry: dict, lock: dict, *, timeout: float = 60.0) -> Probe:
    """One call per tool, validated against schema/*.response.json."""
    import jsonschema
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    token = lookup(TOKEN_ENV)
    if token is None:
        return Probe(
            KEY,
            False,
            f"set {TOKEN_ENV}: the pinned server will not start without a token",
        )
    command = resolve_command(entry)
    if not command.is_file():
        return Probe(KEY, False, f"pinned binary not installed at {command}")
    params = StdioServerParameters(
        command=str(command),
        args=list(entry["args"]),
        env={UPSTREAM_TOKEN_ENV: token, "PATH": os.environ.get("PATH", "")},
    )
    try:
        async with asyncio.timeout(timeout):
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    tools_list = {"tools": [tool.model_dump(mode="json") for tool in listed.tools]}
                    drift = schema_drift(tools_list)
                    if drift:
                        return Probe(KEY, False, "schema drift: " + "; ".join(drift))
                    found = await session.call_tool(
                        INCLUDE[1], {"type": "reviewed", "ecosystem": "pip", "severity": "critical"}
                    )
                    rows = _tool_json(found)
                    _validate(jsonschema, INCLUDE[1], rows)
                    if not rows:
                        return Probe(KEY, False, "list probe returned no advisories")
                    one = await session.call_tool(INCLUDE[0], {"ghsaId": rows[0]["ghsa_id"]})
                    _validate(jsonschema, INCLUDE[0], _tool_json(one))
    except Exception as exc:  # the probe reports any failure as a message, never a trace
        while isinstance(exc, BaseExceptionGroup):
            exc = exc.exceptions[0]
        return Probe(KEY, False, error_envelope(f"{type(exc).__name__}: {exc}")["warnings"][0])
    return Probe(KEY, True, f"live ok, pinned {lock['version']}")


def _validate(jsonschema, tool: str, payload) -> None:
    schema = json.loads((_PACKAGE / "schema" / f"{tool}.response.json").read_text("utf-8"))
    jsonschema.validate(payload, schema)


def _tool_json(result):
    if getattr(result, "isError", False):
        text = " ".join(getattr(item, "text", "") for item in result.content)
        raise RuntimeError(text or "upstream tool error")
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        return structured.get("result", structured) if isinstance(structured, dict) else structured
    return json.loads(result.content[0].text)


def _record(row: dict) -> dict:
    out = dict(row)
    for field in FREE_TEXT:
        if isinstance(out.get(field), str):
            out[field] = untrusted_text(out[field], SOURCE)
    return out


def _flag_values(args: list[str], flag: str) -> list[str]:
    values: list[str] = []
    for index, arg in enumerate(args):
        if arg == flag and index + 1 < len(args):
            values.extend(args[index + 1].split(","))
        elif arg.startswith(flag + "="):
            values.extend(arg.split("=", 1)[1].split(","))
    return values
