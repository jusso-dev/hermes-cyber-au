"""Contract checks for every connector package, including freshly generated stubs."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import re
import sys
import time
from pathlib import Path

import jsonschema
import pytest
from cyberau_common.scaffold import generate
from cyberau_common.server import build_server, get_connector

ROOT = Path(__file__).resolve().parents[2]
ENVELOPE = {
    "type": "object",
    "required": ["source", "retrieved_at", "cache", "data", "untrusted"],
    "properties": {
        "source": {"type": "string"},
        "source_urls": {"type": "array", "items": {"type": "string"}},
        "retrieved_at": {"type": "string"},
        "data_as_of": {"type": ["string", "null"]},
        "cache": {"enum": ["hit", "miss", "stale", "snapshot"]},
        "attribution": {"type": "string"},
        "untrusted": {"const": True},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "data": {},
    },
}
_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{2,40}$")
_SECRET_HEADER = re.compile(
    r"(?i)(authorization|auth-key|x-otx-api-key|x-api-key)\s*:\s*(?!\[REDACTED\]|\s*$)\S+"
)


def _repo_connectors() -> list[Path]:
    found = []
    mcp = ROOT / "mcp"
    if not mcp.is_dir():
        return found
    # org-exposure is the watchlist skill library, not a feed connector.
    libraries = {"common", "org-exposure"}
    for path in sorted(mcp.glob("*/pyproject.toml")):
        if path.parent.name not in libraries:
            found.append(path.parent)
    return found


def _sample_arguments(schema: dict) -> dict:
    properties = schema.get("properties") or {}
    arguments = {}
    for name in schema.get("required") or []:
        arguments[name] = _sample_value(properties.get(name) or {})
    return arguments


def _sample_value(prop: dict):
    if prop.get("type") == "array":
        return [_sample_value(prop.get("items") or {"type": "string"})]
    if "enum" in prop:
        return prop["enum"][0]
    pattern = str(prop.get("pattern") or "")
    if "CVE" in pattern:
        return "CVE-2024-3400"
    if "ism-" in pattern:
        return "ism-1173"
    if pattern.startswith("^") and not pattern.endswith("$"):
        body = pattern[1:]
        if re.fullmatch(r"(?:\\.|[A-Za-z0-9:/.])+", body):
            return body.replace("\\.", ".") + "example"
    if prop.get("type") == "integer":
        return int(prop.get("minimum", 1))
    if prop.get("type") == "number":
        return float(prop.get("minimum", 0))
    if prop.get("type") == "boolean":
        return False
    return "example"


def check_connector(package: Path) -> None:
    module_name = "cyberau_" + package.name.replace("-", "_")
    init = package / "src" / module_name / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        module_name,
        init,
        submodule_search_locations=[str(init.parent)],
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    module.__package__ = module_name
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    connector = get_connector(package.name)
    server = build_server(connector)
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    assert tools
    source = (package / "SOURCE.md").read_text(encoding="utf-8")
    for label in ("Upstream:", "Auth:", "Rate limit:", "Terms:", "Verified:"):
        assert label in source
    for name, tool in tools.items():
        assert _TOOL_NAME.match(name), name
        model_name = f"mcp__{connector.server_name}__{name}"
        assert len(model_name) <= 64, model_name
        assert tool.annotations.readOnlyHint is True
        schema_path = package / "schema" / f"{name}.input.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        cassettes = list((package / "tests" / "fixtures").glob(f"{name}*"))
        assert cassettes, name
        for cassette in cassettes:
            text = cassette.read_text(encoding="utf-8")
            assert not _SECRET_HEADER.search(text)
        result = asyncio.run(server.call_tool(name, _sample_arguments(schema)))
        payload = _payload(result)
        jsonschema.validate(payload, ENVELOPE)
        assert payload["cache"] in {"snapshot", "stale", "hit", "miss"}
        if payload["cache"] != "snapshot":
            assert payload["warnings"]


def _payload(result) -> dict:
    if isinstance(result, dict):
        return result
    if isinstance(result, tuple):
        for item in result:
            found = _payload(item)
            if found:
                return found
    if isinstance(result, list):
        for item in result:
            if hasattr(item, "text"):
                return json.loads(item.text)
    text = getattr(result, "text", None)
    if text:
        return json.loads(text)
    content = getattr(result, "content", None)
    if content:
        return _payload(content)
    structured = getattr(result, "structured_content", None) or getattr(
        result, "structuredContent", None
    )
    if isinstance(structured, dict):
        return structured
    raise AssertionError(f"cannot read tool result {type(result)!r}")


def test_repo_connector_contract():
    packages = _repo_connectors()
    if not packages:
        pytest.skip("no connector packages yet")
    for package in packages:
        check_connector(package)


def test_generated_stubs_pass_contract_quickly(tmp_path: Path):
    started = time.perf_counter()
    for index in range(20):
        key = f"stub{index:02d}"
        generate(tmp_path, key, server="stub", hosts=["example.com"])
        check_connector(tmp_path / "mcp" / key)
    assert time.perf_counter() - started < 60
