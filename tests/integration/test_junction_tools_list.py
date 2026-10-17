"""Disabled Junction wrap: launch args and tools/list from release v0.1.16."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "mcp" / "junction" / "tests" / "fixtures" / "tools_list_v0.1.16.json"
LAUNCH = ["mcp", "serve", "--policy", "read-only"]
INCLUDED = ["junction_search", "junction_describe", "junction_execute"]
EXCLUDED = ["junction_batch", "junction_permissions", "junction_context"]
HOSTS = [
    "graph.microsoft.com",
    "management.azure.com",
    "api.loganalytics.io",
    "login.microsoftonline.com",
]
OPERATIONS = {
    "azure.log_analytics_query.query.execute",
    "graph.security.incidents.list",
    "graph.audit_logs.sign_ins.list",
}
_SECRET = re.compile(r"(?i)(authorization|client_secret|password|api[_-]?key)\s*[:=]\s*\S+")


def _servers() -> dict:
    data = yaml.safe_load((ROOT / "mcp" / "servers.yaml").read_text(encoding="utf-8"))
    return data["servers"]["junction"]


def _tools() -> list[dict]:
    messages = json.loads(FIXTURE.read_text(encoding="utf-8"))
    listed = next(message for message in messages if message.get("id") == 2)
    return listed["result"]["tools"]


def test_junction_entry_is_a_disabled_read_only_wrap():
    entry = _servers()
    assert entry["command"] == "${JUNCTION_BIN}"
    assert entry["args"] == LAUNCH
    assert entry["enabled_by_default"] is False
    assert entry["trust"] == "untrusted"
    assert entry["tools"]["include"] == INCLUDED
    assert "connector" not in entry
    allowlist = yaml.safe_load((ROOT / "mcp" / "egress-allowlist.yaml").read_text(encoding="utf-8"))
    assert allowlist["connectors"]["junction"]["hosts"] == HOSTS


def test_recorded_tools_list_matches_the_include_filter():
    messages = json.loads(FIXTURE.read_text(encoding="utf-8"))
    initialise = next(message for message in messages if message.get("id") == 1)
    assert initialise["result"]["serverInfo"] == {"name": "junction", "version": "0.1.16"}
    assert initialise["result"]["protocolVersion"] == "2025-11-25"
    tools = {tool["name"]: tool for tool in _tools()}
    assert list(tools) == [*INCLUDED, *EXCLUDED]
    assert tools["junction_search"]["annotations"]["readOnlyHint"] is True
    assert tools["junction_describe"]["annotations"]["readOnlyHint"] is True
    assert tools["junction_execute"]["annotations"]["readOnlyHint"] is False
    assert tools["junction_batch"]["annotations"]["readOnlyHint"] is False
    text = FIXTURE.read_text(encoding="utf-8")
    assert _SECRET.search(text) is None
    assert "eyJ" not in text


def test_docs_name_the_hunt_operations_and_the_readme_links_them():
    docs = (ROOT / "docs" / "connectors" / "junction.md").read_text(encoding="utf-8")
    skill = (ROOT / "skills" / "threat-hunting" / "references" / "junction.md").read_text(
        encoding="utf-8"
    )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    row = next(line for line in readme.splitlines() if line.startswith("| Junction "))
    for operation in OPERATIONS:
        assert operation in docs
        assert operation in skill
    assert "junction mcp serve --policy read-only" in docs
    assert "Junction is MIT and is not affiliated with Microsoft." in docs
    assert "Junction is MIT and is not affiliated with Microsoft." in skill
    assert "[docs/connectors/junction.md](docs/connectors/junction.md)" in row
    assert "| off |" in row
    assert "—" not in docs
    assert "—" not in skill
