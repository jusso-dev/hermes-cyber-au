"""Create a connector package that satisfies the contract before any live logic exists."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml

_KEY = re.compile(r"^[a-z][a-z0-9-]{1,30}$")


def generate(root: Path, key: str, server: str, hosts: list[str]) -> Path:
    if not _KEY.match(key):
        raise ValueError(f"connector key {key!r} must be lowercase words separated by hyphens")
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,20}", server):
        raise ValueError(f"server name {server!r} is not a short lowercase token")
    cleaned = [host.strip().lower() for host in hosts if host.strip()]
    if not cleaned:
        raise ValueError("at least one egress host is required")
    module = "cyberau_" + key.replace("-", "_")
    tool = key.replace("-", "_") + "_status"
    package = root / "mcp" / key
    if (package / "pyproject.toml").exists():
        raise FileExistsError(package)
    src = package / "src" / module
    src.mkdir(parents=True)
    (package / "schema").mkdir()
    (package / "tests" / "fixtures").mkdir(parents=True)
    (package / "pyproject.toml").write_text(_pyproject(key, module), encoding="utf-8")
    (src / "__init__.py").write_text(
        "from .source import connector\n\n__all__ = ['connector']\n",
        encoding="utf-8",
    )
    (src / "source.py").write_text(_source(key, server, module, tool), encoding="utf-8")
    (package / "schema" / f"{tool}.input.json").write_text(
        '{\n  "type": "object",\n  "additionalProperties": false,\n  "properties": {}\n}\n',
        encoding="utf-8",
    )
    (package / "SOURCE.md").write_text(_source_md(key, cleaned), encoding="utf-8")
    (package / "tests" / "fixtures" / f"{tool}.yaml").write_text(
        "interactions: []\n# Stub cassette. No auth header values.\n",
        encoding="utf-8",
    )
    test_body = (
        f"def test_import():\n    import {module}\n    assert {module}.connector().key == {key!r}\n"
    )
    (package / "tests" / f"test_{module}.py").write_text(test_body, encoding="utf-8")
    _add_workspace_member(root / "mcp" / "pyproject.toml", key)
    _add_server(root / "mcp" / "servers.yaml", key, server)
    _add_hosts(root / "mcp" / "egress-allowlist.yaml", key, cleaned)
    return package


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="new_connector")
    parser.add_argument("key")
    parser.add_argument("--server", required=True)
    parser.add_argument("--hosts", required=True, help="Comma-separated egress hosts")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    generate(Path(args.root), args.key, args.server, args.hosts.split(","))
    return 0


def _pyproject(key: str, module: str) -> str:
    return f"""[project]
name = "cyberau-{key}"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["cyberau-common"]

[tool.uv.sources]
cyberau-common = {{ workspace = true }}

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/{module}"]
"""


def _source(key: str, server: str, module: str, tool: str) -> str:
    return f'''"""Stub connector for {key}. Replace the body before relying on it."""

from cyberau_common.server import Connector, ToolSpec, register_connector


def {tool}() -> dict:
    return {{"status": "stub", "connector": "{key}"}}


def connector() -> Connector:
    return Connector(
        key="{key}",
        server_name="{server}",
        attribution="{key} stub. No upstream data yet.",
        tools=[
            ToolSpec(
                name="{tool}",
                description="Report that the {key} connector is still a stub.",
                fn={tool},
                open_world=False,
            )
        ],
    )


register_connector("{key}", connector)
'''


def _source_md(key: str, hosts: list[str]) -> str:
    host_list = ", ".join(hosts)
    return f"""# {key}

- Upstream: https://example.com
- Auth: none
- Rate limit: no upstream calls in the stub
- Terms: replace this note before shipping real data
- Verified: 2026-10-16
- Egress hosts: {host_list}
"""


def _add_workspace_member(path: Path, key: str) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            '[project]\nname = "cyberau-workspace"\nversion = "0.1.0"\n'
            'requires-python = ">=3.11"\ndependencies = []\n\n'
            "[tool.uv.workspace]\n"
            f'members = ["common", "{key}"]\n',
            encoding="utf-8",
        )
        return
    text = path.read_text(encoding="utf-8")
    match = re.search(r"members = \[([^\]]*)\]", text)
    if not match:
        raise ValueError(f"{path} has no workspace members list")
    raw_items = match.group(1).split(",")
    current = []
    for item in raw_items:
        token = item.strip().strip('"').strip("'")
        if token:
            current.append(token)
    if key not in current:
        current.append(key)
    rendered = ", ".join(f'"{item}"' for item in current)
    replacement = f"members = [{rendered}]"
    updated = text[: match.start()] + replacement + text[match.end() :]
    path.write_text(updated, encoding="utf-8")


def _add_server(path: Path, key: str, server: str) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    data = data or {}
    servers = data.setdefault("servers", {})
    servers[server] = {
        "connector": key,
        "args": ["serve", key],
        "env": [],
        "trust": "untrusted",
        "lazy": True,
        "timeout": 120,
        "enabled_by_default": True,
        "required_env": [],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _add_hosts(path: Path, key: str, hosts: list[str]) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    data = data or {}
    connectors = data.setdefault("connectors", {})
    connectors[key] = {
        "hosts": hosts,
        "allow_ip_literals": False,
        "allow_http_loopback": False,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
