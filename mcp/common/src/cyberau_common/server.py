"""MCP server wiring. Read-only tools are the default."""

from __future__ import annotations

import importlib
import inspect
from collections.abc import Callable
from dataclasses import dataclass, field

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from cyberau_common.envelope import envelope, harden_envelope, untrusted_text
from cyberau_common.secrets import install_log_redaction, record_tool_audit

_REGISTRY: dict[str, Callable[[], Connector]] = {}


@dataclass
class ToolSpec:
    name: str
    description: str
    fn: Callable
    writes: bool = False
    open_world: bool = True


@dataclass
class Probe:
    name: str
    ok: bool
    detail: str


@dataclass
class Connector:
    key: str
    server_name: str
    attribution: str
    tools: list[ToolSpec] = field(default_factory=list)

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema:
            return Probe(self.key, True, "no schema check for this connector")
        if live:
            return Probe(self.key, True, "live not checked")
        return Probe(self.key, True, "offline ok")


def register_connector(key: str, factory: Callable[[], Connector]) -> None:
    _REGISTRY[key] = factory


def get_connector(key: str) -> Connector:
    if key not in _REGISTRY:
        if key == "stub":
            import cyberau_common.stub  # noqa: F401
        else:
            try:
                importlib.import_module(f"cyberau_{key.replace('-', '_')}")
            except ModuleNotFoundError as exc:
                raise KeyError(key) from exc
    if key not in _REGISTRY:
        raise KeyError(key)
    return _REGISTRY[key]()


def build_server(connector: Connector) -> MCPServer:
    install_log_redaction()
    mcp = MCPServer(connector.server_name)
    for spec in connector.tools:
        mcp.add_tool(
            _wrap(connector, spec),
            name=spec.name,
            description=spec.description,
            annotations=ToolAnnotations(
                readOnlyHint=not spec.writes,
                openWorldHint=spec.open_world,
                destructiveHint=False,
            ),
            structured_output=False,
        )
    return mcp


def invoke_tool(connector: Connector, spec: ToolSpec, *args, **kwargs):
    """Run one tool. Exceptions, envelopes, and the audit line are redacted."""
    try:
        data = spec.fn(*args, **kwargs)
    except Exception as exc:
        record_tool_audit(spec.name, args, kwargs, str(exc))
        return envelope(
            connector.key,
            None,
            cache="snapshot",
            # Exception text can carry upstream response text, so it is wrapped.
            warnings=(untrusted_text(str(exc), connector.key, 500),),
            attribution=connector.attribution,
        )
    record_tool_audit(spec.name, args, kwargs, None)
    if isinstance(data, dict) and data.get("untrusted") is True and "source" in data:
        return harden_envelope(data)
    return envelope(
        connector.key,
        data,
        cache="snapshot",
        attribution=connector.attribution,
    )


def _wrap(connector: Connector, spec: ToolSpec) -> Callable:
    def wrapper(*args, **kwargs):
        return invoke_tool(connector, spec, *args, **kwargs)

    wrapper.__signature__ = inspect.signature(spec.fn)
    wrapper.__name__ = spec.name
    wrapper.__doc__ = spec.description
    return wrapper
