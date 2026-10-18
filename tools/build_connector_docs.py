"""Render connector reference pages and the README connector table.

Pages come from ``mcp/<key>/SOURCE.md``, tool input schemas under
``mcp/<key>/schema/``, and ``feeds/catalogue.yaml`` when that file exists.
A connector with no directory in this checkout does not get a page or a
README row.
"""

from __future__ import annotations

import argparse
import ast
import json
import operator
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

START = "<!-- connectors:start -->"
END = "<!-- connectors:end -->"
EMOJI = re.compile("[\U0001f300-\U0001faff\u2600-\u27bf]")
# No leading word boundary: NVD_API_KEY=... and access_token=... must match too.
SECRETISH = re.compile(
    r"(?i)(?:api[_-]?key|token|secret|passw(?:or)?d)[A-Za-z0-9_]*[\"']?\s*[:=]\s*"
    r"['\"]?[A-Za-z0-9_./+-]{12,}"
)
PLACEHOLDER = re.compile(r"^\$\{[A-Z][A-Z0-9_]*\}$")
# Environment variable names in SOURCE.md auth lines always contain an underscore.
ENV_NAME = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")
ENV_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]+$")
HEADER_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,40}$")
_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
}


@dataclass
class EnvUse:
    name: str
    via: set[str] = field(default_factory=set)
    in_manifest_env: bool = False
    in_required_env: bool = False

    @property
    def kind(self) -> str:
        if self.name.startswith("CYBERAU_"):
            return "runtime"
        if self.in_manifest_env or "lookup" in self.via:
            return "credential"
        if "os.environ.get" in self.via:
            return "runtime"
        return "other"

    @property
    def read_as(self) -> str:
        if self.via:
            return ", ".join(sorted(self.via))
        return "not read in connector source"


@dataclass
class TtlSite:
    function: str
    call: str
    ttl_node: ast.AST
    stale_node: ast.AST | None


@dataclass
class RateSite:
    function: str
    call: str
    key: str
    rate_node: ast.AST
    burst_node: ast.AST | None
    window: str

    @property
    def rate(self) -> str:
        return ast.unparse(self.rate_node)


@dataclass
class Extract:
    docstring: str | None
    attribution: str | None
    server_name: str | None
    tools: list[tuple[str, str]]
    env: dict[str, EnvUse]
    ttls: list[TtlSite]
    rates: list[RateSite]
    burst_assignments: list[tuple[str, str]]


@dataclass
class ConnectorDoc:
    key: str
    name: str
    server_cell: str
    auth_cell: str
    default: str
    page: str


def const_number(node: ast.AST) -> int | float | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = const_number(node.operand)
        if inner is None:
            return None
        return -inner
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        left = const_number(node.left)
        right = const_number(node.right)
        if left is None or right is None:
            return None
        try:
            return _OPS[type(node.op)](left, right)
        except ZeroDivisionError:
            return None
    return None


def const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = const_str(node.left)
        right = const_str(node.right)
        if left is None or right is None:
            return None
        return left + right
    return None


def call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ast.unparse(func)


def format_seconds(seconds: int) -> str:
    if seconds == 0:
        return "0 seconds"
    if seconds % 86400 == 0:
        days = seconds // 86400
        unit = "day" if days == 1 else "days"
        return f"{days} {unit}"
    if seconds % 3600 == 0:
        hours = seconds // 3600
        unit = "hour" if hours == 1 else "hours"
        return f"{hours} {unit}"
    if seconds % 60 == 0:
        minutes = seconds // 60
        unit = "minute" if minutes == 1 else "minutes"
        return f"{minutes} {unit}"
    unit = "second" if seconds == 1 else "seconds"
    return f"{seconds} {unit}"


def seconds_text(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return f"forwards `{node.id}`"
    raw = ast.unparse(node)
    value = const_number(node)
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, int) and value >= 0:
        return f"`{raw}` ({format_seconds(value)})"
    return f"`{raw}`"


class _Extractor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.stack: list[str] = []
        self.docstring: str | None = None
        self.attribution: str | None = None
        self.server_name: str | None = None
        self.tools: list[tuple[str, str]] = []
        self.env: dict[str, EnvUse] = {}
        self.ttls: list[TtlSite] = []
        self.rates: list[RateSite] = []
        self.burst_assignments: list[tuple[str, str]] = []

    @property
    def function(self) -> str:
        return self.stack[-1] if self.stack else "<module>"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id == "ATTRIBUTION" and not self.stack and self.attribution is None:
                self.attribution = const_str(node.value)
            if target.id == "burst":
                self.burst_assignments.append((self.function, ast.unparse(node.value)))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = call_name(node)
        self._record_call(node, name)
        self.generic_visit(node)

    def _record_call(self, node: ast.Call, name: str) -> None:
        if name == "ToolSpec" and len(node.args) >= 2:
            tool = const_str(node.args[0])
            description = const_str(node.args[1])
            if tool and description:
                self.tools.append((tool, description))
        if name == "lookup" and node.args:
            env_name = const_str(node.args[0])
            if env_name:
                self._env(env_name, "lookup")
        if name == "get" and _is_environ_get(node) and node.args:
            env_name = const_str(node.args[0])
            if env_name:
                self._env(env_name, "os.environ.get")
        keywords = {item.arg: item.value for item in node.keywords if item.arg}
        if self.server_name is None and "server_name" in keywords:
            self.server_name = const_str(keywords["server_name"])
        if "ttl" in keywords:
            self.ttls.append(
                TtlSite(
                    function=self.function,
                    call=name,
                    ttl_node=keywords["ttl"],
                    stale_node=keywords.get("stale_if_error"),
                )
            )
        if "rate" in keywords:
            self.rates.append(
                RateSite(
                    function=self.function,
                    call=name,
                    key=_rate_key(name, node),
                    rate_node=keywords["rate"],
                    burst_node=keywords.get("burst"),
                    window=_window_text(keywords.get("window")),
                )
            )

    def _env(self, name: str, via: str) -> None:
        item = self.env.setdefault(name, EnvUse(name))
        item.via.add(via)

    def result(self, tree: ast.AST) -> Extract:
        self.docstring = ast.get_docstring(tree, clean=True)
        return Extract(
            docstring=self.docstring,
            attribution=self.attribution,
            server_name=self.server_name,
            tools=self.tools,
            env=self.env,
            ttls=self.ttls,
            rates=self.rates,
            burst_assignments=self.burst_assignments,
        )


def _is_environ_get(node: ast.Call) -> bool:
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "get":
        return False
    value = func.value
    return (
        isinstance(value, ast.Attribute)
        and value.attr == "environ"
        and isinstance(value.value, ast.Name)
        and value.value.id == "os"
    )


def _rate_key(name: str, node: ast.Call) -> str:
    if name not in {"_limit", "acquire"} or not node.args:
        return ""
    return ast.unparse(node.args[0])


def _window_text(node: ast.AST | None) -> str:
    if node is None:
        return ""
    literal = const_str(node)
    if literal is not None:
        return literal
    return ast.unparse(node)


def extract_source(path: Path) -> Extract:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    visitor = _Extractor()
    visitor.visit(tree)
    return visitor.result(tree)


def shared_stale_default(root: Path) -> int | None:
    path = root / "mcp" / "common" / "src" / "cyberau_common" / "http.py"
    if not path.exists():
        return None
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "HttpClient":
            continue
        for item in node.body:
            if not isinstance(item, ast.FunctionDef) or item.name != "get":
                continue
            pairs = zip(item.args.kwonlyargs, item.args.kw_defaults, strict=False)
            for arg, default in pairs:
                if arg.arg == "stale_if_error" and default is not None:
                    value = const_number(default)
                    if isinstance(value, float) and value.is_integer():
                        return int(value)
                    if isinstance(value, int):
                        return value
    return None


def parse_source_md(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    notes: list[str] = []
    mode = "head"
    for line in text.splitlines():
        if mode == "head":
            if line.startswith("# "):
                fields["title"] = line[2:].strip()
                mode = "meta"
            continue
        if mode == "meta" and line.startswith("- ") and ": " in line[2:]:
            key, value = line[2:].split(": ", 1)
            fields[key.strip().lower()] = value.strip()
            continue
        if mode == "meta" and line.strip() == "":
            continue
        mode = "notes"
        notes.append(line)
    fields["notes"] = "\n".join(notes).strip()
    return fields


def load_schemas(directory: Path) -> tuple[dict[str, dict], dict[str, dict]]:
    schema_dir = directory / "schema"
    inputs: dict[str, dict] = {}
    responses: dict[str, dict] = {}
    if not schema_dir.is_dir():
        return inputs, responses
    for path in sorted(schema_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise SystemExit(f"{path} is not a JSON object")
        name = path.name
        if name.endswith(".input.json"):
            inputs[name[: -len(".input.json")]] = data
        elif name.endswith(".response.json"):
            responses[name[: -len(".response.json")]] = data
    return inputs, responses


def load_feeds(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return []
    if not isinstance(data, dict) or not isinstance(data.get("feeds"), list):
        raise SystemExit(f"{path} must be a mapping with a feeds list")
    feeds: list[dict] = []
    for item in data["feeds"]:
        if not isinstance(item, dict) or not isinstance(item.get("connector"), str):
            raise SystemExit(f"{path} has a feed without a connector name")
        feeds.append(item)
    return feeds


def index_servers(path: Path) -> dict[str, list[tuple[str, dict]]]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must be a mapping")
    servers = data.get("servers") or {}
    if not isinstance(servers, dict):
        raise SystemExit(f"{path} servers must be a mapping")
    grouped: dict[str, list[tuple[str, dict]]] = {}
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        # A wrap with no local package (virustotal, junction) is matched on its server name.
        key = spec.get("connector", name)
        if not isinstance(key, str):
            continue
        grouped.setdefault(key, []).append((str(name), spec))
    for items in grouped.values():
        items.sort(key=lambda item: item[0])
    return grouped


def feeds_for_connector(feeds: list[dict], key: str) -> list[dict]:
    return [item for item in feeds if item.get("connector") == key]


def cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def prose(value: str, missing: str) -> str:
    text = value.strip()
    if not text:
        return missing
    if text.lower() in {"none", "none."}:
        return "None."
    if text[-1] not in ".!?":
        text += "."
    if text[:1].islower():
        return text[:1].upper() + text[1:]
    return text


def display_name(docstring: str | None, key: str) -> str:
    if not docstring:
        return key
    line = docstring.strip().splitlines()[0].strip().rstrip(".")
    prefix = "read-only "
    if line.lower().startswith(prefix):
        line = line[len(prefix) :]
        line = line[:1].upper() + line[1:]
    return line or key


def auth_cell(auth: str) -> str:
    names = ENV_NAME.findall(auth)
    if not names:
        return "none"
    optional = "optional" in auth.lower()
    parts = []
    for name in dict.fromkeys(names):
        parts.append(f"`{name}` (optional)" if optional else f"`{name}`")
    return ", ".join(parts)


def server_cell(names: list[str]) -> str:
    if not names:
        return "not listed"
    return ", ".join(f"`{name}`" for name in names)


def default_label(flags: list[bool | None], reasons: list[str] | None = None) -> str:
    if not flags or any(flag is None for flag in flags):
        return "not listed"
    if all(flag is True for flag in flags):
        return "on"
    if all(flag is False for flag in flags):
        reason = next((item for item in reasons or [] if item), "")
        return f"off: {reason}" if reason else "off"
    return "mixed"


def off_reasons(specs: list[tuple[str, dict]]) -> list[str]:
    return [str(spec.get("off_reason") or "").strip() for _name, spec in specs]


def manifest_flags(specs: list[tuple[str, dict]]) -> list[bool | None]:
    flags: list[bool | None] = []
    for _name, spec in specs:
        if "enabled_by_default" not in spec:
            flags.append(None)
        else:
            flags.append(bool(spec["enabled_by_default"]))
    return flags


def type_label(spec: dict) -> str:
    if "enum" in spec and "type" not in spec:
        return "enum"
    kind = str(spec.get("type", "value"))
    items = spec.get("items")
    if kind == "array" and isinstance(items, dict):
        if "enum" in items:
            return "array of enum"
        if "type" in items:
            return f"array of {items['type']}"
    return kind


def constraint_text(spec: dict) -> str:
    parts: list[str] = []
    if "enum" in spec:
        parts.append("one of " + ", ".join(f"`{item}`" for item in spec["enum"]))
    items = spec.get("items")
    if isinstance(items, dict) and "enum" in items:
        parts.append("items one of " + ", ".join(f"`{item}`" for item in items["enum"]))
    if isinstance(items, dict) and "pattern" in items:
        parts.append(f"items match `{items['pattern']}`")
    if "pattern" in spec:
        parts.append(f"pattern `{spec['pattern']}`")
    if "format" in spec:
        parts.append(f"format `{spec['format']}`")
    bounds: list[str] = []
    for key, label in (
        ("minimum", "minimum"),
        ("maximum", "maximum"),
        ("minLength", "min length"),
        ("maxLength", "max length"),
        ("minItems", "min items"),
        ("maxItems", "max items"),
    ):
        if key in spec:
            bounds.append(f"{label} {spec[key]}")
    if bounds:
        parts.append(", ".join(bounds))
    if "default" in spec:
        parts.append("default `" + json.dumps(spec["default"], ensure_ascii=True) + "`")
    if spec.get("description"):
        parts.append(str(spec["description"]))
    return "; ".join(parts)


def render_property_table(schema: dict) -> list[str]:
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    if not isinstance(props, dict) or not props:
        lines = ["This schema declares no fields."]
    else:
        lines = [
            "| Field | Type | Required | Constraints |",
            "|---|---|---|---|",
        ]
        for name, spec in props.items():
            if not isinstance(spec, dict):
                spec = {}
            required_cell = "yes" if name in required else "no"
            lines.append(
                "| "
                + " | ".join(
                    (
                        cell(f"`{name}`"),
                        cell(type_label(spec)),
                        required_cell,
                        cell(constraint_text(spec)),
                    )
                )
                + " |"
            )
    if schema.get("additionalProperties") is False:
        lines.extend(["", "Additional properties are rejected."])
    elif schema.get("additionalProperties") is True:
        lines.extend(["", "Additional properties are allowed."])
    return lines


def render_schema_block(filename: str, schema: dict, heading: str) -> str:
    lines = [f"{heading} (`schema/{filename}`):", ""]
    if schema.get("type") == "object" or "properties" in schema:
        lines.extend(render_property_table(schema))
        lines.append("")
    lines.append("```json")
    lines.append(json.dumps(schema, indent=2, ensure_ascii=False))
    lines.append("```")
    return "\n".join(lines)


def render_tool(
    name: str, description: str, inputs: dict[str, dict], responses: dict[str, dict]
) -> str:
    blocks = [f"### `{name}`", description or "No description is set on the tool."]
    if name in inputs:
        blocks.append(render_schema_block(f"{name}.input.json", inputs[name], "Input schema"))
    else:
        blocks.append("No input schema file is in `schema/`.")
    if name in responses:
        blocks.append(
            render_schema_block(f"{name}.response.json", responses[name], "Response schema")
        )
    return "\n\n".join(blocks)


def auth_feed_label(auth: object) -> str:
    if not isinstance(auth, dict):
        return "none"
    parts = [str(auth.get("type") or "none")]
    header = auth.get("header")
    if isinstance(header, str) and header:
        if HEADER_TOKEN.fullmatch(header):
            parts.append(f"header `{header}`")
        else:
            parts.append("header omitted")
    env = auth.get("env")
    if isinstance(env, str) and env:
        if ENV_TOKEN.fullmatch(env):
            parts.append(f"env `${{{env}}}`")
        else:
            parts.append("env name omitted")
    return ", ".join(parts)


def render_feed_section(feeds: list[dict], *, catalogue_present: bool = True) -> str:
    if not catalogue_present:
        return "`feeds/catalogue.yaml` is not in this checkout, so no feeds are listed."
    if not feeds:
        return "No feeds for this connector are listed in `feeds/catalogue.yaml`."
    lines = [
        "| Id | URL | Format | Auth | Poll | Licence | Region |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in feeds:
        values = [
            str(item.get("id", "")),
            str(item.get("url", "")),
            str(item.get("format", "")),
            auth_feed_label(item.get("auth")),
            str(item.get("poll", "")),
            str(item.get("licence", "")),
            str(item.get("region", "")),
        ]
        lines.append("| " + " | ".join(cell(value) for value in values) + " |")
    return "\n".join(lines)


def keep_ttl(site: TtlSite) -> bool:
    if site.function == "health":
        return False
    if site.call == "get":
        return True
    forwarded = isinstance(site.ttl_node, ast.Name)
    return not (forwarded and site.stale_node is None)


def keep_rate(site: RateSite) -> bool:
    forwarded_rate = isinstance(site.rate_node, ast.Name)
    forwarded_burst = site.burst_node is None or isinstance(site.burst_node, ast.Name)
    return not (forwarded_rate and forwarded_burst)


def stale_cell(site: TtlSite, default: int | None) -> str:
    if site.stale_node is not None:
        return seconds_text(site.stale_node)
    if site.call == "get" and default is not None:
        return f"not set (shared client default {format_seconds(default)})"
    return "not set on this call"


def render_cache(sites: list[TtlSite], default: int | None) -> str:
    kept = [site for site in sites if keep_ttl(site)]
    lines = ["HTTP cache `ttl` arguments in the connector source."]
    omits_stale = any(site.call == "get" and site.stale_node is None for site in kept)
    if omits_stale and default is not None:
        lines.append(
            "A `get` call that omits `stale_if_error` uses the shared client default "
            f"({format_seconds(default)})."
        )
    if not kept:
        lines.append("No `ttl` argument is set in the connector source.")
        return "\n\n".join(lines)
    rows = [
        "| Function | Call | TTL | Stale if error |",
        "|---|---|---|---|",
    ]
    seen: set[str] = set()
    for site in kept:
        row = (
            "| "
            + " | ".join(
                (
                    cell(f"`{site.function}`"),
                    cell(f"`{site.call}`"),
                    cell(seconds_text(site.ttl_node)),
                    cell(stale_cell(site, default)),
                )
            )
            + " |"
        )
        if row in seen:
            continue
        seen.add(row)
        rows.append(row)
    lines.append("\n".join(rows))
    return "\n\n".join(lines)


def render_rates(sites: list[RateSite], assignments: list[tuple[str, str]], stated: str) -> str:
    blocks = [prose(stated, "Not stated in `SOURCE.md`.")]
    kept = [site for site in sites if keep_rate(site)]
    if kept:
        rows = [
            "| Function | Call | Key | Rate | Burst | Window |",
            "|---|---|---|---|---|---|",
        ]
        for site in kept:
            burst = "" if site.burst_node is None else f"`{ast.unparse(site.burst_node)}`"
            window = f"`{site.window}`" if site.window else ""
            rows.append(
                "| "
                + " | ".join(
                    (
                        cell(f"`{site.function}`"),
                        cell(f"`{site.call}`"),
                        cell(f"`{site.key}`" if site.key else ""),
                        cell(f"`{site.rate}`"),
                        cell(burst),
                        cell(window),
                    )
                )
                + " |"
            )
        blocks.append("Limiter arguments in the connector source:\n\n" + "\n".join(rows))
    seen: set[tuple[str, str]] = set()
    notes: list[str] = []
    for function, expr in assignments:
        relevant = any(
            site.function == function and re.search(r"\bburst\b", site.rate) for site in kept
        )
        if relevant and (function, expr) not in seen:
            seen.add((function, expr))
            notes.append(f"`{function}` sets `burst` to `{expr}`.")
    if notes:
        blocks.append("\n".join(notes))
    return "\n\n".join(blocks)


def render_env(
    uses: dict[str, EnvUse],
    auth: str,
    manifest_env: list[str],
    required_env: list[str],
) -> str:
    blocks: list[str] = []
    credentials = [item for item in uses.values() if item.kind == "credential"]
    if credentials:
        blocks.append(
            "Credential values are read from the profile environment. "
            "Nothing on this page is a secret value."
        )
    else:
        blocks.append("No credential variable is declared for this connector.")
    for entry in manifest_env:
        blocks.append(f"Server manifest `env` entry: `{entry}`.")
    if required_env:
        rendered = ", ".join(f"`{name}`" for name in required_env)
        blocks.append(f"Server manifest `required_env`: {rendered}.")
    if not uses:
        blocks.append("This connector reads no environment variables.")
        return "\n\n".join(blocks)
    order = {"credential": 0, "other": 1, "runtime": 2}
    rows = [
        "| Variable | Kind | Server `env` | `required_env` | Read in connector |",
        "|---|---|---|---|---|",
    ]
    for item in sorted(uses.values(), key=lambda entry: (order.get(entry.kind, 9), entry.name)):
        rows.append(
            "| "
            + " | ".join(
                (
                    cell(f"`{item.name}`"),
                    item.kind,
                    "yes" if item.in_manifest_env else "no",
                    "yes" if item.in_required_env else "no",
                    cell(f"`{item.read_as}`" if item.via else item.read_as),
                )
            )
            + " |"
        )
    blocks.append("\n".join(rows))
    notes = []
    for item in sorted(uses.values(), key=lambda entry: entry.name):
        if item.in_required_env and "optional" in auth.lower() and item.name in auth:
            notes.append(
                f"`{item.name}` is optional in `SOURCE.md`. "
                f"`mcp/servers.yaml` lists it under `required_env`."
            )
    if notes:
        blocks.append("\n".join(notes))
    return "\n\n".join(blocks)


def render_notes(notes: str) -> str:
    if not notes.strip():
        return ""
    if notes.lstrip().startswith("#"):
        return notes.strip()
    return "## Notes\n\n" + notes.strip()


def render_page(
    *,
    key: str,
    name: str,
    summary: str,
    server: str,
    default: str,
    fields: dict[str, str],
    source_rel: str,
    env_section: str,
    rate_section: str,
    cache_section: str,
    tools: list[str],
    feeds: str,
    attribution: str | None,
    catalogue_present: bool,
) -> str:
    inputs = f"`mcp/{key}/SOURCE.md`, `mcp/{key}/schema/` and `mcp/servers.yaml`"
    if catalogue_present:
        inputs = inputs.replace(" and ", ", ", 1) + " and `feeds/catalogue.yaml`"
    banner = f"Generated by `tools/build_connector_docs.py` from {inputs}. Do not edit by hand."
    meta = [f"- Key: `{key}`", f"- Server: {server}", f"- Default: {default}"]
    if fields.get("upstream"):
        meta.append(f"- Upstream: {fields['upstream']}")
    if fields.get("verified"):
        meta.append(f"- Verified: {fields['verified']}")
    if fields.get("egress hosts"):
        meta.append(f"- Egress hosts: {fields['egress hosts']}")
    if source_rel:
        meta.append(f"- Source: `{source_rel}`")
    blocks = [f"# {name}", banner]
    if summary:
        blocks.append(summary)
    blocks.append("\n".join(meta))
    blocks.append(
        "## Authentication\n\n" + prose(fields.get("auth", ""), "Not stated in `SOURCE.md`.")
    )
    blocks.append("## Environment variables\n\n" + env_section)
    blocks.append("## Rate limits\n\n" + rate_section)
    blocks.append("## Cache\n\n" + cache_section)
    tool_body = (
        "\n\n".join(tools)
        if tools
        else "No tools are declared in the connector source or schema directory."
    )
    blocks.append("## Tools\n\n" + tool_body)
    blocks.append("## Feeds\n\n" + feeds)
    terms = prose(fields.get("terms", ""), "Not stated in `SOURCE.md`.")
    if attribution:
        attribution_block = "Attribution returned with each result:\n\n> " + attribution
    else:
        attribution_block = "No attribution string is set in the connector source."
    blocks.append("## Terms and attribution\n\n" + terms + "\n\n" + attribution_block)
    notes = render_notes(fields.get("notes", ""))
    if notes:
        blocks.append(notes)
    return "\n\n".join(blocks).rstrip() + "\n"


def render_readme_block(connectors: list[ConnectorDoc]) -> str:
    rows = [
        (
            "Connectors with a `SOURCE.md` in this checkout. Planned sources without a "
            "connector directory are listed in "
            "[docs/research/connectors.md](docs/research/connectors.md)."
        ),
        "",
        "| Connector | Server | Auth | Default | Docs |",
        "|---|---|---|---|---|",
    ]
    for item in connectors:
        link = f"[docs/connectors/{item.key}.md](docs/connectors/{item.key}.md)"
        rows.append(
            "| "
            + " | ".join(
                (
                    cell(item.name),
                    cell(item.server_cell),
                    cell(item.auth_cell),
                    cell(item.default),
                    link,
                )
            )
            + " |"
        )
    return "\n".join(rows)


def splice_readme(readme: str, block: str) -> str:
    if START not in readme or END not in readme:
        raise SystemExit("README.md is missing connector markers")
    before, rest = readme.split(START, 1)
    _old, after = rest.split(END, 1)
    return before + START + "\n" + block.rstrip() + "\n" + END + after


def assert_house_style(text: str, label: str) -> None:
    if "\u2014" in text:
        raise SystemExit(f"{label} contains an em dash")
    if EMOJI.search(text):
        raise SystemExit(f"{label} contains an emoji")
    if SECRETISH.search(text):
        raise SystemExit(f"{label} looks like it contains a secret assignment")


def _apply_manifest(
    uses: dict[str, EnvUse], specs: list[tuple[str, dict]]
) -> tuple[list[str], list[str]]:
    manifest_env: list[str] = []
    required: list[str] = []
    for _name, spec in specs:
        for entry in spec.get("env") or []:
            if not isinstance(entry, str):
                continue
            env_name, sep, value = entry.partition("=")
            env_name = env_name.strip()
            if sep and not PLACEHOLDER.fullmatch(value.strip()):
                raise SystemExit(
                    f"mcp/servers.yaml: env {env_name} must use a ${{VAR}} placeholder"
                )
            manifest_env.append(entry)
            if env_name:
                uses.setdefault(env_name, EnvUse(env_name)).in_manifest_env = True
        for env_name in spec.get("required_env") or []:
            if not isinstance(env_name, str):
                continue
            if env_name not in required:
                required.append(env_name)
            uses.setdefault(env_name, EnvUse(env_name)).in_required_env = True
    return manifest_env, required


def _tool_order(
    extracted: Extract, inputs: dict[str, dict], responses: dict[str, dict]
) -> list[tuple[str, str]]:
    descriptions = {}
    ordered: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, description in extracted.tools:
        if name in seen:
            continue
        seen.add(name)
        descriptions[name] = description
        ordered.append((name, description))
    for name in sorted(set(inputs) | set(responses)):
        if name in seen:
            continue
        ordered.append((name, descriptions.get(name, "")))
    return ordered


def build(root: Path) -> dict[str, str]:
    mcp = root / "mcp"
    if not mcp.is_dir():
        raise SystemExit(f"missing {mcp}")
    catalogue = root / "feeds" / "catalogue.yaml"
    catalogue_present = catalogue.exists()
    feeds = load_feeds(catalogue)
    servers = index_servers(mcp / "servers.yaml")
    stale_default = shared_stale_default(root)
    connectors: list[ConnectorDoc] = []
    pages: dict[str, str] = {}
    for directory in sorted(path for path in mcp.iterdir() if path.is_dir()):
        source_md = directory / "SOURCE.md"
        if not source_md.is_file():
            continue
        key = directory.name
        fields = parse_source_md(source_md.read_text(encoding="utf-8"))
        inputs, responses = load_schemas(directory)
        source_py = next(iter(sorted((directory / "src").rglob("source.py"))), None)
        extracted = (
            extract_source(source_py)
            if source_py
            else Extract(None, None, None, [], {}, [], [], [])
        )
        specs = servers.get(key, [])
        manifest_env, required_env = _apply_manifest(extracted.env, specs)
        names = [name for name, _spec in specs] or (
            [extracted.server_name] if extracted.server_name else []
        )
        flags = manifest_flags(specs)
        default = default_label(flags, off_reasons(specs)) if specs else "not listed"
        summary = ""
        if extracted.docstring:
            summary = extracted.docstring.strip().splitlines()[0].strip()
        name = display_name(extracted.docstring, fields.get("title") or key)
        tools = [
            render_tool(tool_name, description, inputs, responses)
            for tool_name, description in _tool_order(extracted, inputs, responses)
        ]
        source_rel = "" if source_py is None else source_py.relative_to(root).as_posix()
        page = render_page(
            key=key,
            name=name,
            summary=summary,
            server=server_cell(names),
            default=default,
            fields=fields,
            source_rel=source_rel,
            env_section=render_env(
                extracted.env, fields.get("auth", ""), manifest_env, required_env
            ),
            rate_section=render_rates(
                extracted.rates,
                extracted.burst_assignments,
                fields.get("rate limit", ""),
            ),
            cache_section=render_cache(extracted.ttls, stale_default),
            tools=tools,
            feeds=render_feed_section(
                feeds_for_connector(feeds, key), catalogue_present=catalogue_present
            ),
            attribution=extracted.attribution,
            catalogue_present=catalogue_present,
        )
        assert_house_style(page, f"docs/connectors/{key}.md")
        rel = f"docs/connectors/{key}.md"
        pages[rel] = page
        connectors.append(
            ConnectorDoc(
                key=key,
                name=name,
                server_cell=server_cell(names),
                auth_cell=auth_cell(fields.get("auth", "")),
                default=default,
                page=page,
            )
        )
    known = {item.key for item in connectors}
    unknown = sorted(
        {str(item.get("connector")) for item in feeds if item.get("connector") not in known}
    )
    for name in unknown:
        print(f"catalogue feed ignored, no connector directory: {name}", file=sys.stderr)
    block = render_readme_block(connectors)
    assert_house_style(block, "README connector table")
    readme_path = root / "README.md"
    readme = splice_readme(readme_path.read_text(encoding="utf-8"), block)
    files = dict(pages)
    files["README.md"] = readme
    return files


def stale_files(root: Path, files: dict[str, str]) -> list[str]:
    problems: list[str] = []
    for rel, content in files.items():
        path = root / rel
        if not path.exists():
            problems.append(f"missing {rel}")
        elif path.read_text(encoding="utf-8") != content:
            problems.append(f"stale {rel}")
    docs_dir = root / "docs" / "connectors"
    if docs_dir.is_dir():
        for path in sorted(docs_dir.glob("*.md")):
            rel = path.relative_to(root).as_posix()
            if rel not in files:
                problems.append(f"extra {rel}")
    return problems


def write(root: Path, files: dict[str, str]) -> None:
    docs_dir = root / "docs" / "connectors"
    docs_dir.mkdir(parents=True, exist_ok=True)
    expected = {rel for rel in files if rel.startswith("docs/connectors/")}
    for path in docs_dir.glob("*.md"):
        rel = path.relative_to(root).as_posix()
        if rel not in expected:
            path.unlink()
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render connector reference pages and the README table."
    )
    parser.add_argument("--check", action="store_true", help="exit 1 if generated files differ")
    parser.add_argument("--root", type=Path, default=None, help="repository root")
    args = parser.parse_args(argv)
    root = (args.root or Path(__file__).resolve().parents[1]).resolve()
    files = build(root)
    problems = stale_files(root, files)
    if args.check:
        if problems:
            print("connector docs are stale:", file=sys.stderr)
            for item in problems:
                print(f"  {item}", file=sys.stderr)
            print(
                "Run: uv run --project mcp python tools/build_connector_docs.py",
                file=sys.stderr,
            )
            return 1
        print("connector docs are up to date")
        return 0
    write(root, files)
    print(f"wrote {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
