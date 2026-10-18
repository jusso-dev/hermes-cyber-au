"""Render profile mcp_servers from mcp/servers.yaml.

Hermes 0.22.2 does not reject unknown keys on an MCP server entry
(validate_mcp_server_entry is not a whitelist). Each server we own is marked
with x-cyber-au-managed: true. The same names are written to
plugin-data/cyber-au/managed-servers.json so a later rewrite that drops
unknown keys does not forget which entries we own.

Credential values are never written. Keyed servers get ${VAR} placeholders.
A required variable that is missing or blank in the profile .env sets
enabled: false.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

import yaml

MANAGED_KEY = "x-cyber-au-managed"
PLACEHOLDER = re.compile(r"^\$\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*\}$")
ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
OWNED_RENDER_KEYS = (
    "command",
    "args",
    "env",
    "timeout",
    "lazy",
    "trust",
    "tools",
    "enabled",
    MANAGED_KEY,
)


class _Dumper(yaml.SafeDumper):
    """Stable dump. Unknown-key markers and placeholders stay readable."""


def _represent_str(dumper: yaml.SafeDumper, data: str) -> yaml.nodes.ScalarNode:
    special = any(ch in data for ch in ":${}#&*!|>%@`'\n\"")
    style = '"' if data == "" or special else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


def _ignore_aliases(_self: yaml.SafeDumper, _data: object) -> bool:
    return True


_Dumper.add_representer(str, _represent_str)
_Dumper.ignore_aliases = _ignore_aliases


def _load_yaml(path: Path) -> dict:
    if not path.is_file():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise SystemExit(f"{path} must be a mapping")
    return loaded


def _read_set_names(env_file: Path) -> set[str]:
    """Names with a non-empty value. The values themselves are discarded."""
    if not env_file.is_file():
        return set()
    names: set[str] = set()
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        matched = ASSIGNMENT.match(line)
        if matched is None:
            continue
        key, value = matched.group(1), matched.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        else:
            # An unquoted value ends at " #". KEY=  # todo is still unset.
            value = re.split(r"\s#", " " + value, maxsplit=1)[0]
        if value.strip():
            names.add(key)
    return names


def _placeholder(raw: str, server: str) -> tuple[str, str]:
    name, sep, value = raw.partition("=")
    if sep != "=" or not name:
        raise SystemExit(f"Server {server} has an env entry that is not NAME=${{NAME}}")
    if not PLACEHOLDER.match(value.strip()):
        raise SystemExit(
            f"Refusing a literal env value for {name} on {server}. Use a ${{{name}}} placeholder."
        )
    return name, value.strip()


def _enabled(spec: dict, previous: dict | None, present: set[str]) -> bool | None:
    default_on = spec.get("enabled_by_default", spec.get("default_enabled", True))
    if default_on is False:
        return False
    required = [str(item) for item in spec.get("required_env") or []]
    if required:
        return all(item in present for item in required)
    if previous is not None and "enabled" in previous:
        return bool(previous["enabled"])
    return None


def _server_entry(
    name: str, spec: dict, home: Path, previous: dict | None, present: set[str]
) -> dict:
    if not isinstance(spec, dict):
        raise SystemExit(f"Server {name} in servers.yaml must be a mapping")
    command = home / "mcp" / ".venv" / "bin" / "cyberau-mcp"
    args = spec.get("args")
    if not isinstance(args, list) or not args:
        connector = spec.get("connector") or name
        args = ["serve", str(connector)]
    env: dict[str, str] = {
        "CYBERAU_DATA_DIR": str(home / "plugin-data" / "cyber-au"),
        "CYBERAU_EGRESS_ALLOWLIST": str(home / "mcp" / "egress-allowlist.yaml"),
    }
    for item in spec.get("env") or []:
        if isinstance(item, str):
            key, value = _placeholder(item, name)
        elif isinstance(item, dict) and len(item) == 1:
            key, value = next(iter(item.items()))
            if not PLACEHOLDER.match(str(value).strip()):
                raise SystemExit(
                    f"Refusing a literal env value for {key} on {name}. "
                    f"Use a ${{{key}}} placeholder."
                )
            value = str(value).strip()
            key = str(key)
        else:
            raise SystemExit(f"Server {name} has an env entry that is not NAME=${{NAME}}")
        env[key] = value
    entry: dict = {
        "command": str(command),
        "args": [str(part) for part in args],
        "env": env,
        MANAGED_KEY: True,
    }
    if "timeout" in spec:
        entry["timeout"] = spec["timeout"]
    if "lazy" in spec:
        entry["lazy"] = bool(spec["lazy"])
    if "trust" in spec:
        entry["trust"] = spec["trust"]
    tools = spec.get("tools")
    include = spec.get("tools.include")
    if include is None and isinstance(tools, dict):
        include = tools.get("include")
    if include is not None:
        entry["tools"] = {"include": list(include)}
    enabled = _enabled(spec, previous if isinstance(previous, dict) else None, present)
    if enabled is not None:
        entry["enabled"] = enabled
    if isinstance(previous, dict):
        for key, value in previous.items():
            if key not in entry and key not in OWNED_RENDER_KEYS:
                entry[key] = value
    return _ordered_entry(entry)


def _ordered_entry(entry: dict) -> dict:
    preferred = (
        "command",
        "args",
        "env",
        "timeout",
        "lazy",
        "trust",
        "tools",
        "supports_parallel_tool_calls",
        "enabled",
        MANAGED_KEY,
    )
    ordered: dict = {}
    for key in preferred:
        if key in entry:
            ordered[key] = entry[key]
    for key, value in entry.items():
        if key not in ordered:
            ordered[key] = value
    return ordered


def _load_managed_names(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Could not read {path}: {exc}") from exc
    servers = loaded.get("servers", []) if isinstance(loaded, dict) else []
    if not isinstance(servers, list):
        raise SystemExit(f"{path} servers must be a list")
    return {str(name) for name in servers}


def render_config(
    *,
    profile_home: Path,
    servers_doc: dict,
    config: dict,
    present: set[str],
    managed_names: set[str],
) -> tuple[dict, list[dict[str, str]], list[str]]:
    specs = servers_doc.get("servers")
    if not isinstance(specs, dict):
        raise SystemExit("servers.yaml must contain a servers mapping")
    home = profile_home.resolve()
    previous_servers = config.get("mcp_servers") or {}
    if previous_servers is None:
        previous_servers = {}
    if not isinstance(previous_servers, dict):
        raise SystemExit("mcp_servers in config.yaml must be a mapping")

    owned = set(managed_names)
    for name, entry in previous_servers.items():
        if isinstance(entry, dict) and entry.get(MANAGED_KEY) is True:
            owned.add(str(name))

    rendered: dict[str, dict] = {}
    missing: list[dict[str, str]] = []
    skipped: list[str] = []
    for name, spec in specs.items():
        previous = previous_servers.get(name)
        if name in previous_servers and str(name) not in owned:
            # A server the person added themselves under a shipped name.
            skipped.append(str(name))
            continue
        rendered[str(name)] = _server_entry(str(name), spec, home, previous, present)
        required = []
        if isinstance(spec, dict):
            required = [str(item) for item in spec.get("required_env") or []]
        default_on = True
        if isinstance(spec, dict):
            default_on = (
                spec.get("enabled_by_default", spec.get("default_enabled", True)) is not False
            )
        if default_on:
            for variable in required:
                if variable not in present:
                    missing.append({"server": str(name), "variable": variable})

    merged: dict = {}
    seen: set[str] = set()
    for name, entry in previous_servers.items():
        key = str(name)
        if key in rendered:
            merged[key] = rendered[key]
            seen.add(key)
        elif key in owned:
            continue
        else:
            merged[key] = entry
    for name, entry in rendered.items():
        if name not in seen:
            merged[name] = entry

    updated = dict(config)
    timezone = updated.get("timezone")
    if timezone is None or (isinstance(timezone, str) and not timezone.strip()):
        updated["timezone"] = "Australia/Sydney"
    updated["mcp_servers"] = merged
    missing.sort(key=lambda item: (item["server"], item["variable"]))
    skipped.sort()
    return updated, missing, skipped


def _top_level_block(lines: list[str], key: str) -> tuple[int, int] | None:
    """Line range of a top-level key and its indented body, minus trailing
    blank or column-zero comment lines (those belong to the next key)."""
    start = next(
        (i for i, line in enumerate(lines) if re.match(rf"{re.escape(key)}\s*:", line)),
        None,
    )
    if start is None:
        return None
    end = start + 1
    while end < len(lines) and (lines[end].strip() == "" or lines[end][0] in " \t#"):
        end += 1
    while end > start + 1 and (lines[end - 1].strip() == "" or lines[end - 1].startswith("#")):
        end -= 1
    return start, end


def _splice(original: str, updated: dict) -> str | None:
    """Replace only the mcp_servers block (and a blank timezone) in the
    original text, so comments and layout elsewhere survive. Returns None when
    the result does not parse back to exactly `updated`."""
    lines = original.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    block = _dump_yaml({"mcp_servers": updated["mcp_servers"]}).splitlines(keepends=True)
    found = _top_level_block(lines, "mcp_servers")
    if found is None:
        lines.extend(block)
    else:
        lines[found[0] : found[1]] = block
    tz_line = f"timezone: {updated['timezone']}\n"
    found = _top_level_block(lines, "timezone")
    try:
        before = yaml.safe_load("".join(lines)) or {}
    except yaml.YAMLError:
        return None
    if not (isinstance(before, dict) and str(before.get("timezone") or "").strip()):
        if found is None:
            lines.append(tz_line)
        else:
            lines[found[0] : found[1]] = [tz_line]
    text = "".join(lines)
    try:
        return text if yaml.safe_load(text) == updated else None
    except yaml.YAMLError:
        return None


def _dump_yaml(data: dict) -> str:
    text = yaml.dump(
        data,
        Dumper=_Dumper,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=10000,
    )
    if not text.endswith("\n"):
        text += "\n"
    return text


def _write_if_changed(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        return
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    if path.is_file():
        shutil.copymode(path, temporary)
    temporary.replace(path)


def _print_skipped(skipped: list[str]) -> None:
    for name in skipped:
        print(
            f"Server {name} in config.yaml is not managed by cyber-au, so it was left as it is. "
            f"The shipped {name} connector was not added.",
            flush=True,
        )


def _print_missing(missing: list[dict[str, str]]) -> None:
    for item in missing:
        print(
            f"Keyed connector {item['server']} is disabled because {item['variable']} is unset.",
            flush=True,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render cyber-au mcp_servers into a profile config"
    )
    parser.add_argument("--profile-home", required=True, type=Path)
    parser.add_argument("--servers", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--managed", required=True, type=Path)
    parser.add_argument("--status", required=True, type=Path)
    args = parser.parse_args(argv)

    servers_doc = _load_yaml(args.servers)
    config = _load_yaml(args.config)
    present = _read_set_names(args.env_file)
    managed_names = _load_managed_names(args.managed)
    updated, missing, skipped = render_config(
        profile_home=args.profile_home,
        servers_doc=servers_doc,
        config=config,
        present=present,
        managed_names=managed_names,
    )
    original = args.config.read_text(encoding="utf-8") if args.config.is_file() else ""
    spliced = _splice(original, updated) if original.strip() else None
    _write_if_changed(args.config, spliced if spliced is not None else _dump_yaml(updated))
    owned_names = sorted(
        name
        for name, entry in updated.get("mcp_servers", {}).items()
        if isinstance(entry, dict) and entry.get(MANAGED_KEY) is True
    )
    _write_if_changed(
        args.managed,
        json.dumps({"servers": owned_names}, indent=2) + "\n",
    )
    _write_if_changed(
        args.status,
        json.dumps({"missing_env": missing}, indent=2) + "\n",
    )
    _print_skipped(skipped)
    _print_missing(missing)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
