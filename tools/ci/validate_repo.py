"""Validate skill frontmatter, distribution.yaml, the feed catalogue and allowlist drift.

Run from the repository root:

    uv run --project mcp python tools/ci/validate_repo.py
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

# Fallback until feeds/catalogue.schema.json lands with the catalogue ticket.
# Field names follow that ticket, including the Australian spelling "licence".
CATALOGUE_SCHEMA: dict = {
    "type": "object",
    "required": ["version", "feeds"],
    "properties": {
        "version": {"type": "integer"},
        "feeds": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "id",
                    "connector",
                    "url",
                    "format",
                    "auth",
                    "poll",
                    "licence",
                    "region",
                ],
                "properties": {
                    "id": {"type": "string"},
                    "connector": {"type": "string"},
                    "url": {"type": "string"},
                    "format": {"enum": ["rss", "atom", "json", "csv", "stix", "oscal", "html"]},
                    "auth": {
                        "type": "object",
                        "properties": {
                            "type": {"enum": ["none", "header", "bearer"]},
                            "env": {"type": "string"},
                            "header": {"type": "string"},
                        },
                    },
                    "poll": {"type": "string"},
                    "licence": {"type": "string"},
                    "region": {"enum": ["AU", "global"]},
                    "tlp": {"enum": ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]},
                    "health": {
                        "type": "object",
                        "properties": {
                            "probe": {"type": "string"},
                            "expect_status": {"type": "integer"},
                            "max_age": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
}

_RESERVED_PROFILE_NAMES = {"hermes", "test", "tmp", "root", "sudo"}
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SKILL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_HOST_NAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_URL_HOST = re.compile(r"https://([A-Za-z0-9.-]+)")
_EGRESS_LINE = re.compile(r"^[-*]\s+Egress hosts:\s*(.+?)\s*$", re.MULTILINE)
_DURATION = re.compile(
    r"^P(?=\d|T)(?:\d+Y)?(?:\d+M)?(?:\d+W)?(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?$"
)
_FEED_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_ALLOWLIST_WITHOUT_PACKAGE = {"stub"}
_SKILL_LIST_FIELDS = (
    "tags",
    "related_skills",
    "requires_toolsets",
    "requires_tools",
    "fallback_for_toolsets",
    "fallback_for_tools",
)
_SKILL_REQUIRED = ("name", "description", "version", "author", "license", "platforms")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the hermes-cyber-au repository.")
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    findings = validate(args.root.resolve())
    for finding in findings:
        print(finding)
    return 1 if findings else 0


def validate(root: Path) -> list[str]:
    """Return human-readable findings. An empty list means the tree passes."""
    findings: list[str] = []
    findings.extend(check_distribution(root))
    findings.extend(check_skills(root))
    findings.extend(check_catalogue(root))
    findings.extend(check_allowlist(root))
    return findings


def check_distribution(root: Path) -> list[str]:
    path = root / "distribution.yaml"
    rel = _rel(root, path)
    data, error = _load_yaml(path)
    if error:
        return [f"{rel}: {error}"]
    if not isinstance(data, dict):
        return [f"{rel}: distribution manifest must be a mapping"]

    findings: list[str] = []
    name = data.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", name):
        findings.append(f"{rel}: name must be a lowercase token")
    elif name in _RESERVED_PROFILE_NAMES:
        findings.append(f"{rel}: name {name} is reserved by Hermes")

    for key in ("version", "description", "hermes_requires", "author", "license"):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            findings.append(f"{rel}: {key} must be a non-empty string")

    owned = data.get("distribution_owned")
    if not isinstance(owned, list) or not owned:
        findings.append(f"{rel}: distribution_owned must be a non-empty list")
    else:
        for item in owned:
            if not isinstance(item, str) or not item or item.startswith("/"):
                findings.append(f"{rel}: owned path {item!r} must be a relative path")
                continue
            if ".." in Path(item).parts:
                findings.append(f"{rel}: owned path {item} escapes the repository")
                continue
            candidate = (root / item).resolve()
            if not candidate.is_relative_to(root.resolve()) or not candidate.exists():
                findings.append(f"{rel}: owned path {item} does not exist")
            if Path(item).name in {".env", "auth.json", "credentials.json"}:
                findings.append(f"{rel}: owned path {item} looks like a credential file")

    env_requires = data.get("env_requires", [])
    if not isinstance(env_requires, list):
        findings.append(f"{rel}: env_requires must be a list")
        return findings

    seen: set[str] = set()
    allowed_item_keys = {"name", "description", "required", "default"}
    for index, item in enumerate(env_requires):
        label = f"{rel}: env_requires[{index}]"
        if not isinstance(item, dict):
            findings.append(f"{label} must be a mapping")
            continue
        extra = sorted(set(item) - allowed_item_keys)
        if extra:
            findings.append(f"{label} has unexpected keys: {', '.join(extra)}")
        env_name = item.get("name")
        if not isinstance(env_name, str) or not _ENV_NAME.fullmatch(env_name):
            findings.append(f"{label} name must be an uppercase environment variable")
        elif env_name in seen:
            findings.append(f"{label} duplicates {env_name}")
        else:
            seen.add(env_name)
        description = item.get("description")
        if not isinstance(description, str) or not description.strip():
            findings.append(f"{label} description must be a non-empty string")
        if not isinstance(item.get("required"), bool):
            findings.append(f"{label} required must be a boolean")
        if "default" in item and not isinstance(item.get("default"), str):
            findings.append(f"{label} default must be a string placeholder")
    return findings


def check_skills(root: Path) -> list[str]:
    skills = root / "skills"
    if not skills.is_dir():
        return ["skills: directory is missing"]
    findings: list[str] = []
    for path in sorted(skills.rglob("SKILL.md")):
        findings.extend(_check_skill(root, path))
    return findings


def check_catalogue(root: Path) -> list[str]:
    catalogue_path = root / "feeds" / "catalogue.yaml"
    schema_path = root / "feeds" / "catalogue.schema.json"
    findings: list[str] = []
    schema = CATALOGUE_SCHEMA
    if schema_path.is_file():
        loaded, error = _load_json(schema_path)
        rel = _rel(root, schema_path)
        if error:
            return [f"{rel}: {error}"]
        if not isinstance(loaded, dict):
            return [f"{rel}: catalogue schema must be a JSON object"]
        try:
            Draft202012Validator.check_schema(loaded)
        except SchemaError as exc:
            return [f"{rel}: invalid JSON schema: {exc.message}"]
        schema = loaded
    if not catalogue_path.is_file():
        return findings

    rel = _rel(root, catalogue_path)
    data, error = _load_yaml(catalogue_path)
    if error:
        return [f"{rel}: {error}"]
    if not isinstance(data, dict):
        return [f"{rel}: catalogue must be a mapping"]

    validator = Draft202012Validator(schema)
    for problem in sorted(validator.iter_errors(data), key=_schema_sort_key):
        location = "/".join(str(part) for part in problem.path) or "<root>"
        findings.append(f"{rel}: {location}: {problem.message}")

    feeds = data.get("feeds")
    if not isinstance(feeds, list):
        return findings

    known = _known_connectors(root)
    seen_ids: set[str] = set()
    for index, feed in enumerate(feeds):
        if not isinstance(feed, dict):
            continue
        label = f"{rel}: feeds[{index}]"
        feed_id = feed.get("id")
        if isinstance(feed_id, str):
            if not _FEED_ID.fullmatch(feed_id):
                findings.append(f"{label} id must be a lowercase token")
            elif feed_id in seen_ids:
                findings.append(f"{label} duplicates id {feed_id}")
            else:
                seen_ids.add(feed_id)
        connector = feed.get("connector")
        if isinstance(connector, str) and connector not in known:
            findings.append(f"{label} connector {connector} does not exist")
        url = feed.get("url")
        if isinstance(url, str) and not url.startswith("https://"):
            findings.append(f"{label} url must use https")
        poll = feed.get("poll")
        if isinstance(poll, str) and not _DURATION.fullmatch(poll):
            findings.append(f"{label} poll must be an ISO 8601 duration")
        findings.extend(_check_feed_auth(label, feed.get("auth")))
    return findings


def check_allowlist(root: Path) -> list[str]:
    path = root / "mcp" / "egress-allowlist.yaml"
    rel = _rel(root, path)
    data, error = _load_yaml(path)
    if error:
        return [f"{rel}: {error}"]
    if not isinstance(data, dict):
        return [f"{rel}: egress allowlist must be a mapping"]

    findings: list[str] = []
    unexpected = sorted(set(data) - {"connectors", "version"})
    if unexpected:
        findings.append(f"{rel}: unexpected keys: {', '.join(unexpected)}")
    if "version" in data and not isinstance(data.get("version"), int):
        findings.append(f"{rel}: version must be an integer")

    connectors = data.get("connectors")
    if not isinstance(connectors, dict) or not connectors:
        return findings + [f"{rel}: connectors must be a non-empty mapping"]

    listed: dict[str, set[str]] = {}
    for key, spec in connectors.items():
        label = f"{rel}: {key}"
        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", key):
            findings.append(f"{label}: connector key must be a lowercase token")
            continue
        if not isinstance(spec, dict):
            findings.append(f"{label}: connector entry must be a mapping")
            continue
        extra = sorted(set(spec) - {"hosts", "allow_ip_literals", "allow_http_loopback"})
        if extra:
            findings.append(f"{label}: unexpected keys: {', '.join(extra)}")
        hosts = spec.get("hosts")
        if not isinstance(hosts, list) or not hosts:
            findings.append(f"{label}: hosts must be a non-empty list")
            continue
        normalised: set[str] = set()
        for host in hosts:
            if not isinstance(host, str):
                findings.append(f"{label}: host {host!r} must be a string")
                continue
            cleaned = host.strip().rstrip(".").lower()
            if cleaned in normalised:
                findings.append(f"{label}: duplicate host {cleaned}")
            if not _HOST_NAME.fullmatch(cleaned):
                findings.append(f"{label}: host {cleaned!r} is not a DNS name")
            normalised.add(cleaned)
        for flag in ("allow_ip_literals", "allow_http_loopback"):
            if flag in spec and not isinstance(spec.get(flag), bool):
                findings.append(f"{label}: {flag} must be a boolean")
        listed[key] = normalised

    mcp = root / "mcp"
    packages = []
    if mcp.is_dir():
        packages = sorted(
            child for child in mcp.iterdir() if child.is_dir() and (child / "SOURCE.md").is_file()
        )
    package_names = {child.name for child in packages}
    for key in sorted(set(listed) - package_names - _ALLOWLIST_WITHOUT_PACKAGE):
        findings.append(f"{rel}: {key} is allowlisted but has no mcp/{key}/SOURCE.md")

    for package in packages:
        key = package.name
        source_rel = _rel(root, package / "SOURCE.md")
        declared, declare_error = _egress_hosts(package / "SOURCE.md")
        if declare_error:
            findings.append(f"{source_rel}: {declare_error}")
        if key not in listed:
            findings.append(f"{source_rel}: connector {key} is missing from the egress allowlist")
            continue
        if declared != listed[key]:
            findings.append(
                f"{source_rel}: egress hosts differ from the allowlist "
                f"(SOURCE.md: {_format_hosts(declared)}; allowlist: {_format_hosts(listed[key])})"
            )
        src = package / "src"
        if not src.is_dir():
            continue
        for source_file in sorted(src.rglob("*.py")):
            used = _https_hosts(source_file.read_text(encoding="utf-8"))
            missing = used - listed[key]
            if missing:
                findings.append(
                    f"{_rel(root, source_file)}: hosts not allowlisted for {key}: "
                    f"{_format_hosts(missing)}"
                )

    findings.extend(_check_servers(root, set(listed)))
    return findings


def _check_skill(root: Path, path: Path) -> list[str]:
    rel = _rel(root, path)
    text = path.read_text(encoding="utf-8")
    front, error = _frontmatter(text)
    if error:
        return [f"{rel}: {error}"]
    assert front is not None
    data, yaml_error = _parse_yaml_text(front)
    if yaml_error:
        return [f"{rel}: frontmatter {yaml_error}"]
    if not isinstance(data, dict):
        return [f"{rel}: frontmatter must be a mapping"]

    findings: list[str] = []
    for key in _SKILL_REQUIRED:
        if key not in data:
            findings.append(f"{rel}: frontmatter is missing {key}")

    directory_name = path.parent.name
    name = data.get("name")
    if isinstance(name, str):
        if not _SKILL_NAME.fullmatch(name):
            findings.append(f"{rel}: name must be a lowercase hyphenated token")
        elif name != directory_name:
            findings.append(f"{rel}: name {name} does not match directory {directory_name}")
    elif "name" in data:
        findings.append(f"{rel}: name must be a string")

    description = data.get("description")
    if isinstance(description, str) and (not description.strip() or len(description) > 1024):
        findings.append(f"{rel}: description must be 1 to 1024 characters")
    elif "description" in data and not isinstance(description, str):
        findings.append(f"{rel}: description must be a string")

    for key in ("version", "author", "license"):
        value = data.get(key)
        if key in data and (not isinstance(value, str) or not value.strip()):
            findings.append(f"{rel}: {key} must be a non-empty string")

    platforms = data.get("platforms")
    if "platforms" in data and (
        not isinstance(platforms, list)
        or not platforms
        or not all(isinstance(item, str) and item.strip() for item in platforms)
    ):
        findings.append(f"{rel}: platforms must be a non-empty list of strings")

    metadata = data.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        findings.append(f"{rel}: metadata must be a mapping")
    elif isinstance(metadata, dict) and "hermes" in metadata:
        hermes = metadata.get("hermes")
        if not isinstance(hermes, dict):
            findings.append(f"{rel}: metadata.hermes must be a mapping")
        else:
            findings.extend(_check_hermes_metadata(rel, hermes))

    variables = data.get("required_environment_variables")
    if variables is not None:
        findings.extend(_check_required_env(rel, variables))
    return findings


def _check_hermes_metadata(rel: str, hermes: dict) -> list[str]:
    findings: list[str] = []
    for key in _SKILL_LIST_FIELDS:
        if key in hermes and not _is_str_list(hermes.get(key)):
            findings.append(f"{rel}: metadata.hermes.{key} must be a list of strings")
    blueprint = hermes.get("blueprint")
    if blueprint is not None and not isinstance(blueprint, dict):
        findings.append(f"{rel}: metadata.hermes.blueprint must be a mapping")
    return findings


def _check_required_env(rel: str, variables: object) -> list[str]:
    if not isinstance(variables, list):
        return [f"{rel}: required_environment_variables must be a list"]
    findings: list[str] = []
    for index, item in enumerate(variables):
        label = f"{rel}: required_environment_variables[{index}]"
        if not isinstance(item, dict):
            findings.append(f"{label} must be a mapping")
            continue
        for key in ("name", "prompt", "help"):
            value = item.get(key)
            if not isinstance(value, str) or not value.strip():
                findings.append(f"{label} {key} must be a non-empty string")
        env_name = item.get("name")
        if isinstance(env_name, str) and not _ENV_NAME.fullmatch(env_name):
            findings.append(f"{label} name must be an uppercase environment variable")
        required_for = item.get("required_for")
        if required_for is not None and not (
            isinstance(required_for, str) or _is_str_list(required_for)
        ):
            findings.append(f"{label} required_for must be a string or a list of strings")
    return findings


def _check_feed_auth(label: str, auth: object) -> list[str]:
    if not isinstance(auth, dict):
        return []
    findings: list[str] = []
    auth_type = auth.get("type")
    if auth_type not in {"none", "header", "bearer"}:
        findings.append(f"{label} auth.type must be none, header or bearer")
        return findings
    env_name = auth.get("env")
    if auth_type == "none":
        if env_name not in (None, ""):
            findings.append(f"{label} auth.env must be empty when auth.type is none")
        return findings
    if not isinstance(env_name, str) or not _ENV_NAME.fullmatch(env_name):
        findings.append(f"{label} auth.env must name an uppercase environment variable")
    return findings


def _check_servers(root: Path, allowlisted: set[str]) -> list[str]:
    path = root / "mcp" / "servers.yaml"
    if not path.is_file():
        return []
    rel = _rel(root, path)
    data, error = _load_yaml(path)
    if error:
        return [f"{rel}: {error}"]
    if not isinstance(data, dict):
        return [f"{rel}: servers file must be a mapping"]
    servers = data.get("servers")
    if not isinstance(servers, dict):
        return [f"{rel}: servers must be a mapping"]
    findings: list[str] = []
    for server_name, spec in servers.items():
        if not isinstance(spec, dict):
            findings.append(f"{rel}: {server_name} must be a mapping")
            continue
        connector = spec.get("connector")
        if not isinstance(connector, str) or connector not in allowlisted:
            findings.append(
                f"{rel}: {server_name} connector {connector!r} is not in the egress allowlist"
            )
    return findings


def _known_connectors(root: Path) -> set[str]:
    found: set[str] = set()
    mcp = root / "mcp"
    if not mcp.is_dir():
        return found
    for child in mcp.iterdir():
        if child.is_dir() and (child / "pyproject.toml").is_file():
            found.add(child.name)
    servers = mcp / "servers.yaml"
    if not servers.is_file():
        return found
    data, error = _load_yaml(servers)
    if error or not isinstance(data, dict):
        return found
    for spec in (data.get("servers") or {}).values():
        if isinstance(spec, dict) and isinstance(spec.get("connector"), str):
            found.add(spec["connector"])
    return found


def _egress_hosts(path: Path) -> tuple[set[str], str | None]:
    text = path.read_text(encoding="utf-8")
    matches = _EGRESS_LINE.findall(text)
    if not matches:
        return set(), "Egress hosts line is missing"
    if len(matches) > 1:
        return set(), "Egress hosts is listed more than once"
    hosts = set()
    for part in matches[0].split(","):
        cleaned = part.strip().rstrip(".").lower()
        if cleaned:
            hosts.add(cleaned)
    if not hosts:
        return set(), "Egress hosts line is empty"
    return hosts, None


def _https_hosts(text: str) -> set[str]:
    hosts: set[str] = set()
    for host in _URL_HOST.findall(text):
        cleaned = host.strip().rstrip(".").lower()
        if "." in cleaned:
            hosts.add(cleaned)
    return hosts


def _frontmatter(text: str) -> tuple[str | None, str | None]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, "SKILL.md must start with YAML frontmatter"
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            return "\n".join(lines[1:index]), None
    return None, "SKILL.md frontmatter is missing its closing marker"


def _load_yaml(path: Path) -> tuple[object, str | None]:
    if not path.is_file():
        return None, "file is missing"
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")), None
    except yaml.YAMLError as exc:
        return None, f"invalid YAML: {exc}"


def _parse_yaml_text(text: str) -> tuple[object, str | None]:
    try:
        return yaml.safe_load(text) if text.strip() else {}, None
    except yaml.YAMLError as exc:
        return None, f"invalid YAML: {exc}"


def _load_json(path: Path) -> tuple[object, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc.msg}"


def _is_str_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _format_hosts(hosts: set[str]) -> str:
    return ", ".join(sorted(hosts)) if hosts else "(none)"


def _schema_sort_key(error: object) -> list[str]:
    path = getattr(error, "path", ())
    return [str(part) for part in path]


def _rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


if __name__ == "__main__":
    sys.exit(main())
